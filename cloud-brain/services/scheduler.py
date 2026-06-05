"""Scheduler — recurring autonomous scan engine.

Uses APScheduler AsyncIOScheduler to persist and execute scheduled scans.
Schedules are stored in the `scheduled_scans` table and re-loaded on startup.

Usage:
    from services.scheduler import start_scheduler, stop_scheduler
    # In lifespan: await start_scheduler()
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from croniter import croniter

from models.database import AsyncSessionLocal

logger = structlog.get_logger(__name__)

_scheduler: AsyncIOScheduler | None = None


# ──────────────────────────────────────────────
#  Lifecycle
# ──────────────────────────────────────────────

async def start_scheduler() -> None:
    global _scheduler
    _scheduler = AsyncIOScheduler(timezone="UTC")
    _scheduler.start()

    # Load all enabled schedules from DB
    await _reload_all_schedules()

    # Guardian scheduled checks — every 12 hours
    _scheduler.add_job(
        _run_guardian_checks,
        trigger=CronTrigger(hour="*/12", minute=15, timezone="UTC"),
        id="guardian:daily_checks",
        replace_existing=True,
        misfire_grace_time=600,
    )
    logger.info("Guardian check job scheduled (every 12h)")

    # Lead-table retention — nightly. Scrubs IP/UA past LEAD_PII_RETENTION_DAYS
    # and hard-deletes rows past LEAD_RETENTION_DAYS. See services/retention.py.
    # Idempotent; safe to misfire.
    from services.retention import run_retention_pass
    _scheduler.add_job(
        run_retention_pass,
        trigger=CronTrigger(hour=3, minute=30, timezone="UTC"),
        id="leads:retention_pass",
        replace_existing=True,
        misfire_grace_time=3600,
    )
    logger.info("Lead retention job scheduled (daily 03:30 UTC)")

    logger.info("Scheduler started")


async def stop_scheduler() -> None:
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
    logger.info("Scheduler stopped")


# ──────────────────────────────────────────────
#  Schedule management
# ──────────────────────────────────────────────

async def add_schedule(schedule_id: str, org_id: str, cron_expr: str, scan_config: dict[str, Any]) -> None:
    """Register a new cron-based scan schedule with the APScheduler."""
    if _scheduler is None:
        logger.warning("Scheduler not started — schedule will activate on next restart", schedule_id=schedule_id)
        return

    job_id = f"schedule:{schedule_id}"

    # Remove existing job if any
    if _scheduler.get_job(job_id):
        _scheduler.remove_job(job_id)

    _scheduler.add_job(
        _run_scheduled_scan,
        trigger=CronTrigger.from_crontab(cron_expr, timezone="UTC"),
        id=job_id,
        kwargs={"schedule_id": schedule_id, "org_id": org_id, "scan_config": scan_config},
        replace_existing=True,
        misfire_grace_time=300,
    )

    logger.info("Scheduled scan registered", schedule_id=schedule_id, cron=cron_expr)


async def remove_schedule(schedule_id: str) -> None:
    """Remove a schedule from the APScheduler."""
    if _scheduler is None:
        return
    job_id = f"schedule:{schedule_id}"
    if _scheduler.get_job(job_id):
        _scheduler.remove_job(job_id)
    logger.info("Schedule removed", schedule_id=schedule_id)


async def _reload_all_schedules() -> None:
    """Load all enabled schedules from DB and register them."""
    from sqlalchemy import select
    from models.tables import ScheduledScan

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(ScheduledScan).where(ScheduledScan.enabled == True)  # noqa: E712
        )
        schedules = result.scalars().all()

    for s in schedules:
        try:
            await add_schedule(s.id, s.org_id, s.cron_expression, s.config)
        except Exception as exc:
            logger.warning("Failed to load schedule", schedule_id=s.id, error=str(exc))

    logger.info("Schedules loaded from DB", count=len(schedules))


# ──────────────────────────────────────────────
#  Job execution
# ──────────────────────────────────────────────

async def _run_scheduled_scan(
    schedule_id: str,
    org_id: str,
    scan_config: dict[str, Any],
) -> None:
    """Execute a scheduled scan — creates a new Scan record and seeds tasks."""
    from sqlalchemy import select, update
    from models.tables import Org, Probe, ScheduledScan
    from orchestrator.task_manager import TaskManager

    logger.info("Running scheduled scan", schedule_id=schedule_id, org_id=org_id)

    async with AsyncSessionLocal() as db:
        # Update last_run_at
        await db.execute(
            update(ScheduledScan)
            .where(ScheduledScan.id == schedule_id)
            .values(last_run_at=datetime.now(timezone.utc))
        )

        # Find an online probe for this org
        probe_result = await db.execute(
            select(Probe)
            .where(Probe.org_id == org_id, Probe.status == "online")
            .limit(1)
        )
        probe = probe_result.scalar_one_or_none()

        if probe is None:
            logger.warning("No online probe for scheduled scan", schedule_id=schedule_id, org_id=org_id)
            await db.commit()
            return

        # Create the scan
        tm = TaskManager(db)
        scan_name = scan_config.get("name", f"Scheduled Scan {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')}")
        scan = await tm.create_scan(
            org_id=org_id,
            probe_id=probe.probe_id,
            config=scan_config.get("config", {}),
            name=scan_name,
        )
        await db.commit()

        logger.info(
            "Scheduled scan created",
            schedule_id=schedule_id,
            scan_id=scan.id,
            probe=probe.probe_id,
        )


# ──────────────────────────────────────────────
#  Helpers
# ──────────────────────────────────────────────

def validate_cron(expr: str) -> bool:
    """Return True if the cron expression is valid."""
    try:
        croniter(expr)
        return True
    except (ValueError, KeyError):
        return False


def next_run_time(cron_expr: str) -> datetime | None:
    """Return the next UTC run time for a cron expression."""
    try:
        from croniter import croniter
        cron = croniter(cron_expr, datetime.now(timezone.utc))
        return cron.get_next(datetime)
    except Exception:
        return None


async def _run_guardian_checks() -> None:
    """APScheduler job: run all Guardian checks and fire notifications."""
    try:
        from services.notification_service import run_all_guardian_checks
        await run_all_guardian_checks()
    except Exception as exc:
        logger.error("Guardian check job failed", error=str(exc))
