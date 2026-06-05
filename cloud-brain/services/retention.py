"""Lead-table retention jobs.

Two scheduled tasks run nightly (registered in `services/scheduler.py`):

  - `scrub_lead_pii()` — nulls `ip_address` and `user_agent` on leads older
    than `LEAD_PII_RETENTION_DAYS` (default 90 days). The lead itself is
    kept for sales follow-up; only the PII is shed.
  - `purge_old_leads()` — hard-deletes leads older than
    `LEAD_RETENTION_DAYS` (default 730 days / 2 years).

Both jobs are idempotent and safe to run multiple times per day; running
under a misfire window won't cause data corruption — the worst case is
duplicate UPDATE / DELETE statements that match zero extra rows.

Returned counts are logged at INFO so retention activity is auditable.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import structlog
from sqlalchemy import update, delete

from config import settings
from models.database import AsyncSessionLocal
from models.tables import Lead

logger = structlog.get_logger(__name__)


async def scrub_lead_pii() -> int:
    """Null `ip_address` and `user_agent` on leads older than the PII window.

    Returns the number of rows updated.
    """
    days = max(1, int(settings.LEAD_PII_RETENTION_DAYS))
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    async with AsyncSessionLocal() as session:
        try:
            stmt = (
                update(Lead)
                .where(Lead.created_at < cutoff)
                # Only touch rows that still have PII — avoids generating
                # write traffic against already-scrubbed rows.
                .where((Lead.ip_address.is_not(None)) | (Lead.user_agent.is_not(None)))
                .values(ip_address=None, user_agent=None)
                .execution_options(synchronize_session=False)
            )
            result = await session.execute(stmt)
            await session.commit()
            count = result.rowcount or 0
            logger.info(
                "Lead PII scrubbed",
                rows=count,
                cutoff=cutoff.isoformat(),
                retention_days=days,
            )
            return count
        except Exception as exc:
            await session.rollback()
            logger.error("Lead PII scrub failed", error=str(exc))
            raise


async def purge_old_leads() -> int:
    """Hard-delete leads older than the retention window.

    Returns the number of rows deleted.
    """
    days = max(1, int(settings.LEAD_RETENTION_DAYS))
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    async with AsyncSessionLocal() as session:
        try:
            stmt = (
                delete(Lead)
                .where(Lead.created_at < cutoff)
                .execution_options(synchronize_session=False)
            )
            result = await session.execute(stmt)
            await session.commit()
            count = result.rowcount or 0
            logger.info(
                "Old leads purged",
                rows=count,
                cutoff=cutoff.isoformat(),
                retention_days=days,
            )
            return count
        except Exception as exc:
            await session.rollback()
            logger.error("Lead purge failed", error=str(exc))
            raise


async def run_retention_pass() -> dict[str, int]:
    """Run both retention jobs in sequence. Used by the scheduler.

    Returns a dict of `{ "scrubbed": N, "purged": M }` for observability.
    """
    # Order matters: scrub PII first so that rows about to be deleted aren't
    # touched twice (UPDATE then DELETE — wasted I/O). After the scrub, the
    # purge takes care of anything past the longer retention window.
    scrubbed = await scrub_lead_pii()
    purged = await purge_old_leads()
    return {"scrubbed": scrubbed, "purged": purged}
