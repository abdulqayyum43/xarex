"""Notification service — create, list, and manage in-app security notifications."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import structlog
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from models.database import AsyncSessionLocal
from models.tables import Notification

logger = structlog.get_logger(__name__)

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


async def create_notification(
    org_id: str,
    kind: str,
    severity: str,
    title: str,
    body: str = "",
    action_url: str | None = None,
    action_label: str | None = None,
    meta: dict | None = None,
    db: AsyncSession | None = None,
) -> Notification:
    """Persist a new notification.  Accepts an optional existing session or opens its own."""
    record = Notification(
        org_id       = org_id,
        kind         = kind,
        severity     = severity,
        title        = title,
        body         = body,
        action_url   = action_url,
        action_label = action_label,
        metadata_    = meta or {},
    )

    if db:
        db.add(record)
        await db.flush()
    else:
        async with AsyncSessionLocal() as _db:
            _db.add(record)
            await _db.commit()

    logger.info("Notification created", kind=kind, severity=severity, title=title[:60])
    return record


async def get_notifications(
    org_id: str,
    db: AsyncSession,
    unread_only: bool = False,
    limit: int = 50,
) -> list[Notification]:
    q = select(Notification).where(Notification.org_id == org_id)
    if unread_only:
        q = q.where(Notification.read == False)  # noqa: E712
    q = q.order_by(Notification.created_at.desc()).limit(limit)
    result = await db.execute(q)
    return result.scalars().all()


async def unread_count(org_id: str, db: AsyncSession) -> int:
    from sqlalchemy import func as sqlfunc
    result = await db.execute(
        select(sqlfunc.count()).select_from(Notification).where(
            Notification.org_id == org_id,
            Notification.read == False,  # noqa: E712
        )
    )
    return result.scalar_one() or 0


async def mark_read(org_id: str, notification_id: str, db: AsyncSession) -> None:
    await db.execute(
        update(Notification)
        .where(Notification.id == notification_id, Notification.org_id == org_id)
        .values(read=True)
    )


async def mark_all_read(org_id: str, db: AsyncSession) -> None:
    await db.execute(
        update(Notification)
        .where(Notification.org_id == org_id, Notification.read == False)  # noqa: E712
        .values(read=True)
    )


# ── Scheduled check workers ───────────────────────────────────────────────────

async def run_domain_checks_for_org(org_id: str) -> int:
    """Re-check all monitored domains for an org. Returns number of alerts fired."""
    from services.domain_monitor import run_domain_check
    from models.tables import DomainMonitor

    alerts = 0
    async with AsyncSessionLocal() as db:
        res = await db.execute(
            select(DomainMonitor).where(DomainMonitor.org_id == org_id)
        )
        domains = res.scalars().all()

        for d in domains:
            try:
                result = await run_domain_check(d.domain)
                prev_score = d.health_score
                new_score  = result.get("health_score", 100)

                # Update domain record
                d.health_score       = new_score
                d.ssl_valid          = result["ssl"].get("valid", False)
                d.ssl_days_remaining = result["ssl"].get("days_remaining")
                d.ssl_issuer         = result["ssl"].get("issuer")
                if result["ssl"].get("expires_at"):
                    d.ssl_expires_at = datetime.fromisoformat(result["ssl"]["expires_at"])
                d.spf_valid          = result["dns"].get("spf_valid", False)
                d.dmarc_valid        = result["dns"].get("dmarc_valid", False)
                d.dkim_valid         = result["dns"].get("dkim_valid", False)
                d.dmarc_policy       = result["dns"].get("dmarc_policy")
                d.lookalike_count    = result.get("lookalike_count", 0)
                d.lookalikes         = result.get("lookalikes", [])
                d.issues             = result.get("issues", [])
                d.last_checked       = datetime.now(timezone.utc)
                d.status             = "ok" if new_score >= 80 else "warning" if new_score >= 50 else "critical"

                # Fire notifications for critical issues
                ssl_days = result["ssl"].get("days_remaining")
                if ssl_days is not None and ssl_days <= 14:
                    sev = "critical" if ssl_days <= 0 else "high"
                    await create_notification(
                        org_id=org_id, kind="domain_ssl", severity=sev,
                        title=f"SSL certificate {'expired' if ssl_days<=0 else f'expiring in {ssl_days}d'}: {d.domain}",
                        body=f"The SSL certificate for {d.domain} {'has expired' if ssl_days<=0 else f'expires in {ssl_days} days'}. Renew immediately to prevent browser warnings.",
                        action_url="domain-guardian", action_label="View domain",
                        meta={"domain_id": d.id, "domain": d.domain, "days": ssl_days},
                        db=db,
                    )
                    alerts += 1

                whois_days = result.get("whois", {}).get("days_remaining")
                if whois_days is not None and whois_days <= 30:
                    sev = "critical" if whois_days <= 7 else "high"
                    await create_notification(
                        org_id=org_id, kind="domain_whois", severity=sev,
                        title=f"Domain registration expiring in {whois_days}d: {d.domain}",
                        body=f"{d.domain} registration expires in {whois_days} days. Renew to prevent losing your domain.",
                        action_url="domain-guardian", action_label="View domain",
                        meta={"domain_id": d.id, "domain": d.domain, "days": whois_days},
                        db=db,
                    )
                    alerts += 1

                new_lookalikes = result.get("lookalike_count", 0)
                old_lookalikes = len(d.lookalikes) if d.lookalikes else 0
                if new_lookalikes > old_lookalikes:
                    added = new_lookalikes - old_lookalikes
                    await create_notification(
                        org_id=org_id, kind="domain_lookalike", severity="medium",
                        title=f"{added} new lookalike domain{'s' if added>1 else ''} registered for {d.domain}",
                        body=f"New typosquatting domains targeting {d.domain} have been registered. These could be used for phishing.",
                        action_url="domain-guardian", action_label="View lookalikes",
                        meta={"domain_id": d.id, "domain": d.domain, "count": new_lookalikes},
                        db=db,
                    )
                    alerts += 1

            except Exception as exc:
                logger.warning("Domain re-check failed", domain=d.domain, error=str(exc))

        await db.commit()

    return alerts


async def run_breach_checks_for_org(org_id: str) -> int:
    """Re-check all monitored emails for new breaches. Returns number of new breach notifications."""
    from services.breach_checker import check_email_breaches
    from models.tables import BreachMonitor, BreachHit

    alerts = 0
    async with AsyncSessionLocal() as db:
        res = await db.execute(
            select(BreachMonitor).where(
                BreachMonitor.org_id == org_id,
                BreachMonitor.active == True,  # noqa: E712
            )
        )
        monitors = res.scalars().all()

        for monitor in monitors:
            try:
                breaches = await check_email_breaches(monitor.email)
                if breaches is None:
                    continue

                # Find which breach names are new
                existing = await db.execute(
                    select(BreachHit.breach_name).where(BreachHit.monitor_id == monitor.id)
                )
                existing_names = {r[0] for r in existing.all()}
                new_breaches   = [b for b in breaches if b.get("Name") not in existing_names]

                if new_breaches:
                    # Upsert new breach hits
                    for b in new_breaches:
                        hit = BreachHit(
                            monitor_id   = monitor.id,
                            breach_name  = b.get("Name", "Unknown"),
                            breach_domain= b.get("Domain", ""),
                            breach_date  = b.get("BreachDate"),
                            pwn_count    = b.get("PwnCount", 0),
                            data_classes = b.get("DataClasses", []),
                            is_verified  = b.get("IsVerified", False),
                            is_sensitive = b.get("IsSensitive", False),
                            description  = b.get("Description", ""),
                        )
                        db.add(hit)

                    monitor.breach_count += len(new_breaches)
                    monitor.last_checked  = datetime.now(timezone.utc)

                    names_str = ", ".join(b.get("Name","?") for b in new_breaches[:3])
                    if len(new_breaches) > 3:
                        names_str += f" +{len(new_breaches)-3} more"

                    await create_notification(
                        org_id=org_id, kind="breach_new", severity="high",
                        title=f"New breach found for {monitor.email}",
                        body=f"{monitor.email} appeared in {len(new_breaches)} new data breach{'es' if len(new_breaches)>1 else ''}: {names_str}. Change your password immediately.",
                        action_url="breach-monitor", action_label="View breaches",
                        meta={"monitor_id": monitor.id, "email": monitor.email, "count": len(new_breaches)},
                        db=db,
                    )
                    alerts += 1
                else:
                    monitor.last_checked = datetime.now(timezone.utc)

            except Exception as exc:
                logger.warning("Breach re-check failed", email=monitor.email, error=str(exc))

        await db.commit()

    return alerts


async def run_all_guardian_checks() -> None:
    """Top-level job: run domain + breach checks for every org that has monitors."""
    from models.tables import DomainMonitor, BreachMonitor, Org
    from sqlalchemy import distinct

    logger.info("Guardian scheduled check starting")

    async with AsyncSessionLocal() as db:
        # Orgs with domain monitors
        dm_orgs = (await db.execute(select(distinct(DomainMonitor.org_id)))).scalars().all()
        # Orgs with breach monitors
        bm_orgs = (await db.execute(select(distinct(BreachMonitor.org_id)))).scalars().all()

    all_orgs = set(dm_orgs) | set(bm_orgs)
    total_alerts = 0

    for org_id in all_orgs:
        if org_id in dm_orgs:
            n = await run_domain_checks_for_org(org_id)
            total_alerts += n
        if org_id in bm_orgs:
            n = await run_breach_checks_for_org(org_id)
            total_alerts += n

    logger.info("Guardian scheduled check complete", orgs=len(all_orgs), alerts=total_alerts)
