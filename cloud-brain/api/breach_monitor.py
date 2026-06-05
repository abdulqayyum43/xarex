"""Breach Monitor API — HIBP-powered continuous email monitoring."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import get_org
from models.database import get_db
from models.tables import BreachMonitor, BreachHit, Org
from services.breach_checker import check_email_breaches, check_password_pwned

router = APIRouter(prefix="/breach-monitor", tags=["breach-monitor"])


# ── Schemas ──────────────────────────────────────────────────────────────────

class AddMonitorReq(BaseModel):
    email: str
    label: str = ""

class PasswordCheckReq(BaseModel):
    password: str


# ── Helpers ──────────────────────────────────────────────────────────────────

async def _sync_breaches(monitor: BreachMonitor, db: AsyncSession) -> int:
    """Fetch HIBP breaches for a monitor and upsert BreachHit rows. Returns new breach count."""
    result = await check_email_breaches(monitor.email)
    if not result.get("configured") or result.get("error"):
        return 0

    breaches = result.get("breaches", [])
    existing_r = await db.execute(
        select(BreachHit.breach_name).where(BreachHit.monitor_id == monitor.id)
    )
    existing_names = {row[0] for row in existing_r.fetchall()}

    new_count = 0
    for b in breaches:
        name = b.get("Name", "")
        if name and name not in existing_names:
            hit = BreachHit(
                monitor_id   = monitor.id,
                breach_name  = name,
                breach_domain= b.get("Domain", ""),
                breach_date  = b.get("BreachDate", ""),
                pwn_count    = b.get("PwnCount", 0),
                data_classes = b.get("DataClasses", []),
                is_verified  = b.get("IsVerified", False),
                is_sensitive = b.get("IsSensitive", False),
                description  = b.get("Description", "")[:500],
                logo_path    = b.get("LogoPath", ""),
            )
            db.add(hit)
            new_count += 1

    monitor.last_checked = datetime.now(timezone.utc)
    monitor.breach_count = len(breaches)
    return new_count


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("")
async def list_monitors(
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
):
    """Return all monitored emails for this org."""
    r = await db.execute(
        select(BreachMonitor)
        .where(BreachMonitor.org_id == org.id)
        .order_by(BreachMonitor.created_at.desc())
    )
    monitors = r.scalars().all()
    return [
        {
            "id":           m.id,
            "email":        m.email,
            "label":        m.label,
            "active":       m.active,
            "breach_count": m.breach_count,
            "last_checked": m.last_checked.isoformat() if m.last_checked else None,
            "created_at":   m.created_at.isoformat(),
        }
        for m in monitors
    ]


@router.post("", status_code=201)
async def add_monitor(
    body: AddMonitorReq,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
):
    """Add an email to breach monitoring and run an immediate check."""
    # Deduplicate per org
    existing = await db.execute(
        select(BreachMonitor).where(
            BreachMonitor.org_id == org.id,
            BreachMonitor.email  == body.email.lower(),
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Email already monitored")

    monitor = BreachMonitor(
        org_id = org.id,
        email  = body.email.lower(),
        label  = body.label or body.email.split("@")[0],
        active = True,
    )
    db.add(monitor)
    await db.flush()

    # Immediate breach sync
    new_hits = await _sync_breaches(monitor, db)
    await db.commit()

    return {
        "id":           monitor.id,
        "email":        monitor.email,
        "breach_count": monitor.breach_count,
        "new_hits":     new_hits,
        "message":      f"Monitoring active. Found {monitor.breach_count} breach(es).",
    }


@router.delete("/{monitor_id}", status_code=204)
async def remove_monitor(
    monitor_id: str,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
):
    """Stop monitoring an email."""
    r = await db.execute(
        select(BreachMonitor).where(
            BreachMonitor.id == monitor_id,
            BreachMonitor.org_id == org.id,
        )
    )
    monitor = r.scalar_one_or_none()
    if not monitor:
        raise HTTPException(status_code=404, detail="Monitor not found")
    await db.execute(delete(BreachMonitor).where(BreachMonitor.id == monitor_id))


@router.get("/{monitor_id}/hits")
async def get_hits(
    monitor_id: str,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
):
    """Return all breach hits for a monitored email."""
    r = await db.execute(
        select(BreachMonitor).where(
            BreachMonitor.id == monitor_id,
            BreachMonitor.org_id == org.id,
        )
    )
    monitor = r.scalar_one_or_none()
    if not monitor:
        raise HTTPException(status_code=404, detail="Monitor not found")

    hits_r = await db.execute(
        select(BreachHit)
        .where(BreachHit.monitor_id == monitor_id)
        .order_by(BreachHit.breach_date.desc())
    )
    hits = hits_r.scalars().all()
    return {
        "email":        monitor.email,
        "breach_count": monitor.breach_count,
        "hits": [
            {
                "id":           h.id,
                "breach_name":  h.breach_name,
                "breach_domain": h.breach_domain,
                "breach_date":  h.breach_date,
                "pwn_count":    h.pwn_count,
                "data_classes": h.data_classes,
                "is_verified":  h.is_verified,
                "is_sensitive": h.is_sensitive,
                "description":  h.description,
                "logo_path":    h.logo_path,
                "first_seen":   h.first_seen.isoformat(),
            }
            for h in hits
        ],
    }


@router.post("/{monitor_id}/refresh")
async def refresh_monitor(
    monitor_id: str,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
):
    """Manually trigger a fresh breach check for a monitored email."""
    r = await db.execute(
        select(BreachMonitor).where(
            BreachMonitor.id == monitor_id,
            BreachMonitor.org_id == org.id,
        )
    )
    monitor = r.scalar_one_or_none()
    if not monitor:
        raise HTTPException(status_code=404, detail="Monitor not found")

    new_hits = await _sync_breaches(monitor, db)
    return {
        "email":        monitor.email,
        "breach_count": monitor.breach_count,
        "new_hits":     new_hits,
        "checked_at":   monitor.last_checked.isoformat() if monitor.last_checked else None,
    }


@router.post("/check-password")
async def check_password(
    body: PasswordCheckReq,
    org: Org = Depends(get_org),
):
    """Check if a password has appeared in any known breach (k-anonymity — password never sent)."""
    result = await check_password_pwned(body.password)
    return {
        "pwned":   result["pwned"],
        "count":   result.get("count", 0),
        "message": (
            f"⚠️ This password was found in {result['count']:,} breach(es). Change it immediately."
            if result["pwned"] else
            "✅ This password has not been found in known breaches."
        ),
    }


@router.get("/summary")
async def breach_summary(
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
):
    """High-level breach status for dashboard widget."""
    r = await db.execute(
        select(BreachMonitor).where(BreachMonitor.org_id == org.id)
    )
    monitors = r.scalars().all()
    total_breaches = sum(m.breach_count for m in monitors)
    return {
        "emails_monitored": len(monitors),
        "total_breaches":   total_breaches,
        "status": "breached" if total_breaches > 0 else ("monitoring" if monitors else "inactive"),
    }
