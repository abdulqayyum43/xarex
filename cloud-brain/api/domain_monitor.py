"""Domain Guardian API — SSL, DNS, WHOIS, and lookalike monitoring."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import get_org
from models.database import AsyncSessionLocal, get_db
from models.tables import DomainMonitor, Org

router = APIRouter(prefix="/domain-guardian", tags=["domain-guardian"])


class AddDomainReq(BaseModel):
    domain: str
    label: str = ""


def _status_from_score(score: int) -> str:
    if score >= 80: return "ok"
    if score >= 60: return "warning"
    if score >= 40: return "warning"
    return "critical"


def _domain_summary(d: DomainMonitor) -> dict:
    return {
        "id":                  d.id,
        "domain":              d.domain,
        "label":               d.label,
        "status":              d.status,
        "health_score":        d.health_score,
        "ssl_valid":           d.ssl_valid,
        "ssl_days_remaining":  d.ssl_days_remaining,
        "ssl_expires_at":      d.ssl_expires_at.isoformat() if d.ssl_expires_at else None,
        "ssl_issuer":          d.ssl_issuer,
        "spf_valid":           d.spf_valid,
        "dmarc_valid":         d.dmarc_valid,
        "dkim_valid":          d.dkim_valid,
        "dmarc_policy":        d.dmarc_policy,
        "mx_records":          d.mx_records,
        "whois_expires_at":    d.whois_expires_at.isoformat() if d.whois_expires_at else None,
        "whois_days_remaining":d.whois_days_remaining,
        "registrar":           d.registrar,
        "lookalike_count":     d.lookalike_count,
        "lookalikes":          d.lookalikes,
        "issues":              d.issues,
        "last_checked":        d.last_checked.isoformat() if d.last_checked else None,
        "created_at":          d.created_at.isoformat(),
    }


@router.get("")
async def list_domains(
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
):
    res = await db.execute(
        select(DomainMonitor)
        .where(DomainMonitor.org_id == str(org.id))
        .order_by(DomainMonitor.created_at.desc())
    )
    return [_domain_summary(d) for d in res.scalars().all()]


@router.post("", status_code=202)
async def add_domain(
    body: AddDomainReq,
    background_tasks: BackgroundTasks,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
):
    domain = body.domain.lower().strip().removeprefix("https://").removeprefix("http://").split("/")[0]
    if not domain or "." not in domain:
        raise HTTPException(status_code=422, detail="Invalid domain name")

    # Prevent duplicates per org
    existing = await db.execute(
        select(DomainMonitor).where(
            DomainMonitor.org_id == str(org.id),
            DomainMonitor.domain == domain,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Domain already monitored")

    record = DomainMonitor(
        org_id=str(org.id),
        domain=domain,
        label=body.label.strip(),
        status="pending",
    )
    db.add(record)
    await db.flush()
    record_id = record.id
    await db.commit()

    background_tasks.add_task(_run_check_bg, record_id)
    return {"id": record_id, "domain": domain, "status": "pending",
            "message": "Domain added — checking now, results in ~30s"}


@router.delete("/{domain_id}", status_code=204)
async def remove_domain(
    domain_id: str,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
):
    res = await db.execute(
        select(DomainMonitor).where(
            DomainMonitor.id == domain_id,
            DomainMonitor.org_id == str(org.id),
        )
    )
    record = res.scalar_one_or_none()
    if not record:
        raise HTTPException(status_code=404, detail="Domain not found")
    await db.delete(record)
    await db.commit()


@router.post("/{domain_id}/refresh", status_code=202)
async def refresh_domain(
    domain_id: str,
    background_tasks: BackgroundTasks,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
):
    res = await db.execute(
        select(DomainMonitor).where(
            DomainMonitor.id == domain_id,
            DomainMonitor.org_id == str(org.id),
        )
    )
    record = res.scalar_one_or_none()
    if not record:
        raise HTTPException(status_code=404, detail="Domain not found")
    background_tasks.add_task(_run_check_bg, domain_id)
    return {"message": "Re-checking domain…"}


@router.get("/{domain_id}")
async def get_domain(
    domain_id: str,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
):
    res = await db.execute(
        select(DomainMonitor).where(
            DomainMonitor.id == domain_id,
            DomainMonitor.org_id == str(org.id),
        )
    )
    record = res.scalar_one_or_none()
    if not record:
        raise HTTPException(status_code=404, detail="Domain not found")
    return _domain_summary(record)


# ── Background check worker ───────────────────────────────────────────────────

async def _run_check_bg(record_id: str) -> None:
    from services.domain_monitor import run_domain_check

    async with AsyncSessionLocal() as db:
        res = await db.execute(select(DomainMonitor).where(DomainMonitor.id == record_id))
        record = res.scalar_one_or_none()
        if not record:
            return
        try:
            result = await run_domain_check(record.domain)

            # SSL
            ssl = result.get("ssl", {})
            record.ssl_valid           = ssl.get("valid", False)
            record.ssl_issuer          = ssl.get("issuer")
            if ssl.get("expires_at"):
                record.ssl_expires_at  = datetime.fromisoformat(ssl["expires_at"])
            record.ssl_days_remaining  = ssl.get("days_remaining")

            # DNS
            dns = result.get("dns", {})
            record.spf_valid    = dns.get("spf_valid", False)
            record.dmarc_valid  = dns.get("dmarc_valid", False)
            record.dkim_valid   = dns.get("dkim_valid", False)
            record.dmarc_policy = dns.get("dmarc_policy")
            record.mx_records   = dns.get("mx_records", [])
            record.ns_records   = dns.get("ns_records", [])

            # WHOIS
            whois = result.get("whois", {})
            record.registrar              = whois.get("registrar")
            record.whois_days_remaining   = whois.get("days_remaining")
            if whois.get("expires_at"):
                record.whois_expires_at   = datetime.fromisoformat(whois["expires_at"])

            # Lookalikes
            record.lookalikes      = result.get("lookalikes", [])
            record.lookalike_count = result.get("lookalike_count", 0)

            # Issues + score
            record.issues       = result.get("issues", [])
            record.health_score = result.get("health_score", 100)
            record.status       = _status_from_score(record.health_score)
            record.last_result  = result
            record.last_checked = datetime.now(timezone.utc)

        except Exception as exc:
            record.status = "failed"
            record.issues = [{"severity": "critical", "title": "Check failed", "desc": str(exc)}]

        await db.commit()
