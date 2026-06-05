"""Home Guardian API — consumer-friendly home network security."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import get_org
from models.database import get_db
from models.tables import Finding, Org, Probe, Scan
from services.guardian import format_guardian_scan

router = APIRouter(prefix="/guardian", tags=["guardian"])


class GuardianScanReq(BaseModel):
    target: str          # e.g. "192.168.1.0/24" or "192.168.1.1"
    name: str = "Home Network Scan"


@router.post("/scan", status_code=202)
async def start_guardian_scan(
    body: GuardianScanReq,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
):
    """Start a Home Guardian scan. Uses the standard scan pipeline, formatted for consumers."""
    # Require an online probe
    probe_res = await db.execute(
        select(Probe)
        .where(Probe.status == "online")
        .order_by(Probe.last_seen.desc())
        .limit(1)
    )
    probe = probe_res.scalar_one_or_none()
    if not probe:
        raise HTTPException(
            status_code=503,
            detail="No probe online. Install and connect a Home Guardian sensor first.",
        )

    from orchestrator.task_manager import TaskManager
    tm = TaskManager(db)
    scan = await tm.create_scan(
        org_id   = str(org.id),
        probe_id = probe.probe_id,
        name     = body.name,
        target   = body.target,
        options  = {"mode": "guardian", "target": body.target},
    )
    return {
        "scan_id": str(scan.id),
        "status":  "running",
        "message": f"Scanning {body.target} — check back in 60–90 seconds",
    }


@router.get("/scans")
async def list_guardian_scans(
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
):
    """List past Home Guardian scans (summary only)."""
    res = await db.execute(
        select(Scan)
        .where(Scan.org_id == str(org.id))
        .order_by(Scan.started_at.desc())
        .limit(20)
    )
    scans = res.scalars().all()
    return [
        {
            "scan_id":      str(s.id),
            "name":         s.name,
            "status":       s.status,
            "target":       (s.config or {}).get("target", ""),
            "finding_count": s.finding_count,
            "critical_count": s.critical_count,
            "started_at":   s.started_at.isoformat() if s.started_at else None,
        }
        for s in scans
    ]


@router.get("/scans/{scan_id}")
async def get_guardian_scan(
    scan_id: str,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
):
    """Return consumer-formatted results for a completed scan."""
    scan_res = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.org_id == str(org.id))
    )
    scan = scan_res.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings_res = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id)
    )
    findings = findings_res.scalars().all()

    return format_guardian_scan(scan, findings)


@router.get("/status")
async def guardian_status(
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
):
    """Quick status: probe online, last scan summary, device count."""
    probe_res = await db.execute(
        select(Probe)
        .where(Probe.status == "online")
        .order_by(Probe.last_seen.desc())
        .limit(1)
    )
    probe = probe_res.scalar_one_or_none()

    last_scan_res = await db.execute(
        select(Scan)
        .where(Scan.org_id == str(org.id), Scan.status == "completed")
        .order_by(Scan.completed_at.desc())
        .limit(1)
    )
    last_scan = last_scan_res.scalar_one_or_none()

    return {
        "probe_online": probe is not None,
        "probe_id":     probe.probe_id if probe else None,
        "last_scan_id": str(last_scan.id) if last_scan else None,
        "last_scan_at": last_scan.completed_at.isoformat() if last_scan and last_scan.completed_at else None,
        "device_count": 0,  # populated from last scan on demand
    }
