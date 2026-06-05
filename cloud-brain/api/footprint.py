"""Digital Footprint Scanner API."""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import get_org
from models.database import get_db, AsyncSessionLocal
from models.tables import FootprintScan, Org
from services.footprint_scanner import run_footprint_scan

router = APIRouter(prefix="/footprint", tags=["footprint"])


class FootprintReq(BaseModel):
    full_name: str
    location:  str = ""
    email:     str = ""


@router.post("/scan", status_code=202)
async def start_scan(
    body: FootprintReq,
    background_tasks: BackgroundTasks,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
):
    """Queue a footprint scan. Runs in background; poll /footprint/scans/{id} for results."""
    scan = FootprintScan(
        org_id    = org.id,
        full_name = body.full_name.strip(),
        location  = body.location.strip(),
        email     = body.email.strip().lower(),
        status    = "running",
    )
    db.add(scan)
    await db.flush()
    scan_id = scan.id
    await db.commit()

    background_tasks.add_task(_run_scan_bg, scan_id)
    return {"scan_id": scan_id, "status": "running", "message": "Footprint scan started — check back in ~30s"}


async def _run_scan_bg(scan_id: str) -> None:
    async with AsyncSessionLocal() as db:
        r = await db.execute(select(FootprintScan).where(FootprintScan.id == scan_id))
        scan = r.scalar_one_or_none()
        if not scan:
            return
        try:
            result = await run_footprint_scan(scan.full_name, scan.location, scan.email)
            scan.status          = "done"
            scan.exposure_score  = result["exposure_score"]
            scan.sources_checked = result["sources_checked"]
            scan.exposures_found = result["exposures_found"]
            scan.results         = result["results"]
        except Exception as exc:
            scan.status = "failed"
        await db.commit()


@router.get("/scans")
async def list_scans(
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
):
    """List all footprint scans for this org."""
    r = await db.execute(
        select(FootprintScan)
        .where(FootprintScan.org_id == org.id)
        .order_by(FootprintScan.created_at.desc())
        .limit(50)
    )
    scans = r.scalars().all()
    return [
        {
            "id":              s.id,
            "full_name":       s.full_name,
            "location":        s.location,
            "status":          s.status,
            "exposure_score":  s.exposure_score,
            "sources_checked": s.sources_checked,
            "exposures_found": s.exposures_found,
            "created_at":      s.created_at.isoformat(),
        }
        for s in scans
    ]


@router.get("/scans/{scan_id}")
async def get_scan(
    scan_id: str,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
):
    """Return full results for a completed footprint scan."""
    r = await db.execute(
        select(FootprintScan).where(
            FootprintScan.id == scan_id,
            FootprintScan.org_id == org.id,
        )
    )
    scan = r.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {
        "id":              scan.id,
        "full_name":       scan.full_name,
        "location":        scan.location,
        "email":           scan.email,
        "status":          scan.status,
        "exposure_score":  scan.exposure_score,
        "sources_checked": scan.sources_checked,
        "exposures_found": scan.exposures_found,
        "results":         scan.results or [],
        "created_at":      scan.created_at.isoformat(),
    }
