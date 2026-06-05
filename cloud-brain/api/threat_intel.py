"""Threat Intelligence API — IP reputation, IOC watchlist, scan enrichment."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import get_org as get_current_org
from models.database import AsyncSessionLocal
from models.tables import IOCWatch, Org

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/threat-intel", tags=["threat-intel"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class IOCCreate(BaseModel):
    ioc_type: str   # ip | domain | url | hash
    value: str
    description: str = ""
    severity: str = "medium"


class IOCResponse(BaseModel):
    id: str
    ioc_type: str
    value: str
    description: str
    severity: str
    active: bool
    created_at: datetime

    class Config:
        from_attributes = True


# ---------------------------------------------------------------------------
# IP Lookup
# ---------------------------------------------------------------------------

@router.get("/ip/{ip}")
async def get_ip_intel(
    ip: str,
    org: Org = Depends(get_current_org),
) -> dict[str, Any]:
    """Look up threat intelligence for a single IP address."""
    from services.threat_intel_service import lookup_ip
    result = await lookup_ip(ip)

    # Check if IP is in org's IOC watchlist
    async with AsyncSessionLocal() as db:
        ioc_result = await db.execute(
            select(IOCWatch).where(
                IOCWatch.org_id == org.id,
                IOCWatch.ioc_type == "ip",
                IOCWatch.value == ip,
                IOCWatch.active == True,
            )
        )
        ioc = ioc_result.scalar_one_or_none()
        if ioc:
            result["watchlisted"] = True
            result["watchlist_severity"] = ioc.severity
            result["watchlist_note"] = ioc.description
        else:
            result["watchlisted"] = False

    return result


# ---------------------------------------------------------------------------
# Scan enrichment
# ---------------------------------------------------------------------------

@router.get("/scans/{scan_id}/enrich")
async def enrich_scan(
    scan_id: str,
    org: Org = Depends(get_current_org),
) -> dict[str, Any]:
    """Enrich all findings in a scan with threat intel for each unique host IP."""
    from services.threat_intel_service import enrich_scan_findings
    from models.tables import Scan

    async with AsyncSessionLocal() as db:
        scan_result = await db.execute(
            select(Scan).where(Scan.id == scan_id, Scan.org_id == org.id)
        )
        scan = scan_result.scalar_one_or_none()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        enrichments = await enrich_scan_findings(scan_id, org.id, db)

    return {
        "scan_id": scan_id,
        "enriched_ips": len(enrichments),
        "results": enrichments,
    }


# ---------------------------------------------------------------------------
# IOC Watchlist
# ---------------------------------------------------------------------------

@router.get("/iocs")
async def list_iocs(
    org: Org = Depends(get_current_org),
) -> list[IOCResponse]:
    """List all IOC watchlist entries for this org."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(IOCWatch)
            .where(IOCWatch.org_id == org.id)
            .order_by(IOCWatch.created_at.desc())
        )
        iocs = result.scalars().all()
    return [IOCResponse.model_validate(i) for i in iocs]


@router.post("/iocs", status_code=201)
async def create_ioc(
    body: IOCCreate,
    org: Org = Depends(get_current_org),
) -> IOCResponse:
    """Add an indicator to the watchlist."""
    valid_types = {"ip", "domain", "url", "hash"}
    if body.ioc_type not in valid_types:
        raise HTTPException(status_code=422, detail=f"ioc_type must be one of {valid_types}")

    valid_severities = {"low", "medium", "high", "critical"}
    if body.severity not in valid_severities:
        raise HTTPException(status_code=422, detail=f"severity must be one of {valid_severities}")

    async with AsyncSessionLocal() as db:
        ioc = IOCWatch(
            org_id=org.id,
            ioc_type=body.ioc_type,
            value=body.value.strip(),
            description=body.description,
            severity=body.severity,
        )
        db.add(ioc)
        await db.commit()
        await db.refresh(ioc)
    return IOCResponse.model_validate(ioc)


@router.delete("/iocs/{ioc_id}")
async def delete_ioc(
    ioc_id: str,
    org: Org = Depends(get_current_org),
) -> dict:
    """Remove an IOC from the watchlist."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(IOCWatch).where(IOCWatch.id == ioc_id, IOCWatch.org_id == org.id)
        )
        ioc = result.scalar_one_or_none()
        if not ioc:
            raise HTTPException(status_code=404, detail="IOC not found")
        await db.delete(ioc)
        await db.commit()
    return {"deleted": True}


@router.patch("/iocs/{ioc_id}/toggle")
async def toggle_ioc(
    ioc_id: str,
    org: Org = Depends(get_current_org),
) -> IOCResponse:
    """Toggle the active state of an IOC."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(IOCWatch).where(IOCWatch.id == ioc_id, IOCWatch.org_id == org.id)
        )
        ioc = result.scalar_one_or_none()
        if not ioc:
            raise HTTPException(status_code=404, detail="IOC not found")
        ioc.active = not ioc.active
        await db.commit()
        await db.refresh(ioc)
    return IOCResponse.model_validate(ioc)


# ---------------------------------------------------------------------------
# Bulk scan IOC match
# ---------------------------------------------------------------------------

@router.get("/scans/{scan_id}/ioc-matches")
async def scan_ioc_matches(
    scan_id: str,
    org: Org = Depends(get_current_org),
) -> dict[str, Any]:
    """Cross-reference scan findings against the org's active IOC watchlist."""
    from models.tables import Scan, Finding

    async with AsyncSessionLocal() as db:
        scan_result = await db.execute(
            select(Scan).where(Scan.id == scan_id, Scan.org_id == org.id)
        )
        if not scan_result.scalar_one_or_none():
            raise HTTPException(status_code=404, detail="Scan not found")

        # Get all active IOC values for this org
        ioc_result = await db.execute(
            select(IOCWatch).where(IOCWatch.org_id == org.id, IOCWatch.active == True)
        )
        iocs = ioc_result.scalars().all()

        ioc_ip_map = {i.value: i for i in iocs if i.ioc_type == "ip"}

        # Get all findings for the scan
        findings_result = await db.execute(
            select(Finding).where(Finding.scan_id == scan_id)
        )
        findings = findings_result.scalars().all()

        matches = []
        for f in findings:
            if f.host in ioc_ip_map:
                ioc = ioc_ip_map[f.host]
                matches.append({
                    "finding_id": f.id,
                    "host": f.host,
                    "finding_title": f.title,
                    "severity": f.severity,
                    "ioc_id": ioc.id,
                    "ioc_severity": ioc.severity,
                    "ioc_description": ioc.description,
                })

    return {
        "scan_id": scan_id,
        "total_findings": len(findings),
        "ioc_matches": len(matches),
        "matches": matches,
    }
