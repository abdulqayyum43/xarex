"""SIEM & Webhook Integrations — push scan findings to Splunk, Azure Sentinel, or any webhook."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, HttpUrl
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import get_org
from models.database import get_db
from models.tables import Finding, Integration, Org, Scan

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/integrations", tags=["integrations"])


# ── Schemas ───────────────────────────────────────────────────────────────────

class IntegrationCreate(BaseModel):
    name: str
    type: str          # splunk | sentinel | webhook | qradar | elastic
    url: str
    api_key: str | None = None
    enabled: bool = True
    config: dict[str, Any] = {}


class IntegrationRead(BaseModel):
    id: str
    name: str
    type: str
    url: str
    enabled: bool
    config: dict[str, Any]
    created_at: datetime

    model_config = {"from_attributes": True}


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("", response_model=list[IntegrationRead])
async def list_integrations(
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Integration).where(Integration.org_id == org.id))
    return [IntegrationRead.model_validate(i) for i in result.scalars().all()]


@router.post("", response_model=IntegrationRead, status_code=201)
async def create_integration(
    body: IntegrationCreate,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
):
    allowed = {"splunk", "sentinel", "webhook", "qradar", "elastic"}
    if body.type not in allowed:
        raise HTTPException(status_code=400, detail=f"type must be one of: {', '.join(allowed)}")

    integration = Integration(
        id=str(uuid.uuid4()),
        org_id=org.id,
        name=body.name,
        type=body.type,
        url=body.url,
        api_key_encrypted=body.api_key or "",
        enabled=body.enabled,
        config=body.config,
    )
    db.add(integration)
    await db.commit()
    await db.refresh(integration)
    logger.info("Integration created", org_id=org.id, type=body.type, name=body.name)
    return IntegrationRead.model_validate(integration)


@router.delete("/{integration_id}", status_code=204)
async def delete_integration(
    integration_id: str,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Integration).where(Integration.id == integration_id, Integration.org_id == org.id)
    )
    intg = result.scalar_one_or_none()
    if not intg:
        raise HTTPException(status_code=404, detail="Integration not found")
    await db.delete(intg)
    await db.commit()


@router.post("/{integration_id}/test")
async def test_integration(
    integration_id: str,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
) -> dict:
    result = await db.execute(
        select(Integration).where(Integration.id == integration_id, Integration.org_id == org.id)
    )
    intg = result.scalar_one_or_none()
    if not intg:
        raise HTTPException(status_code=404, detail="Integration not found")

    payload = {
        "source": "xarex",
        "event": "test",
        "message": "Xarex integration test — connection successful",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    ok, error = await _send(intg, payload)
    return {"success": ok, "error": error}


@router.post("/scans/{scan_id}/export")
async def export_scan(
    scan_id: str,
    integration_id: str | None = None,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Push all findings from a scan to one or all enabled integrations."""
    scan_result = await db.execute(select(Scan).where(Scan.id == scan_id, Scan.org_id == org.id))
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings_result = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
    findings = findings_result.scalars().all()

    query = select(Integration).where(Integration.org_id == org.id, Integration.enabled == True)
    if integration_id:
        query = query.where(Integration.id == integration_id)
    intg_result = await db.execute(query)
    integrations = intg_result.scalars().all()

    if not integrations:
        raise HTTPException(status_code=400, detail="No enabled integrations found")

    SEV = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}

    results = []
    for intg in integrations:
        events = []
        for f in findings:
            events.append({
                "source":       "xarex",
                "event_type":   "finding",
                "scan_id":      scan_id,
                "scan_name":    scan.name,
                "host":         f.host,
                "port":         f.port,
                "service":      f.service,
                "severity":     SEV.get(f.severity, "info"),
                "title":        f.title,
                "description":  f.description,
                "cve_id":       f.cve_id,
                "evidence":     f.evidence,
                "remediation":  f.remediation,
                "timestamp":    f.timestamp.isoformat() if f.timestamp else None,
            })

        payload = {
            "source":     "xarex",
            "event_type": "scan_complete",
            "scan_id":    scan_id,
            "scan_name":  scan.name,
            "org_id":     org.id,
            "finding_count": len(findings),
            "critical_count": scan.critical_count or 0,
            "findings": events,
            "exported_at": datetime.now(timezone.utc).isoformat(),
        }

        ok, error = await _send(intg, payload)
        results.append({"integration": intg.name, "type": intg.type, "success": ok, "error": error})
        logger.info("Scan exported", scan_id=scan_id, integration=intg.name, success=ok)

    return {"scan_id": scan_id, "results": results}


# ── HTTP delivery ─────────────────────────────────────────────────────────────

async def _send(intg: Integration, payload: dict) -> tuple[bool, str | None]:
    """Send payload to the integration endpoint. Returns (success, error_msg)."""
    import httpx

    headers = {"Content-Type": "application/json"}

    if intg.type == "splunk":
        headers["Authorization"] = f"Splunk {intg.api_key_encrypted}"
        body = {"event": payload, "sourcetype": "xarex", "index": intg.config.get("index", "main")}
    elif intg.type == "sentinel":
        headers["Log-Type"] = intg.config.get("log_type", "XarexFindings")
        if intg.api_key_encrypted:
            headers["Authorization"] = f"SharedKey {intg.api_key_encrypted}"
        body = payload if isinstance(payload, list) else [payload]
    elif intg.type == "qradar":
        headers["SEC"] = intg.api_key_encrypted or ""
        body = payload
    else:
        # Generic webhook
        if intg.api_key_encrypted:
            headers["Authorization"] = f"Bearer {intg.api_key_encrypted}"
        body = payload

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(intg.url, json=body, headers=headers)
            if resp.status_code < 300:
                return True, None
            return False, f"HTTP {resp.status_code}: {resp.text[:200]}"
    except Exception as exc:
        return False, str(exc)
