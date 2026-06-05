"""Scan template API — save and reuse scan configurations."""
from __future__ import annotations

import uuid
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import get_org
from models.database import get_db
from models.tables import Org, ScanTemplate

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/scan-templates", tags=["scan-templates"])

# ──────────────────────────────────────────────────────────────────────────────
# Schemas
# ──────────────────────────────────────────────────────────────────────────────

class TemplateCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: str = Field(default="", max_length=512)
    scan_name: str = Field(default="", max_length=255, description="Default name for scans created from this template")
    config: dict[str, Any] = Field(default_factory=dict)


class TemplateRead(BaseModel):
    model_config = {"from_attributes": True}

    id: str
    name: str
    description: str
    scan_name: str
    config: dict[str, Any]
    created_at: Any


# ──────────────────────────────────────────────────────────────────────────────
# Built-in templates (seeded on first call if org has none)
# ──────────────────────────────────────────────────────────────────────────────

_BUILTIN_TEMPLATES = [
    {
        "name": "Internal Network Audit",
        "description": "Full security assessment of an internal subnet — host discovery, port scan, credential checks, SMB, LLMNR, DNS, SNMP, and SSL/TLS audit.",
        "scan_name": "Internal Network Audit",
        "config": {
            "target": "192.168.1.0/24",
            "subnets": ["192.168.1.0/24"],
        },
    },
    {
        "name": "Windows Domain Assessment",
        "description": "Targeted assessment for Active Directory environments — Kerberoasting, SMB relay, LLMNR poisoning, admin panel discovery.",
        "scan_name": "Windows Domain Assessment",
        "config": {
            "target": "10.0.0.0/24",
            "subnets": ["10.0.0.0/24"],
        },
    },
    {
        "name": "Web Server Security Check",
        "description": "SSL/TLS audit, HTTP security headers, admin panel discovery, default credentials, and DNS zone transfer for a single server.",
        "scan_name": "Web Server Security Check",
        "config": {
            "target": "192.168.1.10",
            "subnets": ["192.168.1.10/32"],
        },
    },
    {
        "name": "DMZ / Perimeter Scan",
        "description": "Fast scan of a DMZ segment — exposed services, SSL certificates, admin panels, SNMP community strings.",
        "scan_name": "DMZ Perimeter Scan",
        "config": {
            "target": "10.10.10.0/28",
            "subnets": ["10.10.10.0/28"],
        },
    },
    {
        "name": "Single Host Deep Dive",
        "description": "All security checks against a single target host — comprehensive analysis.",
        "scan_name": "Single Host Assessment",
        "config": {
            "target": "192.168.1.1",
            "subnets": ["192.168.1.1/32"],
        },
    },
]


async def _seed_builtins(org_id: str, db: AsyncSession) -> None:
    """Create built-in templates for an org if they don't already have any."""
    result = await db.execute(
        select(ScanTemplate).where(ScanTemplate.org_id == org_id).limit(1)
    )
    if result.scalar_one_or_none() is not None:
        return  # already seeded

    for tpl in _BUILTIN_TEMPLATES:
        db.add(ScanTemplate(
            id=str(uuid.uuid4()),
            org_id=org_id,
            name=tpl["name"],
            description=tpl["description"],
            scan_name=tpl["scan_name"],
            config=tpl["config"],
        ))
    await db.flush()
    logger.info("Built-in scan templates seeded", org_id=org_id)


# ──────────────────────────────────────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────────────────────────────────────

@router.get("", response_model=list[TemplateRead])
async def list_templates(
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
) -> list[TemplateRead]:
    """Return all scan templates for this org, seeding built-ins on first call."""
    await _seed_builtins(org.id, db)
    result = await db.execute(
        select(ScanTemplate)
        .where(ScanTemplate.org_id == org.id)
        .order_by(ScanTemplate.created_at)
    )
    templates = result.scalars().all()
    return [TemplateRead.model_validate(t) for t in templates]


@router.post("", response_model=TemplateRead, status_code=status.HTTP_201_CREATED)
async def create_template(
    body: TemplateCreate,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
) -> TemplateRead:
    """Save a new scan template."""
    template = ScanTemplate(
        id=str(uuid.uuid4()),
        org_id=org.id,
        name=body.name,
        description=body.description,
        scan_name=body.scan_name or body.name,
        config=body.config,
    )
    db.add(template)
    await db.flush()
    await db.commit()
    await db.refresh(template)
    logger.info("Scan template created", org_id=org.id, name=body.name)
    return TemplateRead.model_validate(template)


@router.put("/{template_id}", response_model=TemplateRead)
async def update_template(
    template_id: str,
    body: TemplateCreate,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
) -> TemplateRead:
    """Update an existing scan template."""
    result = await db.execute(
        select(ScanTemplate).where(ScanTemplate.id == template_id, ScanTemplate.org_id == org.id)
    )
    template = result.scalar_one_or_none()
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")

    template.name = body.name
    template.description = body.description
    template.scan_name = body.scan_name or body.name
    template.config = body.config
    await db.commit()
    await db.refresh(template)
    return TemplateRead.model_validate(template)


@router.delete("/{template_id}")
async def delete_template(
    template_id: str,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Delete a scan template."""
    result = await db.execute(
        select(ScanTemplate).where(ScanTemplate.id == template_id, ScanTemplate.org_id == org.id)
    )
    template = result.scalar_one_or_none()
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")
    await db.delete(template)
    await db.commit()
    return {"message": "Template deleted"}
