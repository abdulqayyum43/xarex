"""Admin routes – protected by X-Admin-Secret header."""
from __future__ import annotations

import secrets
import uuid

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import get_admin
from models.database import get_db
from models.schemas import AdminStats, MessageResponse, OrgCreate, OrgRead
from models.tables import Finding, Org, Probe, Scan, ScheduledScan

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/admin", tags=["admin"])


# ---------------------------------------------------------------------------
# Create org
# ---------------------------------------------------------------------------

@router.post("/orgs", response_model=OrgRead, status_code=status.HTTP_201_CREATED)
async def create_org(
    body: OrgCreate,
    _: str = Depends(get_admin),
    db: AsyncSession = Depends(get_db),
) -> OrgRead:
    """Create a new organisation and return its generated API key."""
    # Check for name uniqueness
    existing = await db.execute(select(Org).where(Org.name == body.name))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Organisation '{body.name}' already exists",
        )

    api_key = f"xrx_{secrets.token_urlsafe(32)}"
    org = Org(
        id=str(uuid.uuid4()),
        name=body.name,
        api_key=api_key,
    )
    db.add(org)
    await db.commit()
    await db.refresh(org)

    logger.info("Org created", org_id=org.id, name=org.name)
    return OrgRead.model_validate(org)


# ---------------------------------------------------------------------------
# List orgs
# ---------------------------------------------------------------------------

@router.get("/orgs", response_model=list[OrgRead])
async def list_orgs(
    _: str = Depends(get_admin),
    db: AsyncSession = Depends(get_db),
) -> list[OrgRead]:
    """Return all organisations."""
    result = await db.execute(select(Org).order_by(Org.created_at.desc()))
    orgs = result.scalars().all()
    return [OrgRead.model_validate(o) for o in orgs]


@router.get("/orgs/{org_id}", response_model=OrgRead)
async def get_org_detail(
    org_id: str,
    _: str = Depends(get_admin),
    db: AsyncSession = Depends(get_db),
) -> OrgRead:
    """Return a single organisation by ID."""
    result = await db.execute(select(Org).where(Org.id == org_id))
    org = result.scalar_one_or_none()
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organisation not found")
    return OrgRead.model_validate(org)


@router.delete("/orgs/{org_id}", response_model=MessageResponse)
async def delete_org(
    org_id: str,
    _: str = Depends(get_admin),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    """Delete an organisation and all its associated data."""
    result = await db.execute(select(Org).where(Org.id == org_id))
    org = result.scalar_one_or_none()
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organisation not found")

    # Delete associated schedules
    schedules = await db.execute(select(ScheduledScan).where(ScheduledScan.org_id == org_id))
    for s in schedules.scalars().all():
        await db.delete(s)

    await db.delete(org)
    await db.commit()
    logger.info("Org deleted", org_id=org_id)
    return MessageResponse(message=f"Organisation '{org.name}' deleted")


# ---------------------------------------------------------------------------
# Platform stats
# ---------------------------------------------------------------------------

@router.get("/stats", response_model=AdminStats)
async def get_stats(
    _: str = Depends(get_admin),
    db: AsyncSession = Depends(get_db),
) -> AdminStats:
    """Return aggregate platform statistics."""
    total_orgs = (await db.execute(select(func.count()).select_from(Org))).scalar_one()
    total_probes = (await db.execute(select(func.count()).select_from(Probe))).scalar_one()
    total_scans = (await db.execute(select(func.count()).select_from(Scan))).scalar_one()
    total_findings = (await db.execute(select(func.count()).select_from(Finding))).scalar_one()

    return AdminStats(
        total_orgs=total_orgs,
        total_probes=total_probes,
        total_scans=total_scans,
        total_findings=total_findings,
    )


@router.get("/debug/queues")
async def debug_queues(_: str = Depends(get_admin)) -> dict:
    """Inspect in-memory task queue state (debug only)."""
    from orchestrator.task_manager import _task_queues, _task_type_map, _pending_tasks
    return {
        "task_queues": {k: v.qsize() for k, v in _task_queues.items()},
        "task_type_map_count": len(_task_type_map),
        "pending_tasks": dict(_pending_tasks),
    }
