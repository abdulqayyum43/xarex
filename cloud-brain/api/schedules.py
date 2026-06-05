"""Scheduled Scan API — create and manage recurring autonomous scans."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import get_org
from models.database import get_db
from models.schemas import MessageResponse
from models.tables import Org, ScheduledScan
from services.scheduler import add_schedule, next_run_time, remove_schedule, validate_cron

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/schedules", tags=["schedules"])


# ──────────────────────────────────────────────
#  Schemas
# ──────────────────────────────────────────────

class ScheduleCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    cron_expression: str = Field(..., description="Standard 5-field cron, e.g. '0 2 * * 1' = Monday 02:00 UTC")
    probe_id: str | None = Field(None, description="Probe to use; auto-selected if omitted")
    config: dict[str, Any] = Field(default_factory=dict, description="Scan configuration (subnets, checks, etc.)")
    enabled: bool = True


class ScheduleUpdate(BaseModel):
    name: str | None = None
    cron_expression: str | None = None
    probe_id: str | None = None
    config: dict[str, Any] | None = None
    enabled: bool | None = None


class ScheduleRead(BaseModel):
    model_config = {"from_attributes": True}

    id: str
    org_id: str
    name: str
    cron_expression: str
    probe_id: str | None
    config: dict[str, Any]
    enabled: bool
    last_run_at: datetime | None
    next_run_at: datetime | None
    created_at: datetime


# ──────────────────────────────────────────────
#  Routes
# ──────────────────────────────────────────────

@router.post("", response_model=ScheduleRead, status_code=status.HTTP_201_CREATED)
async def create_schedule(
    body: ScheduleCreate,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
) -> ScheduleRead:
    """Create a new recurring scan schedule."""
    if not validate_cron(body.cron_expression):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid cron expression: '{body.cron_expression}'. Use 5-field format (min hr dom mon dow).",
        )

    next_run = next_run_time(body.cron_expression)
    schedule = ScheduledScan(
        id=str(uuid.uuid4()),
        org_id=org.id,
        name=body.name,
        cron_expression=body.cron_expression,
        probe_id=body.probe_id,
        config={**body.config, "name": body.name},
        enabled=body.enabled,
        next_run_at=next_run,
    )
    db.add(schedule)
    await db.commit()
    await db.refresh(schedule)

    if schedule.enabled:
        await add_schedule(
            schedule_id=schedule.id,
            org_id=org.id,
            cron_expr=schedule.cron_expression,
            scan_config={**schedule.config, "name": schedule.name},
        )

    logger.info("Schedule created", schedule_id=schedule.id, cron=body.cron_expression)
    return ScheduleRead.model_validate(schedule)


@router.get("", response_model=list[ScheduleRead])
async def list_schedules(
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
) -> list[ScheduleRead]:
    """List all schedules for the authenticated org."""
    result = await db.execute(
        select(ScheduledScan)
        .where(ScheduledScan.org_id == org.id)
        .order_by(ScheduledScan.created_at.desc())
    )
    schedules = result.scalars().all()

    # Refresh next_run_at from live cron
    output = []
    for s in schedules:
        s.next_run_at = next_run_time(s.cron_expression)
        output.append(ScheduleRead.model_validate(s))
    return output


@router.get("/{schedule_id}", response_model=ScheduleRead)
async def get_schedule(
    schedule_id: str,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
) -> ScheduleRead:
    """Get a specific schedule."""
    schedule = await _get_schedule_or_404(schedule_id, org.id, db)
    schedule.next_run_at = next_run_time(schedule.cron_expression)
    return ScheduleRead.model_validate(schedule)


@router.put("/{schedule_id}", response_model=ScheduleRead)
async def update_schedule(
    schedule_id: str,
    body: ScheduleUpdate,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
) -> ScheduleRead:
    """Update a schedule."""
    schedule = await _get_schedule_or_404(schedule_id, org.id, db)

    if body.cron_expression is not None:
        if not validate_cron(body.cron_expression):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid cron expression: '{body.cron_expression}'",
            )
        schedule.cron_expression = body.cron_expression
        schedule.next_run_at = next_run_time(body.cron_expression)

    if body.name is not None:
        schedule.name = body.name
    if body.probe_id is not None:
        schedule.probe_id = body.probe_id
    if body.config is not None:
        schedule.config = body.config
    if body.enabled is not None:
        schedule.enabled = body.enabled

    await db.commit()
    await db.refresh(schedule)

    # Re-register with scheduler
    await remove_schedule(schedule_id)
    if schedule.enabled:
        await add_schedule(
            schedule_id=schedule.id,
            org_id=org.id,
            cron_expr=schedule.cron_expression,
            scan_config={**schedule.config, "name": schedule.name},
        )

    return ScheduleRead.model_validate(schedule)


@router.delete("/{schedule_id}", response_model=MessageResponse)
async def delete_schedule(
    schedule_id: str,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    """Delete a schedule and deregister it from the scheduler."""
    schedule = await _get_schedule_or_404(schedule_id, org.id, db)
    await remove_schedule(schedule_id)
    await db.delete(schedule)
    await db.commit()
    logger.info("Schedule deleted", schedule_id=schedule_id)
    return MessageResponse(message="Schedule deleted")


@router.post("/{schedule_id}/run", response_model=dict)
async def run_schedule_now(
    schedule_id: str,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Manually trigger a scheduled scan immediately."""
    schedule = await _get_schedule_or_404(schedule_id, org.id, db)

    from services.scheduler import _run_scheduled_scan
    await _run_scheduled_scan(
        schedule_id=schedule.id,
        org_id=org.id,
        scan_config={**schedule.config, "name": f"{schedule.name} (manual)"},
    )

    return {"message": "Scan triggered", "schedule_id": schedule_id}


# ──────────────────────────────────────────────
#  Helpers
# ──────────────────────────────────────────────

async def _get_schedule_or_404(schedule_id: str, org_id: str, db: AsyncSession) -> ScheduledScan:
    result = await db.execute(
        select(ScheduledScan).where(
            ScheduledScan.id == schedule_id,
            ScheduledScan.org_id == org_id,
        )
    )
    schedule = result.scalar_one_or_none()
    if schedule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Schedule not found")
    return schedule
