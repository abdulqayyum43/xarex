"""Probe management API routes."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import get_org
from models.database import get_db
from models.schemas import ProbeRead
from models.tables import Org, Probe

router = APIRouter(prefix="/probes", tags=["probes"])

# A probe is considered online if it sent a heartbeat within this window.
PROBE_ONLINE_THRESHOLD = timedelta(minutes=5)


def _compute_status(probe: Probe) -> str:
    """Return 'online' only if last_seen is within the heartbeat threshold."""
    if probe.last_seen is None:
        return "offline"
    last_seen = probe.last_seen
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)
    age = datetime.now(timezone.utc) - last_seen
    return "online" if age <= PROBE_ONLINE_THRESHOLD else "offline"


def _probe_to_read(probe: Probe) -> ProbeRead:
    """Serialize a Probe ORM object, injecting the live-computed status."""
    probe.status = _compute_status(probe)
    return ProbeRead.model_validate(probe)


@router.get("", response_model=list[ProbeRead])
async def list_probes(
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
) -> list[ProbeRead]:
    """Return all probes registered to the authenticated org with live status."""
    result = await db.execute(select(Probe).where(Probe.org_id == org.id))
    probes = result.scalars().all()
    return [_probe_to_read(p) for p in probes]


@router.get("/{probe_id}", response_model=ProbeRead)
async def get_probe(
    probe_id: str,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
) -> ProbeRead:
    """Return detail and live status of a specific probe."""
    result = await db.execute(
        select(Probe).where(Probe.probe_id == probe_id, Probe.org_id == org.id)
    )
    probe = result.scalar_one_or_none()
    if probe is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Probe '{probe_id}' not found",
        )
    return _probe_to_read(probe)
