"""Notification Center API."""
from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import get_org
from models.database import get_db
from models.tables import Notification, Org
from services.notification_service import (
    get_notifications,
    mark_all_read,
    mark_read,
    run_all_guardian_checks,
    unread_count,
)

router = APIRouter(prefix="/notifications", tags=["notifications"])


def _serialize(n: Notification) -> dict:
    return {
        "id":           n.id,
        "kind":         n.kind,
        "severity":     n.severity,
        "title":        n.title,
        "body":         n.body,
        "action_url":   n.action_url,
        "action_label": n.action_label,
        "read":         n.read,
        "created_at":   n.created_at.isoformat(),
    }


@router.get("")
async def list_notifications(
    unread_only: bool = False,
    limit: int = 50,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
):
    items = await get_notifications(str(org.id), db, unread_only=unread_only, limit=limit)
    return [_serialize(n) for n in items]


@router.get("/unread-count")
async def get_unread_count(
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
):
    count = await unread_count(str(org.id), db)
    return {"count": count}


@router.post("/{notification_id}/read", status_code=204)
async def mark_notification_read(
    notification_id: str,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
):
    await mark_read(str(org.id), notification_id, db)
    await db.commit()


@router.post("/read-all", status_code=204)
async def mark_all_notifications_read(
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
):
    await mark_all_read(str(org.id), db)
    await db.commit()


@router.post("/run-checks", status_code=202)
async def trigger_guardian_checks(
    background_tasks: BackgroundTasks,
    org: Org = Depends(get_org),
):
    """Manually trigger domain + breach re-checks for this org."""
    from services.notification_service import run_domain_checks_for_org, run_breach_checks_for_org

    async def _run():
        await run_domain_checks_for_org(str(org.id))
        await run_breach_checks_for_org(str(org.id))

    background_tasks.add_task(_run)
    return {"message": "Checks triggered — notifications will appear shortly"}
