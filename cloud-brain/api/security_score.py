"""Personal Security Score API."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import get_org
from models.database import get_db
from models.tables import SecurityScore, Org
from services.score_engine import compute_score

router = APIRouter(prefix="/security-score", tags=["security-score"])


@router.get("")
async def get_score(
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
):
    """Return the latest security score, computing one if it doesn't exist."""
    r = await db.execute(
        select(SecurityScore)
        .where(SecurityScore.org_id == org.id)
        .order_by(SecurityScore.computed_at.desc())
        .limit(1)
    )
    latest = r.scalar_one_or_none()
    if latest:
        return {
            "score":       latest.score,
            "grade":       latest.grade,
            "breakdown":   latest.breakdown,
            "actions":     latest.actions,
            "computed_at": latest.computed_at.isoformat(),
        }
    # No score yet — compute on demand
    return await _compute_and_save(org.id, db)


@router.post("/compute")
async def refresh_score(
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
):
    """Force-recompute the security score."""
    return await _compute_and_save(org.id, db)


@router.get("/history")
async def score_history(
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
    limit: int = 30,
):
    """Return score history for trend charts (newest first)."""
    r = await db.execute(
        select(SecurityScore)
        .where(SecurityScore.org_id == org.id)
        .order_by(SecurityScore.computed_at.desc())
        .limit(limit)
    )
    rows = r.scalars().all()
    return [
        {
            "score":       s.score,
            "grade":       s.grade,
            "computed_at": s.computed_at.isoformat(),
        }
        for s in reversed(rows)
    ]


async def _compute_and_save(org_id: str, db: AsyncSession) -> dict:
    data = await compute_score(org_id, db)
    record = SecurityScore(
        org_id    = org_id,
        score     = data["score"],
        grade     = data["grade"],
        breakdown = data["breakdown"],
        actions   = data["actions"],
    )
    db.add(record)
    return data
