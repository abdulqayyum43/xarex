"""Link & Email Analyzer API."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import get_org
from models.database import get_db
from models.tables import AnalysisResult, Org
from services.link_analyzer import analyze_url, analyze_email

router = APIRouter(prefix="/analyze", tags=["analyzer"])


class URLReq(BaseModel):
    url: str

class EmailReq(BaseModel):
    raw_email: str


@router.post("/url")
async def check_url(
    body: URLReq,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
):
    """Analyse a URL for phishing, malware, and safety indicators."""
    result = await analyze_url(body.url)

    record = AnalysisResult(
        org_id      = org.id,
        kind        = "url",
        input_value = body.url[:1000],
        verdict     = result["verdict"],
        risk_score  = result["risk_score"],
        result_json = result,
    )
    db.add(record)
    result["analysis_id"] = record.id
    return result


@router.post("/email")
async def check_email(
    body: EmailReq,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
):
    """Analyse raw email text (paste full headers + body) for phishing indicators."""
    result = await analyze_email(body.raw_email)

    record = AnalysisResult(
        org_id      = org.id,
        kind        = "email",
        input_value = body.raw_email[:2000],
        verdict     = result["verdict"],
        risk_score  = result["risk_score"],
        result_json = result,
    )
    db.add(record)
    result["analysis_id"] = record.id
    return result


@router.get("/history")
async def analysis_history(
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
    limit: int = 20,
):
    """Return recent analysis results for this org."""
    from sqlalchemy import select
    r = await db.execute(
        select(AnalysisResult)
        .where(AnalysisResult.org_id == org.id)
        .order_by(AnalysisResult.created_at.desc())
        .limit(limit)
    )
    items = r.scalars().all()
    return [
        {
            "id":          a.id,
            "kind":        a.kind,
            "input":       a.input_value[:80],
            "verdict":     a.verdict,
            "risk_score":  a.risk_score,
            "created_at":  a.created_at.isoformat(),
        }
        for a in items
    ]
