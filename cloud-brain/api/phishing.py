"""Phishing Simulation — create and track phishing awareness campaigns."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import structlog
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import get_org
from models.database import get_db
from models.tables import Org, PhishingCampaign

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/phishing", tags=["phishing"])


# ── Schemas ───────────────────────────────────────────────────────────────────

class CampaignCreate(BaseModel):
    name: str
    targets: list[str]         # email addresses
    template: str = "generic"  # generic | invoice | it_helpdesk | hr_password | ceo_fraud
    landing_page: str = "credential_harvest"
    redirect_url: str = "https://example.com"


class CampaignRead(BaseModel):
    id: str
    name: str
    status: str
    template: str
    target_count: int
    sent_count: int
    opened_count: int
    clicked_count: int
    submitted_count: int
    created_at: datetime

    model_config = {"from_attributes": True}


# ── Email templates ───────────────────────────────────────────────────────────

TEMPLATES: dict[str, dict[str, str]] = {
    "generic": {
        "subject": "Important: Action Required",
        "body":    "Please click the link below to verify your account.",
        "sender":  "security@{domain}",
    },
    "invoice": {
        "subject": "Invoice #{num} — Payment Required",
        "body":    "Please review and approve the attached invoice.",
        "sender":  "billing@{domain}",
    },
    "it_helpdesk": {
        "subject": "IT Alert: Password Expiry Notice",
        "body":    "Your network password expires in 24 hours. Click here to reset it.",
        "sender":  "it-support@{domain}",
    },
    "hr_password": {
        "subject": "HR Portal: Your Account Has Been Locked",
        "body":    "Your HR portal account has been locked. Click to unlock.",
        "sender":  "hr@{domain}",
    },
    "ceo_fraud": {
        "subject": "Urgent Request from CEO",
        "body":    "I need you to process an urgent wire transfer. Reply ASAP.",
        "sender":  "ceo@{domain}",
    },
    "microsoft_365": {
        "subject": "Microsoft 365: Unusual sign-in activity",
        "body":    "We detected a suspicious login to your Microsoft 365 account.",
        "sender":  "no-reply@microsoft-security.com",
    },
}


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("", response_model=list[CampaignRead])
async def list_campaigns(
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(PhishingCampaign).where(PhishingCampaign.org_id == org.id)
        .order_by(PhishingCampaign.created_at.desc())
    )
    return [CampaignRead.model_validate(c) for c in result.scalars().all()]


@router.post("", response_model=CampaignRead, status_code=201)
async def create_campaign(
    body: CampaignCreate,
    background_tasks: BackgroundTasks,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
):
    if body.template not in TEMPLATES:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown template '{body.template}'. Available: {', '.join(TEMPLATES)}"
        )
    if not body.targets:
        raise HTTPException(status_code=400, detail="At least one target email is required")
    if len(body.targets) > 500:
        raise HTTPException(status_code=400, detail="Max 500 targets per campaign")

    campaign = PhishingCampaign(
        id=str(uuid.uuid4()),
        org_id=org.id,
        name=body.name,
        status="pending",
        template=body.template,
        landing_page=body.landing_page,
        redirect_url=body.redirect_url,
        targets=body.targets,
        target_count=len(body.targets),
        sent_count=0,
        opened_count=0,
        clicked_count=0,
        submitted_count=0,
    )
    db.add(campaign)
    await db.commit()
    await db.refresh(campaign)

    background_tasks.add_task(_send_campaign, campaign.id, org.id)
    logger.info("Phishing campaign created", campaign_id=campaign.id, targets=len(body.targets))
    return CampaignRead.model_validate(campaign)


@router.get("/{campaign_id}", response_model=CampaignRead)
async def get_campaign(
    campaign_id: str,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(PhishingCampaign).where(PhishingCampaign.id == campaign_id, PhishingCampaign.org_id == org.id)
    )
    campaign = result.scalar_one_or_none()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return CampaignRead.model_validate(campaign)


@router.get("/{campaign_id}/results")
async def campaign_results(
    campaign_id: str,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    result = await db.execute(
        select(PhishingCampaign).where(PhishingCampaign.id == campaign_id, PhishingCampaign.org_id == org.id)
    )
    campaign = result.scalar_one_or_none()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")

    total = campaign.target_count or 1
    return {
        "campaign_id":    campaign.id,
        "name":           campaign.name,
        "status":         campaign.status,
        "template":       campaign.template,
        "targets_total":  campaign.target_count,
        "sent":           campaign.sent_count,
        "opened":         campaign.opened_count,
        "clicked":        campaign.clicked_count,
        "submitted":      campaign.submitted_count,
        "open_rate":      round((campaign.opened_count / total) * 100, 1),
        "click_rate":     round((campaign.clicked_count / total) * 100, 1),
        "submit_rate":    round((campaign.submitted_count / total) * 100, 1),
        "risk_rating":    _risk_rating(campaign.clicked_count, total),
        "recommendations": _recommendations(campaign),
    }


@router.get("/templates/list")
async def list_templates() -> dict:
    return {
        "templates": [
            {"id": k, "subject": v["subject"], "sender": v["sender"]}
            for k, v in TEMPLATES.items()
        ]
    }


# ── Background send ───────────────────────────────────────────────────────────

async def _send_campaign(campaign_id: str, org_id: str) -> None:
    """Background task: mark campaign as running and simulate send."""
    from models.database import AsyncSessionLocal
    from sqlalchemy import update

    async with AsyncSessionLocal() as db:
        try:
            result = await db.execute(select(PhishingCampaign).where(PhishingCampaign.id == campaign_id))
            campaign = result.scalar_one_or_none()
            if not campaign:
                return

            await db.execute(
                update(PhishingCampaign)
                .where(PhishingCampaign.id == campaign_id)
                .values(status="running", sent_count=campaign.target_count)
            )
            await db.commit()
            logger.info("Campaign emails dispatched", campaign_id=campaign_id, count=campaign.target_count)
        except Exception as exc:
            logger.error("Campaign send error", campaign_id=campaign_id, error=str(exc))


# ── Helpers ───────────────────────────────────────────────────────────────────

def _risk_rating(clicked: int, total: int) -> str:
    pct = (clicked / max(total, 1)) * 100
    if pct >= 30:
        return "CRITICAL"
    if pct >= 15:
        return "HIGH"
    if pct >= 5:
        return "MEDIUM"
    return "LOW"


def _recommendations(c: PhishingCampaign) -> list[str]:
    recs = []
    total = c.target_count or 1
    click_pct = (c.clicked_count / total) * 100
    submit_pct = (c.submitted_count / total) * 100

    if click_pct >= 15:
        recs.append("Mandatory phishing awareness training for all staff")
        recs.append("Implement email link-rewriting and detonation sandbox")
    if submit_pct >= 5:
        recs.append("Enable MFA on all user accounts immediately")
        recs.append("Deploy credential-stuffing protection on login pages")
    if c.template in ("ceo_fraud", "invoice"):
        recs.append("Implement BEC detection and out-of-band wire-transfer verification")
    if not recs:
        recs.append("Security posture is good — run quarterly simulations to maintain awareness")
    return recs
