"""SDR agent endpoints — generate outreach and manage campaigns."""
import uuid
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from core.database import get_db, AgentRun
from core.auth import get_current_org
from agents.sdr.writer import generate_outreach
from agents.sdr.prospector import build_prospect_from_dict, enrich_from_apollo

router = APIRouter(prefix="/api/v1/sdr", tags=["sdr"])


class GenerateOutreachRequest(BaseModel):
    prospect_name: str
    prospect_title: str
    company_name: str
    company_description: str
    your_product: str
    your_value_prop: str
    recent_news: str | None = None
    sender_name: str = "Alex"


class EnrichProspectsRequest(BaseModel):
    domain: str
    title_filter: str = "CEO,CTO,VP,Director,Head"


@router.post("/outreach")
def create_outreach(
    req: GenerateOutreachRequest,
    db: Session = Depends(get_db),
    org=Depends(get_current_org),
):
    sequence = generate_outreach(
        prospect_name=req.prospect_name,
        prospect_title=req.prospect_title,
        company_name=req.company_name,
        company_description=req.company_description,
        your_product=req.your_product,
        your_value_prop=req.your_value_prop,
        recent_news=req.recent_news,
        sender_name=req.sender_name,
    )

    run = AgentRun(
        id=uuid.uuid4(),
        org_id=org.id,
        agent_type="sdr",
        status="complete",
        input=req.model_dump(),
        output={
            "subject": sequence.subject,
            "email_body": sequence.email_body,
            "linkedin_message": sequence.linkedin_message,
            "follow_up_1": sequence.follow_up_1,
            "follow_up_2": sequence.follow_up_2,
        },
        tokens_used=sequence.tokens_used,
    )
    db.add(run)
    db.commit()

    return {
        "subject": sequence.subject,
        "email_body": sequence.email_body,
        "linkedin_message": sequence.linkedin_message,
        "follow_up_1": sequence.follow_up_1,
        "follow_up_2": sequence.follow_up_2,
    }


@router.post("/prospects/enrich")
def enrich_prospects(
    req: EnrichProspectsRequest,
    org=Depends(get_current_org),
):
    prospects = enrich_from_apollo(req.domain, req.title_filter)
    return {
        "domain": req.domain,
        "prospects_found": len(prospects),
        "prospects": [
            {
                "name": p.name,
                "title": p.title,
                "company": p.company,
                "email": p.email,
                "linkedin_url": p.linkedin_url,
                "industry": p.industry,
            }
            for p in prospects
        ],
    }
