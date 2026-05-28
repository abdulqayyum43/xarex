"""Customer support agent endpoints."""
import uuid
from fastapi import APIRouter, Depends, UploadFile, File, Form, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from core.database import get_db, AgentRun
from core.auth import get_current_org
from agents.support.responder import answer_ticket
from agents.support.ingestion import ingest_text, ingest_url

router = APIRouter(prefix="/api/v1/support", tags=["support"])


class TicketRequest(BaseModel):
    text: str
    customer_name: str | None = None
    customer_email: str | None = None
    escalate_threshold: float = 0.6


@router.post("/tickets")
def handle_ticket(
    req: TicketRequest,
    db: Session = Depends(get_db),
    org=Depends(get_current_org),
):
    response = answer_ticket(
        db=db,
        org_id=str(org.id),
        ticket_text=req.text,
        customer_name=req.customer_name,
        escalate_threshold=req.escalate_threshold,
    )

    run = AgentRun(
        id=uuid.uuid4(),
        org_id=org.id,
        agent_type="support",
        status="complete",
        input={"text": req.text, "customer_name": req.customer_name},
        output={
            "answer": response.answer,
            "confidence": response.confidence,
            "should_escalate": response.should_escalate,
            "escalation_reason": response.escalation_reason,
        },
        tokens_used=response.tokens_used,
    )
    db.add(run)
    db.commit()

    return {
        "answer": response.answer,
        "confidence": response.confidence,
        "should_escalate": response.should_escalate,
        "escalation_reason": response.escalation_reason,
    }


@router.post("/knowledge")
async def add_knowledge_text(
    name: str = Form(...),
    content: str = Form(...),
    db: Session = Depends(get_db),
    org=Depends(get_current_org),
):
    count = ingest_text(db, str(org.id), name, content)
    return {"chunks_created": count}


@router.post("/knowledge/url")
async def add_knowledge_url(
    url: str = Form(...),
    db: Session = Depends(get_db),
    org=Depends(get_current_org),
):
    count = await ingest_url(db, str(org.id), url)
    return {"url": url, "chunks_created": count}


@router.post("/knowledge/file")
async def add_knowledge_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    org=Depends(get_current_org),
):
    content = (await file.read()).decode("utf-8", errors="replace")
    count = ingest_text(db, str(org.id), file.filename or "upload", content)
    return {"filename": file.filename, "chunks_created": count}
