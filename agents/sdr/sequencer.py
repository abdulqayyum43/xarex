"""
Outreach sequencer — manages the multi-step sending schedule
and tracks replies/opens per prospect.
"""
import uuid
import json
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from sqlalchemy.orm import Session
from sqlalchemy import Column, String, Text, DateTime, Boolean
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from core.database import Base


class OutreachCampaign(Base):
    __tablename__ = "outreach_campaigns"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), nullable=False)
    name = Column(String(255))
    product_description = Column(Text)
    value_prop = Column(Text)
    sender_name = Column(String(100))
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class OutreachStep(Base):
    __tablename__ = "outreach_steps"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    campaign_id = Column(UUID(as_uuid=True), nullable=False)
    prospect_email = Column(String(255))
    prospect_name = Column(String(255))
    step_number = Column(String(10))
    subject = Column(Text)
    body = Column(Text)
    scheduled_at = Column(DateTime(timezone=True))
    sent_at = Column(DateTime(timezone=True))
    opened = Column(Boolean, default=False)
    replied = Column(Boolean, default=False)


def schedule_sequence(
    db: Session,
    campaign_id: str,
    prospect_email: str,
    prospect_name: str,
    sequence: "OutreachSequence",
    start_at: datetime = None,
):
    """Create send-schedule rows for all steps of an outreach sequence."""
    base = start_at or datetime.utcnow()
    steps = [
        ("1", sequence.subject, sequence.email_body, base),
        ("2", f"Re: {sequence.subject}", sequence.follow_up_1, base + timedelta(days=3)),
        ("3", f"Re: {sequence.subject}", sequence.follow_up_2, base + timedelta(days=7)),
    ]
    for step_num, subject, body, scheduled_at in steps:
        if not body:
            continue
        db.add(
            OutreachStep(
                id=uuid.uuid4(),
                campaign_id=campaign_id,
                prospect_email=prospect_email,
                prospect_name=prospect_name,
                step_number=step_num,
                subject=subject,
                body=body,
                scheduled_at=scheduled_at,
            )
        )
    db.commit()


def get_due_steps(db: Session) -> list[OutreachStep]:
    """Fetch all steps that are due to be sent and haven't been sent yet."""
    return (
        db.query(OutreachStep)
        .filter(
            OutreachStep.scheduled_at <= datetime.utcnow(),
            OutreachStep.sent_at.is_(None),
            OutreachStep.replied.is_(False),
        )
        .all()
    )
