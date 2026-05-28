"""Admin endpoints — org management (requires ADMIN_SECRET)."""
import uuid
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from core.database import get_db, Organization
from core.auth import require_admin, generate_api_key

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])


class CreateOrgRequest(BaseModel):
    name: str
    plan: str = "starter"


@router.post("/orgs")
def create_org(
    req: CreateOrgRequest,
    db: Session = Depends(get_db),
    _=Depends(require_admin),
):
    api_key = generate_api_key()
    org = Organization(
        id=uuid.uuid4(),
        name=req.name,
        plan=req.plan,
        api_key=api_key,
    )
    db.add(org)
    db.commit()
    return {"org_id": str(org.id), "name": org.name, "plan": org.plan, "api_key": api_key}


@router.get("/orgs")
def list_orgs(db: Session = Depends(get_db), _=Depends(require_admin)):
    orgs = db.query(Organization).order_by(Organization.created_at.desc()).all()
    return [
        {"org_id": str(o.id), "name": o.name, "plan": o.plan, "created_at": o.created_at}
        for o in orgs
    ]
