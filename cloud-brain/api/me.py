"""Self-introspection endpoint — returns the authenticated org's identity.

The dashboard needs the caller's `org_id` to populate probe-deploy
instructions (the api_key alone doesn't reveal it, and there's no other
authenticated way for the UI to learn its own org without admin auth).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends

from api.auth import get_org
from models.schemas import OrgRead
from models.tables import Org

router = APIRouter(tags=["me"])


@router.get("/me", response_model=OrgRead)
async def get_me(org: Org = Depends(get_org)) -> Org:
    """Return the authenticated org's id, name, api_key, and created_at."""
    return org
