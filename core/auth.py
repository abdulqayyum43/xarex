import os
import secrets
from fastapi import HTTPException, Security, Depends
from fastapi.security import APIKeyHeader
from sqlalchemy.orm import Session
from core.database import get_db, Organization

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=True)


def generate_api_key() -> str:
    return secrets.token_urlsafe(32)


async def get_current_org(
    api_key: str = Security(api_key_header),
    db: Session = Depends(get_db),
) -> Organization:
    org = db.query(Organization).filter(Organization.api_key == api_key).first()
    if not org:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return org


def require_admin(api_key: str = Security(api_key_header)):
    admin_secret = os.environ.get("ADMIN_SECRET", "")
    if not admin_secret or api_key != admin_secret:
        raise HTTPException(status_code=403, detail="Admin access required")
