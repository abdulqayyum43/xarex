"""Secrets / Git scanner API.

Scans a public git repository for leaked credentials. Useful for:
  - Developers auditing their own repos before going public
  - SOC teams checking org repos after a suspected leak
  - Acquirers / due-diligence reviewers

Note: deliberately NOT using `from __future__ import annotations` — see
`api/leads.py` for the slowapi / Pydantic interaction that breaks otherwise.
"""

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from api.auth import get_org
from limiter import limiter
from models.tables import Org
from services.secrets_scanner import scan_git_url

router = APIRouter(prefix="/secrets", tags=["secrets"])


class SecretsScanReq(BaseModel):
    git_url: str = Field(
        ...,
        min_length=10,
        max_length=512,
        description="HTTPS git URL of a public repository to scan",
        examples=["https://github.com/Plazmaz/leaky-repo"],
    )


@router.post("/scan")
@limiter.limit("3/minute")
async def post_secrets_scan(
    request: Request,
    body: SecretsScanReq,
    org: Org = Depends(get_org),
):
    """Clone and scan a public git repo for leaked credentials.

    Hard limits: 100 MB clone, 60 s scan, 5000 files, 5 MB per file.
    Rate limit: 3 scans / minute / IP.
    """
    try:
        result = await scan_git_url(body.git_url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return result
