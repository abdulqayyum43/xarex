"""Recon API — passive reconnaissance endpoints.

Currently:
  - POST /api/v1/recon/subdomains  — subdomain enumeration via crt.sh + OTX + HackerTarget
  - POST /api/v1/recon/emails      — OSINT employee email harvest + breach lookup

Note: deliberately NOT using `from __future__ import annotations` — slowapi's
`@limiter.limit(...)` decorator wraps endpoints in a way that breaks Pydantic
class-reference resolution when annotations are deferred. See `api/leads.py`
for the same constraint.
"""

from fastapi import APIRouter, Depends, HTTPException, Request

from api.auth import get_org
from limiter import limiter
from models.tables import Org
from pydantic import BaseModel, Field
from services.osint_email import harvest_emails
from services.subdomain_enum import enumerate_subdomains

router = APIRouter(prefix="/recon", tags=["recon"])


# ──────────────────────────────────────────────────────────────────────────────
# Subdomains
# ──────────────────────────────────────────────────────────────────────────────


class SubdomainsReq(BaseModel):
    domain:      str  = Field(..., min_length=3, max_length=253)
    resolve:     bool = Field(True, description="Resolve each subdomain to its IP")
    max_results: int  = Field(500, ge=10, le=2000)


@router.post("/subdomains")
@limiter.limit("10/minute")
async def post_subdomains(
    request: Request,
    body: SubdomainsReq,
    org: Org = Depends(get_org),
):
    """Enumerate subdomains for a domain via passive public sources.

    Runs synchronously — typical completion 5-20s depending on cert volume.
    Returns inline; no DB persistence in v1 (frontend caches in localStorage).
    """
    try:
        result = await enumerate_subdomains(
            body.domain,
            resolve=body.resolve,
            max_results=body.max_results,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Enumeration failed: {exc}")

    return result


# ──────────────────────────────────────────────────────────────────────────────
# OSINT email harvesting
# ──────────────────────────────────────────────────────────────────────────────


class EmailsReq(BaseModel):
    domain:         str  = Field(..., min_length=3, max_length=253)
    check_breaches: bool = Field(True, description="Enrich each email with HIBP breach data (requires HIBP_API_KEY)")
    max_results:    int  = Field(100, ge=5, le=500)


@router.post("/emails")
@limiter.limit("6/minute")
async def post_emails(
    request: Request,
    body: EmailsReq,
    org: Org = Depends(get_org),
):
    """Harvest passively-discoverable employee emails for a domain.

    Sources: certificate transparency (crt.sh) + public PGP keyservers.
    Each result is enriched with HIBP breach status when an HIBP API key
    is configured (best-effort, rate-limited).
    """
    try:
        result = await harvest_emails(
            body.domain,
            check_breaches=body.check_breaches,
            max_results=body.max_results,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Harvest failed: {exc}")

    return result
