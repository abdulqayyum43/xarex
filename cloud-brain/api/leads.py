"""Xarex — public lead-capture API.

Endpoints:
  POST /api/v1/leads   Receive a lead submission from the marketing site

This endpoint is intentionally PUBLIC (no API key, no org context). It receives
anonymous form submissions from the marketing site (e.g. the sample-report
gated download form, or a future "Contact sales" form). Submissions are stored
in the `leads` table for sales follow-up.

Security notes:
  - All string fields are length-capped via Pydantic Field(max_length=...).
  - Honeypot field `website` silently swallows obvious-bot submissions.
  - User-supplied content is stored as plain text and is NOT echoed back into
    HTML anywhere in the codebase. Any future consumer (admin UI, email, etc.)
    MUST escape these fields before rendering.
  - We log structured events but never the full request body.
  - `ip_address` is captured for abuse detection; treated as PII and never
    returned in any response. See models/tables.py::Lead for retention notes.

Rate limiting:
  - A minimal in-process per-IP throttle (`_IPRateLimiter`, 5/60s) runs in
    front of every request. This is defense-in-depth; it is per-process and
    does NOT survive restarts. Production deployments MUST add either
    slowapi or an upstream nginx `limit_req` rule, ideally both.

Open SECURITY follow-ups (tracked, not blocking ship of this file):
  - Global CORS in main.py is `allow_origins=["*"]`; tighten to the marketing
    + dashboard origins.
  - No captcha / Turnstile token validated yet — sophisticated bots that
    read the form will bypass the honeypot.
  - Retention policy: leads + ip_address/user_agent should age out (suggest
    2-year cap for leads, 90-day cap for IP/UA columns).
  - No unit tests for the honeypot/timing/rate-limit paths.

Note on `from __future__ import annotations`: deliberately NOT used here.
FastAPI's dependency introspection resolves type hints via the function's
`__globals__`, and slowapi's `@limiter.limit(...)` decorator wraps the
endpoint so the resolution lookup runs against slowapi's module globals.
With PEP 563 deferred annotations the request-body class name fails to
resolve and Pydantic raises `PydanticUndefinedAnnotation` at app start.
Plain (eagerly-evaluated) type hints keep the class reference live.
"""
import asyncio
import hashlib
import random
from datetime import datetime, timezone
from uuid import uuid4

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from limiter import limiter
from models.database import get_db
from models.tables import Lead
from services.turnstile import turnstile_enabled, verify_turnstile_token

log = structlog.get_logger(__name__)

router = APIRouter(tags=["leads"])


# ─────────────────────────────────────────────────────────────────────────────
# Defensive helpers
# ─────────────────────────────────────────────────────────────────────────────

def _scrub_for_log(value: str | None) -> str | None:
    """Strip CR/LF from user-supplied strings before structured logging.

    Defense-in-depth against log-injection in case structlog is rendered as
    line-oriented key=value text (which can be spoofed by a bot supplying
    newlines in `email`, `source`, etc.). Structured JSON renderers escape
    these automatically, but we don't depend on the renderer choice here.
    """
    if value is None:
        return None
    return value.replace("\n", " ").replace("\r", " ")[:512]


def _email_hash(email: str) -> str:
    """SHA-256 of the (lowercased) email — safe to log at high volume.

    PII-minimizing alternative to logging raw emails on every success.
    Plaintext email is still kept on warning/error paths where a human
    investigator may need to follow up.
    """
    return hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()[:16]


# Rate limiting is now handled by `slowapi` via the `@limiter.limit(...)`
# decorator on the endpoint below. See `cloud-brain/limiter.py` for the
# limiter configuration (in-memory by default, Redis-backed when
# RATE_LIMIT_STORAGE_URI is set).


# ─────────────────────────────────────────────────────────────────────────────
# Allowed values
# ─────────────────────────────────────────────────────────────────────────────

# Org-size bucket labels accepted from the marketing form. We validate manually
# (rather than via Literal) so the API still returns a clean 422 and we can log
# unexpected values for analytics without breaking deployment when the form adds
# a new bucket.
_ALLOWED_SIZES: frozenset[str] = frozenset({
    "Just me",
    "2–10",
    "11–50",
    "51–200",
    "201–1,000",
    "1,000+",
})


# ─────────────────────────────────────────────────────────────────────────────
# Request / Response models
# ─────────────────────────────────────────────────────────────────────────────

class LeadCreate(BaseModel):
    """Lead-capture submission payload.

    All optional fields are accepted as None or omitted; strings are trimmed
    of surrounding whitespace before storage. The `website` field is a honeypot:
    bots tend to fill every field on a form, so any non-empty value triggers a
    silent drop (response looks successful, but nothing is persisted).
    """
    # Reject extra fields with a 422 — clearer client feedback than silently
    # dropping, and prevents drift between FE form fields and BE expectations.
    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    name: str | None = Field(default=None, max_length=200)
    company: str | None = Field(default=None, max_length=200)
    size: str | None = Field(default=None, max_length=32)
    source: str = Field(default="sample-report-gate", max_length=64)
    message: str | None = Field(default=None, max_length=4000)
    # Honeypot — must be left empty by real users. Never persisted.
    website: str | None = Field(default=None, max_length=500)
    # Cloudflare Turnstile token (anti-bot). When a TURNSTILE_SECRET_KEY is
    # configured the endpoint requires this and verifies it server-side.
    # When unconfigured, the field is accepted but ignored. Length-capped
    # liberally — current Turnstile tokens are ~1.5 KB but the format is
    # not contractually fixed.
    turnstile_token: str | None = Field(default=None, max_length=4000)

    @field_validator("name", "company", "size", "message", mode="before")
    @classmethod
    def _strip_optional_strings(cls, v: object) -> object:
        # For optional string fields: strip surrounding whitespace and treat
        # empty-after-strip as None so we don't store useless empty rows.
        if isinstance(v, str):
            stripped = v.strip()
            return stripped or None
        return v

    @field_validator("source", mode="before")
    @classmethod
    def _strip_source(cls, v: object) -> object:
        # `source` is non-optional with a default — strip whitespace but fall
        # back to the default when the client passes an empty / blank string.
        if isinstance(v, str):
            stripped = v.strip()
            return stripped or "sample-report-gate"
        return v

    @field_validator("website", mode="before")
    @classmethod
    def _strip_honeypot(cls, v: object) -> object:
        # Strip whitespace; treat all-whitespace as None so a stray space from
        # autofill doesn't accidentally flag a human.
        if isinstance(v, str):
            return v.strip() or None
        return v

    @field_validator("size", mode="after")
    @classmethod
    def _validate_size(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if v not in _ALLOWED_SIZES:
            raise ValueError(
                f"size must be one of {sorted(_ALLOWED_SIZES)} or null"
            )
        return v

    @field_validator("email", mode="after")
    @classmethod
    def _check_email_length(cls, v: str) -> str:
        # RFC 5321 caps a forward-path address at 256 chars; the DB column is
        # 320 to be safe. Pydantic's EmailStr validates format only, not length,
        # so without this an attacker can submit a 10 KB email and the column
        # truncation will throw at the DB layer. Reject at the edge with 422.
        if len(v) > 320:
            raise ValueError("email must be 320 characters or fewer")
        return v


class LeadResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: str
    email: str
    created_at: datetime


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _extract_ip(request: Request) -> str | None:
    """Return the best-guess client IP.

    Prefers the first IP in `X-Forwarded-For` (when behind a reverse proxy
    such as the Cloud Brain's nginx / ALB), falling back to the direct
    socket peer. Capped to 64 chars to comfortably fit IPv6 + zone-id.
    """
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        # XFF is a comma-separated list; first entry is the original client.
        first = xff.split(",", 1)[0].strip()
        if first:
            return first[:64]
    if request.client and request.client.host:
        return request.client.host[:64]
    return None


def _extract_user_agent(request: Request) -> str | None:
    ua = request.headers.get("user-agent")
    if not ua:
        return None
    return ua[:500]


# ─────────────────────────────────────────────────────────────────────────────
# POST /leads
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/leads",
    response_model=LeadResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Submit a marketing lead",
)
# 5 submissions per minute per client IP. The key function honours
# X-Forwarded-For (see limiter.py). For deployments behind multiple
# instances, set RATE_LIMIT_STORAGE_URI=redis://... so the counter is shared.
@limiter.limit("5/minute")
async def create_lead(
    request: Request,
    lead: LeadCreate,
    db: AsyncSession = Depends(get_db),
) -> LeadResponse:
    """Receive a lead-capture submission from the public marketing site.

    Returns 201 with the persisted row's id, email, and timestamp. Honeypot
    triggers return a 201-shaped response without persisting. Transient DB
    failures return 503 so the front-end's local-storage fallback queue can
    retry later.
    """
    # Rate limit is enforced by the @limiter.limit decorator above; slowapi
    # raises RateLimitExceeded (→ 429) before this body runs.
    ip_address = _extract_ip(request)
    user_agent = _extract_user_agent(request)

    # Cloudflare Turnstile — only enforced when a secret is configured.
    # Verified BEFORE the honeypot so we don't burn a fake-success response
    # on a request that already failed the captcha (small but real signal
    # back to the bot operator). Fail-closed: any error => 400.
    if await turnstile_enabled():
        ok = await verify_turnstile_token(lead.turnstile_token, remote_ip=ip_address)
        if not ok:
            log.warning(
                "Turnstile verification failed",
                source=_scrub_for_log(lead.source),
                ip=ip_address,
            )
            # Neutral error — don't tell the caller which signal rejected
            # them. Same shape as other validation failures.
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Could not verify request — please refresh and try again",
            )

    # Honeypot — bots fill every visible-looking input. Real users never
    # submit a non-empty `website` value (the form hides it via CSS).
    if lead.website:
        log.warning(
            "Honeypot triggered",
            email=_scrub_for_log(lead.email),
            source=_scrub_for_log(lead.source),
            ip=ip_address,
        )
        # Match the real-path timing envelope so bots can't detect the
        # honeypot via response latency:
        #   1. A short randomised jitter (1–5 ms) absorbs measurement noise.
        #   2. A trivial DB round-trip mimics the real flush/refresh cost.
        # We deliberately ignore failures here — the response must succeed.
        await asyncio.sleep(random.uniform(0.001, 0.005))
        try:
            await db.execute(text("SELECT 1"))
        except SQLAlchemyError:
            pass
        # Return a response that LOOKS like success so the bot doesn't retry
        # with a different fingerprint. The id is a fake UUID and never persists.
        # tz-aware UTC to match the real `created_at` column type and avoid
        # the naive-vs-aware oracle a bot could JSON-parse to detect.
        return LeadResponse(
            id=str(uuid4()),
            email=lead.email,
            created_at=datetime.now(timezone.utc),
        )

    row = Lead(
        email=lead.email,
        name=lead.name,
        company=lead.company,
        size=lead.size,
        source=lead.source,
        message=lead.message,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    try:
        db.add(row)
        # flush() to populate the server defaults (id, created_at) without
        # committing — get_db() commits on successful yield-return.
        await db.flush()
        await db.refresh(row)
    except SQLAlchemyError as exc:
        # Transient DB issue — return 503 so the FE can decide to retry or
        # rely on its localStorage queue. We deliberately do NOT echo the
        # exception detail to the client (could leak schema info).
        # Error path keeps full plaintext email + IP for ops follow-up.
        log.error(
            "Lead persistence failed",
            error=str(exc),
            email=_scrub_for_log(lead.email),
            source=_scrub_for_log(lead.source),
            ip=ip_address,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Lead capture temporarily unavailable — please retry shortly",
        ) from exc

    # Success path runs on every legitimate submission. To minimise PII volume
    # in long-retention log stores:
    #   - log a sha256-truncated email hash instead of plaintext
    #   - omit the IP (it lives on the row for ops; no need to duplicate)
    # Investigators with DB access can correlate the row's id back to email/IP.
    log.info(
        "Lead captured",
        lead_id=row.id,
        email_hash=_email_hash(lead.email),
        source=_scrub_for_log(lead.source),
        company=_scrub_for_log(lead.company),
    )

    return LeadResponse.model_validate(row)
