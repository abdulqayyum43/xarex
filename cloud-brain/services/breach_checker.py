"""Breach Monitor service — checks emails against HaveIBeenPwned and local logic.

Password checks use the free k-anonymity range API (no key needed).
Email/account checks use the HIBP v3 API (requires HIBP_API_KEY in .env).
If no key is configured the service returns a graceful "not configured" result.
"""
from __future__ import annotations

import hashlib
import asyncio
from datetime import datetime, timezone
from typing import Any

import httpx
import structlog

from config import settings

logger = structlog.get_logger(__name__)

_HIBP_HEADERS = {
    "hibp-api-key": settings.HIBP_API_KEY,
    "user-agent":   "Xarex-Security-Platform/1.0",
}

# ---------------------------------------------------------------------------
# Password check — 100% free, k-anonymity (SHA-1 prefix)
# ---------------------------------------------------------------------------

async def check_password_pwned(password: str) -> dict[str, Any]:
    """Check if a password appears in breach databases using k-anonymity.

    Never sends the full password — only the first 5 hex chars of its SHA-1.
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        async with httpx.AsyncClient(timeout=8) as client:
            resp = await client.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                headers={"Add-Padding": "true"},
            )
            resp.raise_for_status()
    except Exception as exc:
        logger.warning("HIBP password API error", error=str(exc))
        return {"pwned": False, "count": 0, "error": str(exc)}

    for line in resp.text.splitlines():
        parts = line.split(":")
        if len(parts) == 2 and parts[0] == suffix:
            count = int(parts[1].strip())
            return {"pwned": True, "count": count}

    return {"pwned": False, "count": 0}


# ---------------------------------------------------------------------------
# Email / account breach check — requires HIBP_API_KEY
# ---------------------------------------------------------------------------

async def check_email_breaches(email: str) -> dict[str, Any]:
    """Return all known breaches for an email address via HIBP v3."""
    if not settings.HIBP_API_KEY:
        return {
            "configured": False,
            "breaches": [],
            "message": "HIBP_API_KEY not set — add it to .env to enable email breach checks",
        }

    url = f"{settings.HIBP_API_URL}/breachedaccount/{email}"
    params = {"truncateResponse": "false", "includeUnverified": "true"}

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(url, headers=_HIBP_HEADERS, params=params)

            if resp.status_code == 404:
                return {"configured": True, "breaches": [], "clean": True}

            if resp.status_code == 401:
                return {"configured": False, "breaches": [], "message": "Invalid HIBP API key"}

            if resp.status_code == 429:
                retry = int(resp.headers.get("retry-after", 5))
                await asyncio.sleep(retry)
                resp = await client.get(url, headers=_HIBP_HEADERS, params=params)

            resp.raise_for_status()
            breaches = resp.json()
            return {"configured": True, "breaches": breaches, "clean": False}

    except httpx.HTTPStatusError as exc:
        logger.warning("HIBP account API error", email=email, status=exc.response.status_code)
        return {"configured": True, "breaches": [], "error": str(exc)}
    except Exception as exc:
        logger.warning("HIBP account API error", email=email, error=str(exc))
        return {"configured": True, "breaches": [], "error": str(exc)}


async def get_all_breaches() -> list[dict]:
    """Fetch the full HIBP breach catalogue (for UI enrichment)."""
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"{settings.HIBP_API_URL}/breaches",
                headers=_HIBP_HEADERS,
            )
            resp.raise_for_status()
            return resp.json()
    except Exception as exc:
        logger.warning("HIBP catalogue fetch failed", error=str(exc))
        return []
