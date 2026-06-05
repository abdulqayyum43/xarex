"""Cloudflare Turnstile server-side verification.

Turnstile is a privacy-respecting captcha alternative. Flow:
  1. Browser renders the Turnstile widget using the public site key.
  2. User solves the challenge (often invisible); widget injects a token
     into a hidden form input named `cf-turnstile-response`.
  3. Client posts the token alongside the form data.
  4. Server calls Cloudflare's siteverify endpoint with `secret + token`.
  5. Cloudflare returns `{ success: bool, ... }`. Only proceed if true.

This module is the server side of (4)–(5). It is a no-op when
`settings.TURNSTILE_SECRET_KEY` is empty (dev / pre-launch mode) — callers
should treat `verify_turnstile_token(None)` as success when the secret is
unset.
"""
from __future__ import annotations

import httpx
import structlog

from config import settings

log = structlog.get_logger(__name__)

# Network timeout for the siteverify call. Cloudflare's endpoint is reliably
# fast; >5s usually means we should fail-closed and reject the submission.
_VERIFY_TIMEOUT_S = 5.0


async def turnstile_enabled() -> bool:
    """Return True when a Turnstile secret is configured.

    Centralised so callers don't poke at `settings` directly.
    """
    return bool((settings.TURNSTILE_SECRET_KEY or "").strip())


async def verify_turnstile_token(
    token: str | None,
    remote_ip: str | None = None,
) -> bool:
    """Verify a Turnstile token against Cloudflare.

    Returns True if Turnstile is disabled (no secret set) OR the token is
    valid. Returns False on any failure: missing token, network error,
    Cloudflare-side rejection.

    Never raises — callers map False to a 422 / 400 themselves.
    """
    if not await turnstile_enabled():
        # Dev / pre-launch mode: there's no secret to verify against. We
        # accept the absence of a token as success so the form works during
        # local development. The honeypot + rate limit still apply.
        return True

    if not token or not token.strip():
        log.warning("Turnstile token missing on a request that requires it")
        return False

    payload = {
        "secret": settings.TURNSTILE_SECRET_KEY,
        "response": token.strip(),
    }
    if remote_ip:
        payload["remoteip"] = remote_ip

    try:
        async with httpx.AsyncClient(timeout=_VERIFY_TIMEOUT_S) as client:
            resp = await client.post(settings.TURNSTILE_VERIFY_URL, data=payload)
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPError as exc:
        # Network / 5xx — fail closed (reject the submission). Logged at
        # warning rather than error because Cloudflare hiccups happen and
        # we don't want to page on every retryable failure.
        log.warning("Turnstile verify request failed", error=str(exc))
        return False
    except ValueError as exc:
        # JSON decode error — treat as a verify failure.
        log.warning("Turnstile verify returned non-JSON", error=str(exc))
        return False

    ok = bool(data.get("success"))
    if not ok:
        # `error-codes` is an array per Cloudflare's spec — useful for ops
        # to distinguish "invalid token" from "secret misconfigured".
        log.warning(
            "Turnstile verify rejected",
            error_codes=data.get("error-codes", []),
            hostname=data.get("hostname"),
        )
    return ok
