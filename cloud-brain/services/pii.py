"""Xarex — small PII-minimising helpers shared across services.

We log a lot at INFO across billing + leads. Plaintext emails on every
success event accumulate in long-retention log stores and become a real
breach blast-radius problem. This module centralises:

  - `email_hash(email)`: a stable, truncated SHA-256 of the lowercased
    email. Safe to log on INFO/success paths; investigators can rebuild
    the mapping from the row's id when needed.
  - `scrub_for_log(value)`: defense-in-depth against log injection (CR/LF)
    when structlog renders as line-oriented key=value text.

ERROR/WARNING paths intentionally keep the plaintext email — ops needs it
to investigate failures, dunning, abuse, etc.
"""
from __future__ import annotations

import hashlib


def email_hash(email: str) -> str:
    """SHA-256 of the (lowercased, stripped) email, truncated to 16 hex chars.

    Truncation is a deliberate trade-off — full 64-char digests are noisy
    in logs and the 16-char prefix is still collision-resistant for the
    handful of customer emails any single org sees.
    """
    if not email:
        return ""
    return hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()[:16]


def scrub_for_log(value: str | None) -> str | None:
    """Strip CR/LF from user-supplied strings before structured logging."""
    if value is None:
        return None
    return value.replace("\n", " ").replace("\r", " ")[:512]
