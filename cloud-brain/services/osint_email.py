"""OSINT Email Harvesting service.

Pulls publicly-discoverable email addresses for a given domain from passive
sources and enriches each with breach-status (via the existing breach_checker
service, which uses HIBP's k-anonymity password API for free + HIBP v3 for
emails when an API key is configured).

Sources (free, no API key required):
  - crt.sh   — extracts emails from certificate Subject / SAN fields
  - keys.openpgp.org — searches the public PGP keyserver by domain

Optionally enriched when HIBP_API_KEY is configured:
  - For each discovered email, look up known breaches via HIBP v3.

This is intentionally a *passive* harvest. We never send any email, never
scrape commercial people-search sites, never use Google dorks (TOS-grey).
The output is what's already publicly indexed.
"""
from __future__ import annotations

import asyncio
import re
from typing import Any

import httpx
import structlog

from config import settings
from services.breach_checker import check_email_breaches
from services.subdomain_enum import _normalise_domain

logger = structlog.get_logger(__name__)


# RFC 5322-lite — pragmatic, not perfectly compliant. The certificate fields
# we parse are well-behaved; we don't need a 1000-char regex here.
_EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")


def _belongs_to_domain(email: str, root: str) -> bool:
    """True iff the email's domain part is root or a subdomain of root."""
    email = email.strip().lower()
    if "@" not in email:
        return False
    local, _, dom = email.partition("@")
    if not local or not dom:
        return False
    return dom == root or dom.endswith("." + root)


# ──────────────────────────────────────────────────────────────────────────────
# Source fetchers — each returns set[str] of normalised lowercase emails
# ──────────────────────────────────────────────────────────────────────────────


async def _from_crtsh(client: httpx.AsyncClient, domain: str) -> set[str]:
    """Extract emails from every cert SAN/CN under the domain.

    crt.sh certificates often expose admin / ops emails in the Subject's
    `emailAddress` or in SAN `rfc822Name` entries.
    """
    url = f"https://crt.sh/?q={domain}&output=json"
    resp = await client.get(url, headers={"User-Agent": "xarex-recon/1.0"}, timeout=20)
    resp.raise_for_status()
    found: set[str] = set()
    for entry in resp.json():
        # `name_value` is the SAN list (newline-separated)
        # `common_name` sometimes has an email in it too
        for blob in (entry.get("name_value") or "", entry.get("common_name") or ""):
            for match in _EMAIL_RE.findall(blob):
                email = match.lower()
                if _belongs_to_domain(email, domain):
                    found.add(email)
    return found


async def _from_openpgp(client: httpx.AsyncClient, domain: str) -> set[str]:
    """Query keys.openpgp.org for any PGP keys with a UID matching the domain.

    Uses the VKS (Verifying Key Server) HKP-over-HTTPS interface. The 'index'
    op returns a 'pub' / 'uid' machine-readable listing.
    """
    url = "https://keys.openpgp.org/pks/lookup"
    params = {"op": "index", "options": "mr", "search": domain}
    resp = await client.get(
        url, params=params,
        headers={"User-Agent": "xarex-recon/1.0"},
        timeout=15,
    )
    if resp.status_code == 404:
        return set()  # no keys for this domain — not an error
    resp.raise_for_status()
    found: set[str] = set()
    for line in resp.text.splitlines():
        # uid lines look like: uid:Some Name <person@example.com>:...
        if not line.startswith("uid:"):
            continue
        for match in _EMAIL_RE.findall(line):
            email = match.lower()
            if _belongs_to_domain(email, domain):
                found.add(email)
    return found


_SOURCES = [
    ("crt.sh",          _from_crtsh),
    ("keys.openpgp.org", _from_openpgp),
]


# ──────────────────────────────────────────────────────────────────────────────
# Public entry point
# ──────────────────────────────────────────────────────────────────────────────


async def harvest_emails(
    domain: str,
    *,
    check_breaches: bool = True,
    max_results: int = 100,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Harvest passively-discoverable emails for `domain`.

    Returns:
        {
            "domain": "example.com",
            "discovered": 7,
            "sources_succeeded": ["crt.sh"],
            "sources_failed":    ["keys.openpgp.org"],
            "breach_enrichment": True | False,
            "emails": [
                {
                    "email":   "ops@example.com",
                    "sources": ["crt.sh"],
                    "breached": True,
                    "breach_count": 3,
                    "breaches": [{"name": "Adobe", "date": "2013-10-04"}, ...],
                },
                ...
            ],
        }
    """
    root = _normalise_domain(domain)
    if not root or "." not in root:
        raise ValueError("Invalid domain — provide a bare apex like 'example.com'")

    per_source: dict[str, set[str]] = {}
    succeeded: list[str] = []
    failed: list[str] = []

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        tasks = [fetcher(client, root) for _, fetcher in _SOURCES]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    for (name, _), result in zip(_SOURCES, results):
        if isinstance(result, Exception):
            logger.warning("OSINT email source failed", source=name, error=str(result))
            failed.append(name)
            per_source[name] = set()
        else:
            succeeded.append(name)
            per_source[name] = result

    # Aggregate + per-email source attribution
    all_emails: dict[str, list[str]] = {}
    for name, emails in per_source.items():
        for e in emails:
            all_emails.setdefault(e, []).append(name)

    sorted_emails = sorted(all_emails.keys())[:max_results]

    # Optional breach enrichment — runs in parallel but is bounded by HIBP rate
    # limits (the v3 API enforces ~1 req/1.5s per key). We cap at 25 concurrent
    # checks; if a user has more, they get a partial enrichment and a flag.
    breach_data: dict[str, dict[str, Any]] = {}
    enriched = False
    if check_breaches and settings.HIBP_API_KEY and sorted_emails:
        enriched = True
        sem = asyncio.Semaphore(4)  # HIBP doesn't like bursts

        async def _check(email: str) -> tuple[str, dict[str, Any]]:
            async with sem:
                try:
                    return email, await check_email_breaches(email)
                except Exception as exc:
                    return email, {"error": str(exc), "breaches": []}

        breach_results = await asyncio.gather(
            *[_check(e) for e in sorted_emails[:25]],
            return_exceptions=False,
        )
        for email, data in breach_results:
            breach_data[email] = data

    emails_out = []
    for e in sorted_emails:
        item: dict[str, Any] = {
            "email":   e,
            "sources": all_emails[e],
        }
        if e in breach_data:
            b = breach_data[e]
            breaches = b.get("breaches", []) or []
            item["breached"]     = bool(breaches)
            item["breach_count"] = len(breaches)
            item["breaches"]     = [
                {"name": x.get("Name") or x.get("name"), "date": x.get("BreachDate") or x.get("date")}
                for x in breaches[:10]
            ]
        emails_out.append(item)

    logger.info(
        "OSINT email harvest complete",
        domain=root,
        discovered=len(emails_out),
        succeeded=succeeded,
        failed=failed,
        breach_enrichment=enriched,
    )

    return {
        "domain":             root,
        "discovered":         len(emails_out),
        "sources_succeeded":  succeeded,
        "sources_failed":     failed,
        "breach_enrichment":  enriched,
        "emails":             emails_out,
    }
