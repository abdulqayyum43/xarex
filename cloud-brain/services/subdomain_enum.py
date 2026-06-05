"""Subdomain Enumeration service.

Fans out to multiple public sources in parallel, dedups by hostname, and
optionally resolves each result to an IP via Cloudflare's DNS-over-HTTPS.

Sources (all free, no API key required):
  - crt.sh  — Certificate Transparency log search
  - HackerTarget — free passive DNS API
  - AlienVault OTX — passive DNS feed

This is intentionally light-touch and read-only. We don't run active DNS
bruteforce — that would generate per-customer-paid noise + can get the
Xarex IP blocklisted. All sources hit are passive aggregators.

Returns at most `max_results` subdomains per scan to bound runtime.
"""
from __future__ import annotations

import asyncio
import re
from typing import Any

import httpx
import structlog

logger = structlog.get_logger(__name__)


# RFC 1035 hostname pattern, anchored — keeps us from picking up garbage from
# certificate CN / SAN fields (wildcards, IPs, comma-separated lists, etc.).
_HOSTNAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")


def _is_valid_subdomain(host: str, root_domain: str) -> bool:
    host = host.strip().lower().rstrip(".")
    if not host or "*" in host or " " in host:
        return False
    if not _HOSTNAME_RE.match(host):
        return False
    # Must end with .root_domain and not BE root_domain
    suffix = "." + root_domain.lower()
    return host.endswith(suffix) and host != root_domain.lower()


def _normalise_domain(domain: str) -> str:
    """Strip scheme/path, leave bare apex like 'example.com'."""
    d = (domain or "").strip().lower()
    d = re.sub(r"^https?://", "", d)
    d = d.split("/")[0].split(":")[0]
    d = d.lstrip("*.").rstrip(".")
    return d


# ──────────────────────────────────────────────────────────────────────────────
# Source fetchers — each returns set[str] of bare hostnames (no protocol/path).
# Exceptions are caught at the caller; a single failed source must not kill the
# whole enumeration.
# ──────────────────────────────────────────────────────────────────────────────


async def _from_crtsh(client: httpx.AsyncClient, domain: str) -> set[str]:
    """crt.sh — every cert ever issued under the domain, dedup'd."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    resp = await client.get(url, headers={"User-Agent": "xarex-recon/1.0"})
    resp.raise_for_status()
    found: set[str] = set()
    for entry in resp.json():
        # `name_value` is newline-separated list of SANs from the cert
        for name in (entry.get("name_value") or "").split("\n"):
            if _is_valid_subdomain(name, domain):
                found.add(name.strip().lower())
    return found


async def _from_hackertarget(client: httpx.AsyncClient, domain: str) -> set[str]:
    """HackerTarget — free 50 reqs/day, returns 'host,ip' per line."""
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    resp = await client.get(url, headers={"User-Agent": "xarex-recon/1.0"})
    if resp.status_code != 200:
        return set()
    body = resp.text.strip()
    # API returns 'error' or 'API count exceeded' as the whole body on failure
    if not body or body.startswith("error") or "exceeded" in body.lower():
        return set()
    found: set[str] = set()
    for line in body.splitlines():
        host = line.split(",")[0].strip()
        if _is_valid_subdomain(host, domain):
            found.add(host.lower())
    return found


async def _from_otx(client: httpx.AsyncClient, domain: str) -> set[str]:
    """AlienVault OTX passive DNS — no API key required."""
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    resp = await client.get(url, headers={"User-Agent": "xarex-recon/1.0"})
    resp.raise_for_status()
    data = resp.json()
    found: set[str] = set()
    for record in data.get("passive_dns", []):
        host = (record.get("hostname") or "").strip().lower()
        if _is_valid_subdomain(host, domain):
            found.add(host)
    return found


_SOURCES = [
    ("crt.sh",       _from_crtsh),
    ("hackertarget", _from_hackertarget),
    ("otx",          _from_otx),
]


# ──────────────────────────────────────────────────────────────────────────────
# DNS resolution via Cloudflare DoH (no extra dep beyond httpx)
# ──────────────────────────────────────────────────────────────────────────────


async def _resolve_a(client: httpx.AsyncClient, host: str) -> str | None:
    """Return the first A-record IP for host, or None if NXDOMAIN / no record."""
    try:
        resp = await client.get(
            "https://cloudflare-dns.com/dns-query",
            params={"name": host, "type": "A"},
            headers={"Accept": "application/dns-json", "User-Agent": "xarex-recon/1.0"},
            timeout=4.0,
        )
        resp.raise_for_status()
        for ans in resp.json().get("Answer", []):
            if ans.get("type") == 1:  # A record
                return ans.get("data")
    except Exception:
        return None
    return None


# ──────────────────────────────────────────────────────────────────────────────
# Public entry point
# ──────────────────────────────────────────────────────────────────────────────


async def enumerate_subdomains(
    domain: str,
    *,
    resolve: bool = True,
    max_results: int = 500,
    timeout: float = 25.0,
) -> dict[str, Any]:
    """Enumerate subdomains for `domain` from public sources.

    Returns:
        {
            "domain": "example.com",
            "discovered": 42,
            "sources_succeeded": ["crt.sh", "otx"],
            "sources_failed":    ["hackertarget"],
            "subdomains": [
                {"host": "api.example.com", "sources": ["crt.sh"], "ip": "1.2.3.4"},
                ...
            ],
        }
    """
    root = _normalise_domain(domain)
    if not root or "." not in root:
        raise ValueError("Invalid domain — provide a bare apex like 'example.com'")

    # Per-source result map so we can attribute each subdomain to its sources
    per_source: dict[str, set[str]] = {}
    succeeded: list[str] = []
    failed: list[str] = []

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        tasks = [fetcher(client, root) for _, fetcher in _SOURCES]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for (name, _), result in zip(_SOURCES, results):
            if isinstance(result, Exception):
                logger.warning("Subdomain source failed", source=name, error=str(result))
                failed.append(name)
                per_source[name] = set()
            else:
                succeeded.append(name)
                per_source[name] = result

        # Aggregate, dedup, cap
        all_hosts: dict[str, list[str]] = {}
        for name, hosts in per_source.items():
            for h in hosts:
                all_hosts.setdefault(h, []).append(name)

        sorted_hosts = sorted(all_hosts.keys())[:max_results]

        # Resolve in parallel if requested
        ips: dict[str, str | None] = {}
        if resolve and sorted_hosts:
            resolve_tasks = [_resolve_a(client, h) for h in sorted_hosts]
            resolved = await asyncio.gather(*resolve_tasks, return_exceptions=True)
            for h, ip in zip(sorted_hosts, resolved):
                ips[h] = ip if isinstance(ip, str) else None

    subdomains = [
        {
            "host":    h,
            "sources": all_hosts[h],
            "ip":      ips.get(h),
        }
        for h in sorted_hosts
    ]

    logger.info(
        "Subdomain enum complete",
        domain=root,
        discovered=len(subdomains),
        succeeded=succeeded,
        failed=failed,
    )

    return {
        "domain":            root,
        "discovered":        len(subdomains),
        "sources_succeeded": succeeded,
        "sources_failed":    failed,
        "subdomains":        subdomains,
    }
