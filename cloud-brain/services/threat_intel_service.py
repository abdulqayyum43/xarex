"""Threat Intelligence service — IP/domain reputation via AbuseIPDB, VirusTotal, and ipapi.co."""
from __future__ import annotations

import asyncio
import ipaddress
import time
from typing import Any

import httpx
import structlog

from config import settings

logger = structlog.get_logger(__name__)

# In-process TTL cache: lookup_key → (result_dict, expires_at_monotonic)
_mem_cache: dict[str, tuple[dict, float]] = {}


def _cache_get(key: str) -> dict | None:
    entry = _mem_cache.get(key)
    if entry and time.monotonic() < entry[1]:
        return entry[0]
    _mem_cache.pop(key, None)
    return None


def _cache_set(key: str, result: dict) -> None:
    _mem_cache[key] = (result, time.monotonic() + settings.THREAT_INTEL_CACHE_TTL)
    if len(_mem_cache) > 2000:
        now = time.monotonic()
        stale = [k for k, v in _mem_cache.items() if v[1] < now]
        for k in stale:
            _mem_cache.pop(k, None)


def _is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved)
    except ValueError:
        return False


async def lookup_ip(ip: str) -> dict[str, Any]:
    """Return combined reputation data for an IP address."""
    cache_key = f"ip:{ip}"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    result: dict[str, Any] = {
        "ip": ip,
        "is_public": _is_public_ip(ip),
        "geo": {},
        "abuse": {},
        "virustotal": {},
        "risk_score": 0,
        "tags": [],
        "cached": False,
    }

    async with httpx.AsyncClient(timeout=10.0) as client:
        tasks = [_geo_lookup(client, ip)]
        if _is_public_ip(ip):
            if settings.ABUSEIPDB_API_KEY:
                tasks.append(_abuseipdb_lookup(client, ip))
            if settings.VIRUSTOTAL_API_KEY:
                tasks.append(_virustotal_ip_lookup(client, ip))

        responses = await asyncio.gather(*tasks, return_exceptions=True)

    for resp in responses:
        if isinstance(resp, Exception):
            logger.warning("Threat intel sub-lookup failed", error=str(resp))
            continue
        result.update(resp)

    # Aggregate risk score (0-100)
    score = 0
    abuse_score = result.get("abuse", {}).get("abuseConfidenceScore", 0)
    vt_malicious = result.get("virustotal", {}).get("malicious", 0)
    score = max(score, abuse_score)
    if vt_malicious > 0:
        score = max(score, min(100, vt_malicious * 15))
    result["risk_score"] = score

    tags: list[str] = []
    if abuse_score >= 80:
        tags.append("high-abuse")
    elif abuse_score >= 30:
        tags.append("reported-abuse")
    if vt_malicious > 0:
        tags.append("malicious")
    if result.get("abuse", {}).get("isTor"):
        tags.append("tor-exit-node")
    result["tags"] = tags

    _cache_set(cache_key, result)
    return result


async def _geo_lookup(client: httpx.AsyncClient, ip: str) -> dict[str, Any]:
    """Free ipapi.co geolocation — no key required."""
    try:
        r = await client.get(f"https://ipapi.co/{ip}/json/")
        if r.status_code == 200:
            data = r.json()
            return {
                "geo": {
                    "country": data.get("country_name", ""),
                    "country_code": data.get("country_code", ""),
                    "region": data.get("region", ""),
                    "city": data.get("city", ""),
                    "org": data.get("org", ""),
                    "asn": data.get("asn", ""),
                    "latitude": data.get("latitude"),
                    "longitude": data.get("longitude"),
                }
            }
    except Exception as exc:
        logger.debug("Geo lookup failed", ip=ip, error=str(exc))
    return {"geo": {}}


async def _abuseipdb_lookup(client: httpx.AsyncClient, ip: str) -> dict[str, Any]:
    try:
        r = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            headers={"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"},
        )
        if r.status_code == 200:
            d = r.json().get("data", {})
            return {
                "abuse": {
                    "abuseConfidenceScore": d.get("abuseConfidenceScore", 0),
                    "totalReports": d.get("totalReports", 0),
                    "numDistinctUsers": d.get("numDistinctUsers", 0),
                    "lastReportedAt": d.get("lastReportedAt"),
                    "isTor": d.get("isTor", False),
                    "usageType": d.get("usageType", ""),
                    "isp": d.get("isp", ""),
                    "domain": d.get("domain", ""),
                    "countryCode": d.get("countryCode", ""),
                }
            }
    except Exception as exc:
        logger.debug("AbuseIPDB lookup failed", ip=ip, error=str(exc))
    return {"abuse": {}}


async def _virustotal_ip_lookup(client: httpx.AsyncClient, ip: str) -> dict[str, Any]:
    try:
        r = await client.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
        )
        if r.status_code == 200:
            stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "virustotal": {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                }
            }
    except Exception as exc:
        logger.debug("VirusTotal lookup failed", ip=ip, error=str(exc))
    return {"virustotal": {}}


async def enrich_scan_findings(scan_id: str, org_id: str, db) -> list[dict[str, Any]]:
    """
    Look up threat intel for every unique public IP in a scan's findings.
    Returns list of {ip, finding_ids, intel} records.
    """
    from sqlalchemy import select
    from models.tables import Finding

    result = await db.execute(
        select(Finding.id, Finding.host)
        .where(Finding.scan_id == scan_id)
    )
    rows = result.all()

    # Group finding IDs by host IP
    ip_findings: dict[str, list[str]] = {}
    for finding_id, host in rows:
        if host and _is_public_ip(host):
            ip_findings.setdefault(host, []).append(finding_id)

    enrichments = []
    for ip, fids in ip_findings.items():
        intel = await lookup_ip(ip)
        enrichments.append({"ip": ip, "finding_ids": fids, "intel": intel})

    return enrichments
