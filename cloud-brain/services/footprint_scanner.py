"""Digital Footprint Scanner.

Checks publicly accessible data broker sites for personal information exposure.
Uses httpx with realistic browser headers. Returns exposure level per source
and direct opt-out links so the user can remove their data.

This intentionally avoids techniques that would breach ToS in an aggressive way —
it only checks publicly accessible search result pages.
"""
from __future__ import annotations

import asyncio
import re
from typing import Any
from urllib.parse import quote_plus

import httpx
import structlog

from config import settings

logger = structlog.get_logger(__name__)

_HEADERS = {
    "User-Agent":      settings.FOOTPRINT_USER_AGENT,
    "Accept-Language": "en-US,en;q=0.9",
    "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "DNT":             "1",
}

# Each broker: {id, name, check_url, optout_url, exposure_weight}
_BROKERS = [
    {
        "id":      "whitepages",
        "name":    "Whitepages",
        "description": "People search engine with addresses, phone numbers, relatives",
        "check_url":   "https://www.whitepages.com/name/{name_encoded}",
        "optout_url":  "https://www.whitepages.com/suppression-requests",
        "weight":      15,
        "patterns":    [r"premium result", r"age \d+", r"whitepages premium"],
    },
    {
        "id":      "spokeo",
        "name":    "Spokeo",
        "description": "Aggregates social profiles, phone, email, address history",
        "check_url":   "https://www.spokeo.com/{name_slug}",
        "optout_url":  "https://www.spokeo.com/optout",
        "weight":      15,
        "patterns":    [r"results for", r"age \d+", r"spokeo", r"found \d+ result"],
    },
    {
        "id":      "fastpeoplesearch",
        "name":    "FastPeopleSearch",
        "description": "Free people search with address, phone, email",
        "check_url":   "https://www.fastpeoplesearch.com/name/{name_encoded}",
        "optout_url":  "https://www.fastpeoplesearch.com/removal",
        "weight":      10,
        "patterns":    [r"view details", r"age \d+", r"relatives", r"associated phones"],
    },
    {
        "id":      "truepeoplesearch",
        "name":    "TruePeopleSearch",
        "description": "Free people search aggregating public records",
        "check_url":   "https://www.truepeoplesearch.com/results?name={name_encoded}",
        "optout_url":  "https://www.truepeoplesearch.com/removal",
        "weight":      10,
        "patterns":    [r"associated with", r"age \d+", r"related to", r"possible relatives"],
    },
    {
        "id":      "peoplefinder",
        "name":    "PeopleFinder",
        "description": "Background check and people search",
        "check_url":   "https://www.peoplefinder.com/people/{name_slug}/",
        "optout_url":  "https://www.peoplefinder.com/optout.php",
        "weight":      10,
        "patterns":    [r"background check", r"related people", r"found \d+"],
    },
    {
        "id":      "radaris",
        "name":    "Radaris",
        "description": "Personal info, business records, social media aggregator",
        "check_url":   "https://radaris.com/ng/search/name/?ff={first}&fl={last}",
        "optout_url":  "https://radaris.com/control/privacy",
        "weight":      12,
        "patterns":    [r"profile", r"age \d+", r"lives in", r"related to"],
    },
    {
        "id":      "instantcheckmate",
        "name":    "Instant Checkmate",
        "description": "Background reports with criminal, address, social history",
        "check_url":   "https://www.instantcheckmate.com/results/?firstName={first}&lastName={last}",
        "optout_url":  "https://www.instantcheckmate.com/opt-out/",
        "weight":      13,
        "patterns":    [r"background report", r"found \d+ result", r"criminal records"],
    },
    {
        "id":      "beenverified",
        "name":    "BeenVerified",
        "description": "People search with criminal, financial, and social data",
        "check_url":   "https://www.beenverified.com/f/search/person?firstName={first}&lastName={last}",
        "optout_url":  "https://www.beenverified.com/app/optout/search",
        "weight":      15,
        "patterns":    [r"view report", r"found \d+", r"search complete", r"background"],
    },
]


def _name_parts(full_name: str) -> tuple[str, str]:
    parts = full_name.strip().split()
    first = parts[0] if parts else ""
    last  = " ".join(parts[1:]) if len(parts) > 1 else ""
    return first, last


def _build_url(broker: dict, full_name: str, location: str) -> str:
    first, last = _name_parts(full_name)
    slug = re.sub(r"[^a-z0-9]+", "-", full_name.lower()).strip("-")
    encoded = quote_plus(full_name)
    return (
        broker["check_url"]
        .replace("{name_encoded}", encoded)
        .replace("{name_slug}", slug)
        .replace("{first}", quote_plus(first))
        .replace("{last}", quote_plus(last))
    )


async def _check_broker(
    client: httpx.AsyncClient,
    broker: dict,
    full_name: str,
    location: str,
) -> dict[str, Any]:
    url = _build_url(broker, full_name, location)
    result = {
        "id":          broker["id"],
        "name":        broker["name"],
        "description": broker["description"],
        "optout_url":  broker["optout_url"],
        "check_url":   url,
        "exposed":     False,
        "confidence":  "low",
        "snippets":    [],
        "weight":      broker["weight"],
    }

    try:
        resp = await client.get(url, timeout=10, follow_redirects=True)
        html = resp.text.lower()

        matched = []
        for pat in broker["patterns"]:
            m = re.search(pat, html)
            if m:
                # Grab a small snippet around the match
                start = max(0, m.start() - 30)
                end   = min(len(html), m.end() + 60)
                snippet = resp.text[start:end].strip()
                matched.append(snippet)

        if matched:
            result["exposed"]    = True
            result["confidence"] = "high" if len(matched) >= 2 else "medium"
            result["snippets"]   = matched[:2]

    except httpx.TimeoutException:
        result["error"] = "timeout"
    except Exception as exc:
        result["error"] = str(exc)[:80]

    return result


async def run_footprint_scan(
    full_name: str,
    location: str = "",
    email: str = "",
) -> dict[str, Any]:
    """Check all known data brokers for the given name/location.
    Returns exposure score, per-broker results, and opt-out links.
    """
    results = []
    async with httpx.AsyncClient(headers=_HEADERS) as client:
        tasks = [
            _check_broker(client, broker, full_name, location)
            for broker in _BROKERS
        ]
        results = await asyncio.gather(*tasks, return_exceptions=False)

    exposed_brokers = [r for r in results if r.get("exposed")]
    sources_checked = len(results)

    # Weighted exposure score 0-100
    raw_score = sum(r["weight"] for r in exposed_brokers)
    max_possible = sum(b["weight"] for b in _BROKERS)
    exposure_score = min(100, int((raw_score / max_possible) * 100))

    return {
        "full_name":       full_name,
        "location":        location,
        "email":           email,
        "sources_checked": sources_checked,
        "exposures_found": len(exposed_brokers),
        "exposure_score":  exposure_score,
        "exposure_level": (
            "critical" if exposure_score >= 70 else
            "high"     if exposure_score >= 40 else
            "medium"   if exposure_score >= 20 else
            "low"
        ),
        "results": results,
        "optout_guide": [
            {
                "broker":    r["name"],
                "optout_url": r["optout_url"],
                "priority":  r["confidence"],
            }
            for r in exposed_brokers
        ],
    }
