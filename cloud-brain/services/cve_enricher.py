"""CVE Enricher — fetches CVSS scores and metadata from the NVD NIST API.

Enriches findings with:
  - CVSS v3.1 base score + severity rating
  - CVSS v3.1 vector string
  - CWE IDs
  - References
  - Description (official NVD text)
  - EPSS score (Exploit Prediction Scoring System) if available

NVD API is free and requires no key for basic queries (rate-limited to 5 req/30s).
"""
from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx
import structlog

logger = structlog.get_logger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API_BASE = "https://api.first.org/data/v1/epss"

# Simple in-process cache
_cache: dict[str, dict[str, Any]] = {}
_cache_timestamps: dict[str, float] = {}
CACHE_TTL = 86400  # 24 hours

# NVD rate limit: 5 requests per 30 seconds without API key
_last_nvd_call = 0.0
_NVD_MIN_INTERVAL = 6.5  # seconds between calls


class CVEEnricher:
    """Fetches and caches CVE metadata from NVD and EPSS."""

    def __init__(self, nvd_api_key: str | None = None) -> None:
        self._nvd_key = nvd_api_key
        self._client = httpx.AsyncClient(timeout=15.0)

    async def close(self) -> None:
        await self._client.aclose()

    # ──────────────────────────────────────────────
    #  Public API
    # ──────────────────────────────────────────────

    async def enrich(self, cve_id: str) -> dict[str, Any]:
        """
        Return enrichment data for a CVE ID.
        Uses cache; fetches from NVD on miss.
        """
        if not cve_id or not cve_id.upper().startswith("CVE-"):
            return {}

        cve_id = cve_id.upper().strip()

        # Cache hit
        if self._cache_valid(cve_id):
            return _cache[cve_id]

        data = await self._fetch_nvd(cve_id)

        # Also fetch EPSS score
        epss = await self._fetch_epss(cve_id)
        if epss:
            data["epss_score"] = epss.get("epss")
            data["epss_percentile"] = epss.get("percentile")

        _cache[cve_id] = data
        _cache_timestamps[cve_id] = time.time()
        return data

    async def enrich_batch(self, cve_ids: list[str]) -> dict[str, dict[str, Any]]:
        """Enrich a batch of CVE IDs respecting rate limits."""
        results: dict[str, dict[str, Any]] = {}
        for cve_id in cve_ids:
            try:
                results[cve_id] = await self.enrich(cve_id)
            except Exception as exc:
                logger.warning("CVE enrichment failed", cve_id=cve_id, error=str(exc))
                results[cve_id] = {}
        return results

    # ──────────────────────────────────────────────
    #  NVD Fetch
    # ──────────────────────────────────────────────

    async def _fetch_nvd(self, cve_id: str) -> dict[str, Any]:
        global _last_nvd_call

        # Rate limiting
        elapsed = time.time() - _last_nvd_call
        if elapsed < _NVD_MIN_INTERVAL:
            await asyncio.sleep(_NVD_MIN_INTERVAL - elapsed)

        _last_nvd_call = time.time()

        headers: dict[str, str] = {}
        if self._nvd_key:
            headers["apiKey"] = self._nvd_key

        try:
            resp = await self._client.get(
                NVD_API_BASE,
                params={"cveId": cve_id},
                headers=headers,
            )
            resp.raise_for_status()
            raw = resp.json()
        except httpx.HTTPStatusError as exc:
            logger.warning("NVD API error", cve_id=cve_id, status=exc.response.status_code)
            return {"cve_id": cve_id, "error": f"NVD HTTP {exc.response.status_code}"}
        except Exception as exc:
            logger.warning("NVD fetch failed", cve_id=cve_id, error=str(exc))
            return {"cve_id": cve_id, "error": str(exc)}

        items = raw.get("vulnerabilities", [])
        if not items:
            return {"cve_id": cve_id, "not_found": True}

        cve_data = items[0].get("cve", {})
        return self._parse_nvd_cve(cve_id, cve_data)

    def _parse_nvd_cve(self, cve_id: str, cve_data: dict) -> dict[str, Any]:
        result: dict[str, Any] = {"cve_id": cve_id}

        # Description (English preferred)
        descriptions = cve_data.get("descriptions", [])
        for d in descriptions:
            if d.get("lang") == "en":
                result["nvd_description"] = d.get("value", "")[:500]
                break

        # CVSS v3.1
        metrics = cve_data.get("metrics", {})
        cvss31_list = metrics.get("cvssMetricV31", [])
        if cvss31_list:
            cvss31 = cvss31_list[0].get("cvssData", {})
            result["cvss_score"] = cvss31.get("baseScore")
            result["cvss_severity"] = cvss31.get("baseSeverity")
            result["cvss_vector"] = cvss31.get("vectorString")
            result["cvss_version"] = "3.1"
            # Component scores
            result["cvss_exploitability"] = cvss31.get("exploitabilityScore")
            result["cvss_impact"] = cvss31.get("impactScore")
        else:
            # Fall back to v3.0
            cvss30_list = metrics.get("cvssMetricV30", [])
            if cvss30_list:
                cvss30 = cvss30_list[0].get("cvssData", {})
                result["cvss_score"] = cvss30.get("baseScore")
                result["cvss_severity"] = cvss30.get("baseSeverity")
                result["cvss_vector"] = cvss30.get("vectorString")
                result["cvss_version"] = "3.0"
            else:
                # v2 fallback
                cvss2_list = metrics.get("cvssMetricV2", [])
                if cvss2_list:
                    cvss2 = cvss2_list[0].get("cvssData", {})
                    result["cvss_score"] = cvss2.get("baseScore")
                    result["cvss_severity"] = cvss2_list[0].get("baseSeverity")
                    result["cvss_version"] = "2.0"

        # CWE IDs
        weaknesses = cve_data.get("weaknesses", [])
        cwes = []
        for w in weaknesses:
            for desc in w.get("description", []):
                val = desc.get("value", "")
                if val and val.startswith("CWE-"):
                    cwes.append(val)
        result["cwe_ids"] = list(set(cwes))

        # Published / modified dates
        result["published"] = cve_data.get("published", "")[:10]
        result["last_modified"] = cve_data.get("lastModified", "")[:10]

        # Top 5 references
        refs = cve_data.get("references", [])
        result["references"] = [r.get("url") for r in refs[:5] if r.get("url")]

        return result

    async def _fetch_epss(self, cve_id: str) -> dict[str, Any]:
        """Fetch EPSS score from FIRST.org API."""
        try:
            resp = await self._client.get(
                EPSS_API_BASE,
                params={"cve": cve_id},
                timeout=8.0,
            )
            resp.raise_for_status()
            data = resp.json()
            items = data.get("data", [])
            if items:
                return {"epss": float(items[0].get("epss", 0)), "percentile": float(items[0].get("percentile", 0))}
        except Exception:
            pass
        return {}

    # ──────────────────────────────────────────────
    #  Cache helpers
    # ──────────────────────────────────────────────

    def _cache_valid(self, cve_id: str) -> bool:
        if cve_id not in _cache:
            return False
        age = time.time() - _cache_timestamps.get(cve_id, 0)
        return age < CACHE_TTL


# Module-level singleton
_enricher: CVEEnricher | None = None


def get_enricher() -> CVEEnricher:
    global _enricher
    if _enricher is None:
        from config import settings
        _enricher = CVEEnricher(nvd_api_key=getattr(settings, "NVD_API_KEY", None))
    return _enricher
