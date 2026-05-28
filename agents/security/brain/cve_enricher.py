"""CVE enrichment using the NVD API with EPSS scores."""
import httpx
import json
from typing import Optional


NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API = "https://api.first.org/data/v1/epss"


def fetch_cve(cve_id: str) -> Optional[dict]:
    try:
        resp = httpx.get(f"{NVD_API}?cveId={cve_id}", timeout=10)
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None
        cve = vulns[0]["cve"]
        descriptions = cve.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description")
        metrics = cve.get("metrics", {})
        cvss_score = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                cvss_score = metrics[key][0]["cvssData"].get("baseScore")
                break
        return {"id": cve_id, "description": desc, "cvss_score": cvss_score}
    except Exception:
        return {"id": cve_id, "description": "Lookup failed", "cvss_score": None}


def fetch_epss_scores(cve_ids: list[str]) -> dict[str, float]:
    try:
        ids_param = ",".join(cve_ids)
        resp = httpx.get(f"{EPSS_API}?cve={ids_param}", timeout=10)
        data = resp.json()
        return {item["cve"]: float(item["epss"]) for item in data.get("data", [])}
    except Exception:
        return {}


def enrich_cves_handler(cve_ids: list[str]) -> str:
    enriched = []
    epss_scores = fetch_epss_scores(cve_ids)
    for cve_id in cve_ids:
        info = fetch_cve(cve_id) or {"id": cve_id}
        info["epss_score"] = epss_scores.get(cve_id, 0.0)
        info["priority"] = _priority(info.get("cvss_score"), info["epss_score"])
        enriched.append(info)
    enriched.sort(key=lambda x: x.get("cvss_score") or 0, reverse=True)
    return json.dumps(enriched)


def _priority(cvss: Optional[float], epss: float) -> str:
    if cvss is None:
        return "info"
    if cvss >= 9.0 or epss >= 0.5:
        return "critical"
    if cvss >= 7.0 or epss >= 0.2:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"
