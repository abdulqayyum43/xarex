"""Compliance Reporting — maps scan findings to PCI-DSS, HIPAA, ISO 27001, SOC 2 controls."""
from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import get_org
from models.database import get_db
from models.tables import Finding, Org, Scan

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/compliance", tags=["compliance"])

# ── Control mappings ──────────────────────────────────────────────────────────

# title keywords → list of control IDs per framework
_PCI_DSS: dict[str, list[str]] = {
    "sql injection":           ["6.3.1", "6.4.1"],
    "xss":                     ["6.3.1", "6.4.1"],
    "cross-site scripting":    ["6.3.1", "6.4.1"],
    "open redirect":           ["6.3.1"],
    "default cred":            ["2.1.1", "8.3.6"],
    "default password":        ["2.1.1", "8.3.6"],
    "ssl":                     ["4.2.1", "4.2.2"],
    "tls":                     ["4.2.1", "4.2.2"],
    "weak cipher":             ["4.2.1"],
    "smb relay":               ["1.3.2", "6.4.1"],
    "sensitive file":          ["6.3.1", "6.4.3"],
    "directory traversal":     ["6.3.1", "6.4.1"],
    "admin panel":             ["8.6.1", "8.6.2"],
    "snmp":                    ["2.2.1", "8.6.3"],
    "rdp":                     ["1.3.2", "8.3.2"],
    "open port":               ["1.2.1"],
    "debug":                   ["6.3.1"],
    "backup":                  ["9.5.1"],
    "web app":                 ["6.4.1", "6.4.2"],
}

_HIPAA: dict[str, list[str]] = {
    "sql injection":           ["§164.312(a)(1)", "§164.312(c)(1)"],
    "xss":                     ["§164.312(a)(1)"],
    "cross-site scripting":    ["§164.312(a)(1)"],
    "default cred":            ["§164.308(a)(5)", "§164.312(d)"],
    "default password":        ["§164.308(a)(5)", "§164.312(d)"],
    "ssl":                     ["§164.312(e)(2)(ii)"],
    "tls":                     ["§164.312(e)(2)(ii)"],
    "weak cipher":             ["§164.312(e)(2)(ii)"],
    "sensitive file":          ["§164.308(a)(3)", "§164.312(a)(1)"],
    "backup":                  ["§164.308(a)(7)"],
    "admin panel":             ["§164.308(a)(4)", "§164.312(a)(2)"],
    "rdp":                     ["§164.312(a)(2)(iv)"],
    "audit":                   ["§164.312(b)"],
    "open port":               ["§164.312(a)(1)"],
    "web app":                 ["§164.312(a)(1)", "§164.312(c)(1)"],
}

_ISO27001: dict[str, list[str]] = {
    "sql injection":           ["A.8.28", "A.8.29"],
    "xss":                     ["A.8.28", "A.8.29"],
    "cross-site scripting":    ["A.8.28", "A.8.29"],
    "open redirect":           ["A.8.28"],
    "default cred":            ["A.5.17", "A.8.5"],
    "default password":        ["A.5.17", "A.8.5"],
    "ssl":                     ["A.8.24"],
    "tls":                     ["A.8.24"],
    "weak cipher":             ["A.8.24"],
    "smb relay":               ["A.8.20", "A.8.22"],
    "sensitive file":          ["A.8.3", "A.8.10"],
    "directory traversal":     ["A.8.28"],
    "admin panel":             ["A.8.2", "A.8.3"],
    "snmp":                    ["A.8.20", "A.8.22"],
    "rdp":                     ["A.8.20", "A.8.3"],
    "backup":                  ["A.8.13"],
    "web app":                 ["A.8.28", "A.8.29"],
    "debug":                   ["A.8.28"],
    "open port":               ["A.8.20"],
}

_SOC2: dict[str, list[str]] = {
    "sql injection":           ["CC7.1", "CC8.1"],
    "xss":                     ["CC7.1", "CC8.1"],
    "cross-site scripting":    ["CC7.1", "CC8.1"],
    "default cred":            ["CC6.1", "CC6.2"],
    "default password":        ["CC6.1", "CC6.2"],
    "ssl":                     ["CC6.7"],
    "tls":                     ["CC6.7"],
    "weak cipher":             ["CC6.7"],
    "smb relay":               ["CC6.6", "CC7.2"],
    "sensitive file":          ["CC6.1", "CC9.2"],
    "admin panel":             ["CC6.3", "CC6.6"],
    "open port":               ["CC6.6"],
    "backup":                  ["A1.2"],
    "web app":                 ["CC7.1", "CC8.1"],
    "debug":                   ["CC7.1"],
}

FRAMEWORKS = {
    "pci_dss":  ("PCI-DSS v4.0",  _PCI_DSS),
    "hipaa":    ("HIPAA Security Rule", _HIPAA),
    "iso27001": ("ISO 27001:2022",  _ISO27001),
    "soc2":     ("SOC 2 Type II",   _SOC2),
}

SEV_LABEL = {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Info"}


def _map_finding(finding: Finding, control_map: dict[str, list[str]]) -> list[str]:
    title_lower = finding.title.lower()
    controls: set[str] = set()
    for keyword, ids in control_map.items():
        if keyword in title_lower:
            controls.update(ids)
    return sorted(controls)


def _status(controls_hit: int, total_controls: int, critical_gaps: int) -> str:
    if critical_gaps > 0:
        return "FAIL"
    if controls_hit == 0:
        return "PASS"
    pct = controls_hit / max(total_controls, 1)
    if pct > 0.3:
        return "FAIL"
    if pct > 0.1:
        return "PARTIAL"
    return "PASS"


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/scans/{scan_id}")
async def compliance_report(
    scan_id: str,
    framework: str = "pci_dss",
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """
    Generate a compliance gap report for a completed scan.

    framework: pci_dss | hipaa | iso27001 | soc2
    """
    if framework not in FRAMEWORKS:
        raise HTTPException(status_code=400, detail=f"Unknown framework '{framework}'. Choose from: {', '.join(FRAMEWORKS)}")

    scan_result = await db.execute(select(Scan).where(Scan.id == scan_id, Scan.org_id == org.id))
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings_result = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
    findings = findings_result.scalars().all()

    framework_name, control_map = FRAMEWORKS[framework]

    violations: list[dict] = []
    controls_violated: set[str] = set()

    for f in findings:
        if f.severity == 0:
            continue  # skip INFO-only
        controls = _map_finding(f, control_map)
        if controls:
            controls_violated.update(controls)
            violations.append({
                "finding_id":  f.id,
                "host":        f.host,
                "title":       f.title,
                "severity":    SEV_LABEL.get(f.severity, "?"),
                "severity_int": f.severity,
                "controls":    controls,
                "remediation": f.remediation,
            })

    # Sort by severity desc
    violations.sort(key=lambda v: v["severity_int"], reverse=True)

    critical_gaps = sum(1 for v in violations if v["severity_int"] >= 4)
    high_gaps     = sum(1 for v in violations if v["severity_int"] == 3)
    total_controls = len(control_map)
    status = _status(len(controls_violated), total_controls, critical_gaps)

    return {
        "scan_id":        scan_id,
        "scan_name":      scan.name,
        "framework":      framework,
        "framework_name": framework_name,
        "status":         status,
        "summary": {
            "total_findings":       len(findings),
            "findings_with_gaps":   len(violations),
            "controls_violated":    sorted(controls_violated),
            "controls_violated_count": len(controls_violated),
            "critical_gaps":        critical_gaps,
            "high_gaps":            high_gaps,
            "compliance_score":     max(0, round(100 - (len(controls_violated) / max(total_controls, 1)) * 100)),
        },
        "violations": violations,
        "passed_note": "Controls not listed here had no matching findings — review manually for full assurance.",
    }


@router.get("/scans/{scan_id}/all")
async def all_frameworks_report(
    scan_id: str,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Return compliance gap summary across all frameworks for one scan."""
    scan_result = await db.execute(select(Scan).where(Scan.id == scan_id, Scan.org_id == org.id))
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings_result = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
    findings = findings_result.scalars().all()

    results = {}
    for fw_key, (fw_name, control_map) in FRAMEWORKS.items():
        controls_violated: set[str] = set()
        critical_gaps = 0
        for f in findings:
            if f.severity == 0:
                continue
            controls = _map_finding(f, control_map)
            controls_violated.update(controls)
            if f.severity >= 4 and controls:
                critical_gaps += 1
        score = max(0, round(100 - (len(controls_violated) / max(len(control_map), 1)) * 100))
        results[fw_key] = {
            "framework_name":        fw_name,
            "status":                _status(len(controls_violated), len(control_map), critical_gaps),
            "compliance_score":      score,
            "controls_violated":     len(controls_violated),
            "critical_gaps":         critical_gaps,
        }

    return {"scan_id": scan_id, "scan_name": scan.name, "frameworks": results}
