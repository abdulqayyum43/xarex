"""Enhanced Findings API — filtering, stats, export, suppression, MITRE ATT&CK."""
from __future__ import annotations

import csv
import io
import json
import re as _re
from datetime import datetime, timezone
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import get_org
from models.database import get_db
from models.schemas import FindingRead, MessageResponse
from models.tables import Finding, Org, Scan

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/findings", tags=["findings"])

SEV_LABEL = {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Info"}

REMEDIATION_STATUSES = ("new", "in_progress", "fixed", "false_positive", "accepted_risk")

# ── Compliance framework mapping ───────────────────────────────
COMPLIANCE_MAP: list[tuple[str, str, str, str]] = [
    # (regex_pattern, standard, control_ref, control_name)
    # PCI-DSS v4.0
    (r"ssl|tls|weak.cipher|certificate",         "PCI-DSS", "6.2.4",  "Secure Communications"),
    (r"default.cred|default.password",           "PCI-DSS", "2.2.1",  "Default Credentials"),
    (r"port|exposed.service|open.port",          "PCI-DSS", "1.3.1",  "Network Access Controls"),
    (r"cve-|patch|unpatched|exploit",            "PCI-DSS", "6.3.3",  "Patch Management"),
    (r"snmp|telnet|ftp|insecure.protocol",       "PCI-DSS", "2.2.7",  "Insecure Protocols"),
    (r"rdp|remote.desktop|remote.access",        "PCI-DSS", "12.3.2", "Remote Access Security"),
    # NIST 800-53 Rev 5
    (r"auth|cred|password|kerberos",             "NIST",    "IA-5",   "Authenticator Management"),
    (r"ssl|tls|encrypt|cipher",                  "NIST",    "SC-8",   "Transmission Confidentiality"),
    (r"cve-|patch|vulner|exploit",               "NIST",    "SI-2",   "Flaw Remediation"),
    (r"access|exposure|public.facing",           "NIST",    "AC-3",   "Access Enforcement"),
    (r"smb|rdp|ssh|remote.service",              "NIST",    "AC-17",  "Remote Access"),
    (r"admin.panel|admin.interface|exposed.admin","NIST",   "CM-7",   "Least Functionality"),
    (r"dns.zone|zone.transfer",                  "NIST",    "SC-20",  "Secure Name Resolution"),
    (r"llmnr|nbns|poison|relay",                 "NIST",    "SI-3",   "Malicious Code Protection"),
    # CIS Controls v8
    (r"port|service|open",                       "CIS",     "4.4",    "Manage Network Ports"),
    (r"ssl|tls|cert|hsts",                       "CIS",     "3.10",   "Encrypt Sensitive Data"),
    (r"cve-|patch|outdated|old.version",         "CIS",     "7.3",    "Perform Automated Patch Mgmt"),
    (r"default.cred|weak.password|anonymous",    "CIS",     "5.2",    "Use Unique Passwords"),
    (r"rdp|vnc|remote.mgmt",                     "CIS",     "12.7",   "Manage Remote Access"),
    (r"snmp.community|public.community",         "CIS",     "12.2",   "Manage Network Devices"),
    # ISO 27001:2022
    (r"ssl|tls|encrypt",                         "ISO27001","A.8.24", "Use of Cryptography"),
    (r"patch|vulner|cve",                        "ISO27001","A.8.8",  "Management of Vulnerabilities"),
    (r"access|auth|cred",                        "ISO27001","A.5.15", "Access Control"),
    (r"network|firewall|port",                   "ISO27001","A.8.20", "Network Security"),
]


def _get_compliance_controls(finding: Finding) -> list[dict]:
    """Map a finding to compliance framework controls."""
    text = ((finding.title or "") + " " + (finding.service or "") + " " + (finding.description or "")).lower()
    seen: set[str] = set()
    results: list[dict] = []
    for pattern, std, ref, name in COMPLIANCE_MAP:
        key = f"{std}:{ref}"
        if key not in seen and _re.search(pattern, text):
            seen.add(key)
            results.append({"standard": std, "control_ref": ref, "control_name": name})
    return results[:8]  # cap at 8 controls per finding


MITRE_ATTACK_MAP: dict[str, list[str]] = {
    "smb":             ["T1021.002"],   # Remote Services: SMB/Windows Admin Shares
    "ms17":            ["T1210"],       # Exploitation of Remote Services
    "eternalblue":     ["T1210"],
    "kerberoast":      ["T1558.003"],   # Steal or Forge Kerberos Tickets: Kerberoasting
    "asrep":           ["T1558.004"],   # AS-REP Roasting
    "zerologon":       ["T1210"],
    "printnightmare":  ["T1068"],       # Exploitation for Privilege Escalation
    "log4shell":       ["T1190"],       # Exploit Public-Facing Application
    "default cred":    ["T1078"],       # Valid Accounts
    "anonymous":       ["T1078.004"],   # Valid Accounts: Cloud Accounts
    "rdp":             ["T1021.001"],   # Remote Services: RDP
    "ssh":             ["T1021.004"],   # Remote Services: SSH
    "ftp":             ["T1021.002"],
    "snmp":            ["T1602"],       # Data from Configuration Repository
    "llmnr":           ["T1557.001"],   # Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning
    "relay":           ["T1557"],
    "docker":          ["T1610"],       # Deploy Container
    "kubernetes":      ["T1609"],       # Container Administration Command
    "redis":           ["T1505.003"],   # Server Software Component: Web Shell
    "elasticsearch":   ["T1530"],       # Data from Cloud Storage
    "mongodb":         ["T1530"],
}


def _attach_attack_techniques(finding: Finding) -> list[str]:
    """Infer MITRE ATT&CK technique IDs from finding title/service."""
    title_lower = (finding.title or "").lower()
    service_lower = (finding.service or "").lower()
    techniques: list[str] = []

    # Check metadata first
    meta_techniques = (finding.metadata_ or {}).get("attack_technique_ids", [])
    techniques.extend(meta_techniques)

    # Title-based inference
    for keyword, ids in MITRE_ATTACK_MAP.items():
        if keyword in title_lower or keyword in service_lower:
            techniques.extend(ids)

    return list(set(techniques))


# ──────────────────────────────────────────────
#  List findings (org-wide, filterable)
# ──────────────────────────────────────────────

@router.get("", response_model=list[dict])
async def list_findings(
    severity: int | None = Query(None, ge=0, le=4, description="Filter by severity 0-4"),
    scan_id: str | None = Query(None, description="Filter by scan ID"),
    host: str | None = Query(None, description="Filter by host IP"),
    cve_id: str | None = Query(None, description="Filter by CVE ID"),
    suppressed: bool = Query(False, description="Include suppressed findings"),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    """Return all findings for the authenticated org with optional filters."""
    # Get scan IDs for this org
    scan_ids_result = await db.execute(
        select(Scan.id).where(Scan.org_id == org.id)
    )
    org_scan_ids = [row[0] for row in scan_ids_result.fetchall()]

    if not org_scan_ids:
        return []

    # Build findings query
    query = select(Finding).where(Finding.scan_id.in_(org_scan_ids))

    if not suppressed:
        # Filter out suppressed findings (stored in metadata_)
        # We use a simple approach: check if suppressed key exists
        pass  # handled post-fetch for SQLite compat

    if severity is not None:
        query = query.where(Finding.severity == severity)
    if scan_id:
        if scan_id not in org_scan_ids:
            raise HTTPException(status_code=403, detail="Scan not found in your org")
        query = query.where(Finding.scan_id == scan_id)
    if host:
        query = query.where(Finding.host == host)
    if cve_id:
        query = query.where(Finding.cve_id.ilike(f"%{cve_id}%"))

    query = query.order_by(Finding.severity.desc(), Finding.timestamp.desc())
    query = query.offset(offset).limit(limit)

    result = await db.execute(query)
    findings = result.scalars().all()

    output = []
    for f in findings:
        meta = f.metadata_ or {}
        if not suppressed and meta.get("suppressed"):
            continue
        output.append({
            "id": f.id,
            "scan_id": f.scan_id,
            "host": f.host,
            "port": f.port,
            "protocol": f.protocol,
            "service": f.service,
            "severity": f.severity,
            "severity_label": SEV_LABEL.get(f.severity, "Unknown"),
            "cve_id": f.cve_id,
            "title": f.title,
            "description": f.description,
            "evidence": f.evidence,
            "remediation": f.remediation,
            "timestamp": f.timestamp.isoformat() if f.timestamp else None,
            "cvss_score": meta.get("cvss_score"),
            "cvss_vector": meta.get("cvss_vector"),
            "cvss_severity": meta.get("cvss_severity"),
            "epss_score": meta.get("epss_score"),
            "attack_techniques": _attach_attack_techniques(f),
            "suppressed": meta.get("suppressed", False),
            "analyst_note": meta.get("analyst_note", ""),
            "analyst_note_at": meta.get("analyst_note_at"),
            "remediation_status": f.remediation_status or "new",
            "remediation_note": f.remediation_note or "",
            "remediation_updated_at": f.remediation_updated_at.isoformat() if f.remediation_updated_at else None,
            "compliance_controls": _get_compliance_controls(f),
        })

    return output


# ──────────────────────────────────────────────
#  Stats
# ──────────────────────────────────────────────

@router.get("/stats")
async def finding_stats(
    scan_id: str | None = Query(None),
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Aggregate finding statistics for the org."""
    scan_ids_result = await db.execute(select(Scan.id).where(Scan.org_id == org.id))
    org_scan_ids = [row[0] for row in scan_ids_result.fetchall()]

    if not org_scan_ids:
        return _empty_stats()

    target_scan_ids = [scan_id] if (scan_id and scan_id in org_scan_ids) else org_scan_ids

    # Per-severity counts
    counts: dict[int, int] = {}
    for sev in range(5):
        count_result = await db.execute(
            select(func.count()).select_from(Finding)
            .where(Finding.scan_id.in_(target_scan_ids), Finding.severity == sev)
        )
        counts[sev] = count_result.scalar_one()

    # Unique hosts affected by critical/high
    affected_result = await db.execute(
        select(func.count(Finding.host.distinct())).select_from(Finding)
        .where(Finding.scan_id.in_(target_scan_ids), Finding.severity >= 3)
    )
    high_risk_hosts = affected_result.scalar_one()

    # Top CVEs
    from sqlalchemy import desc
    top_cves_result = await db.execute(
        select(Finding.cve_id, func.count().label("count"))
        .where(Finding.scan_id.in_(target_scan_ids), Finding.cve_id.isnot(None))
        .group_by(Finding.cve_id)
        .order_by(desc("count"))
        .limit(5)
    )
    top_cves = [{"cve_id": row[0], "count": row[1]} for row in top_cves_result.fetchall()]

    # Top affected hosts
    top_hosts_result = await db.execute(
        select(Finding.host, func.count().label("count"), func.max(Finding.severity).label("max_sev"))
        .where(Finding.scan_id.in_(target_scan_ids))
        .group_by(Finding.host)
        .order_by(desc("max_sev"), desc("count"))
        .limit(10)
    )
    top_hosts = [
        {"host": row[0], "finding_count": row[1], "max_severity": row[2], "max_severity_label": SEV_LABEL.get(row[2], "?")}
        for row in top_hosts_result.fetchall()
    ]

    return {
        "total": sum(counts.values()),
        "by_severity": {SEV_LABEL[k]: v for k, v in counts.items()},
        "high_risk_hosts": high_risk_hosts,
        "top_cves": top_cves,
        "top_hosts": top_hosts,
    }


def _empty_stats() -> dict:
    return {"total": 0, "by_severity": {}, "high_risk_hosts": 0, "top_cves": [], "top_hosts": []}


# ──────────────────────────────────────────────
#  Host risk profiles
# ──────────────────────────────────────────────

@router.get("/host-risk")
async def host_risk_profiles(
    scan_id: str | None = Query(None),
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    """Per-host risk aggregation: score, open ports, findings, ATT&CK techniques."""
    scan_ids_result = await db.execute(select(Scan.id).where(Scan.org_id == org.id))
    org_scan_ids = [row[0] for row in scan_ids_result.fetchall()]

    if not org_scan_ids:
        return []

    target_scan_ids = [scan_id] if (scan_id and scan_id in org_scan_ids) else org_scan_ids

    result = await db.execute(
        select(Finding).where(Finding.scan_id.in_(target_scan_ids))
    )
    findings = result.scalars().all()

    host_map: dict[str, dict] = {}
    for f in findings:
        if f.host not in host_map:
            host_map[f.host] = {
                "host": f.host,
                "findings": [],
                "open_ports": set(),
                "max_severity": 0,
                "techniques": set(),
                "cves": set(),
                "risk_score": 0.0,
            }
        h = host_map[f.host]
        h["findings"].append(f.id)
        if f.port:
            h["open_ports"].add(f.port)
        h["max_severity"] = max(h["max_severity"], f.severity)
        h["techniques"].update(_attach_attack_techniques(f))
        if f.cve_id:
            h["cves"].add(f.cve_id)

    # Compute risk score per host
    results = []
    for host, h in host_map.items():
        finding_count = len(h["findings"])
        # Weighted score: critical=10, high=7, medium=4, low=1
        all_findings_for_host = [f for f in findings if f.host == host]
        weighted = sum({4: 10, 3: 7, 2: 4, 1: 1, 0: 0}.get(f.severity, 0) for f in all_findings_for_host)
        risk_score = min(10.0, round(weighted / max(finding_count, 1) + len(h["cves"]) * 0.3, 2))

        results.append({
            "host": host,
            "risk_score": risk_score,
            "max_severity": h["max_severity"],
            "max_severity_label": SEV_LABEL.get(h["max_severity"], "?"),
            "finding_count": finding_count,
            "open_ports": sorted(h["open_ports"]),
            "cves": sorted(h["cves"]),
            "attack_techniques": sorted(h["techniques"]),
        })

    return sorted(results, key=lambda x: x["risk_score"], reverse=True)


# ──────────────────────────────────────────────
#  Export
# ──────────────────────────────────────────────

@router.get("/export.csv")
async def export_findings_csv(
    scan_id: str | None = Query(None),
    severity: int | None = Query(None, ge=0, le=4),
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Download all findings as a CSV file."""
    findings_data = await list_findings(
        severity=severity, scan_id=scan_id, host=None, cve_id=None,
        suppressed=False, limit=10000, offset=0, org=org, db=db
    )

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=[
        "id", "scan_id", "host", "port", "protocol", "service",
        "severity_label", "cve_id", "cvss_score", "title",
        "description", "evidence", "remediation",
        "attack_techniques", "timestamp",
    ])
    writer.writeheader()
    for f in findings_data:
        writer.writerow({
            **{k: f.get(k, "") for k in ["id", "scan_id", "host", "port", "protocol", "service", "severity_label", "cve_id", "cvss_score", "title", "description", "evidence", "remediation", "timestamp"]},
            "attack_techniques": ", ".join(f.get("attack_techniques", [])),
        })

    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=xarex_findings.csv"},
    )


@router.get("/export.json")
async def export_findings_json(
    scan_id: str | None = Query(None),
    severity: int | None = Query(None, ge=0, le=4),
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Download all findings as JSON."""
    findings_data = await list_findings(
        severity=severity, scan_id=scan_id, host=None, cve_id=None,
        suppressed=False, limit=10000, offset=0, org=org, db=db
    )
    return Response(
        content=json.dumps(findings_data, indent=2, default=str),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=xarex_findings.json"},
    )


# ──────────────────────────────────────────────
#  Suppress / un-suppress
# ──────────────────────────────────────────────

@router.patch("/{finding_id}/suppress", response_model=MessageResponse)
async def suppress_finding(
    finding_id: str,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    """Mark a finding as a false positive / suppressed."""
    finding = await _get_finding_for_org(finding_id, org.id, db)
    meta = dict(finding.metadata_ or {})
    meta["suppressed"] = True
    meta["suppressed_by"] = "user"
    finding.metadata_ = meta
    await db.commit()
    return MessageResponse(message="Finding suppressed")


@router.patch("/{finding_id}/note", response_model=MessageResponse)
async def update_finding_note(
    finding_id: str,
    body: dict,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    """Add or update an analyst note on a finding."""
    finding = await _get_finding_for_org(finding_id, org.id, db)
    meta = dict(finding.metadata_ or {})
    note = (body.get("note") or "").strip()
    if note:
        meta["analyst_note"] = note
        meta["analyst_note_at"] = datetime.now(timezone.utc).isoformat()
    else:
        meta.pop("analyst_note", None)
        meta.pop("analyst_note_at", None)
    finding.metadata_ = meta
    await db.commit()
    return MessageResponse(message="Note saved")


@router.patch("/{finding_id}/status", response_model=MessageResponse)
async def update_remediation_status(
    finding_id: str,
    body: dict,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    """Update the remediation tracking status of a finding."""
    finding = await _get_finding_for_org(finding_id, org.id, db)
    new_status = (body.get("status") or "").strip()
    if new_status not in REMEDIATION_STATUSES:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {', '.join(REMEDIATION_STATUSES)}")
    finding.remediation_status = new_status
    finding.remediation_note = (body.get("note") or "").strip() or finding.remediation_note
    finding.remediation_updated_at = datetime.now(timezone.utc)
    await db.commit()
    return MessageResponse(message=f"Status updated to '{new_status}'")


@router.delete("/{finding_id}/suppress", response_model=MessageResponse)
async def unsuppress_finding(
    finding_id: str,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    """Remove suppression from a finding."""
    finding = await _get_finding_for_org(finding_id, org.id, db)
    meta = dict(finding.metadata_ or {})
    meta.pop("suppressed", None)
    meta.pop("suppressed_by", None)
    finding.metadata_ = meta
    await db.commit()
    return MessageResponse(message="Finding unsuppressed")


# ──────────────────────────────────────────────
#  Per-finding CVE enrichment (on-demand)
# ──────────────────────────────────────────────

@router.post("/{finding_id}/enrich", response_model=dict)
async def enrich_finding(
    finding_id: str,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Fetch fresh CVE enrichment data from NVD for a specific finding."""
    finding = await _get_finding_for_org(finding_id, org.id, db)
    if not finding.cve_id:
        raise HTTPException(status_code=400, detail="Finding has no CVE ID")

    from services.cve_enricher import get_enricher
    enricher = get_enricher()
    data = await enricher.enrich(finding.cve_id)

    if data:
        meta = dict(finding.metadata_ or {})
        meta.update(data)
        finding.metadata_ = meta
        await db.commit()

    return data


# ──────────────────────────────────────────────
#  Helpers
# ──────────────────────────────────────────────

async def _get_finding_for_org(finding_id: str, org_id: str, db: AsyncSession) -> Finding:
    """Fetch a finding and verify it belongs to the org."""
    from sqlalchemy import select as sa_select
    result = await db.execute(
        sa_select(Finding).where(Finding.id == finding_id)
    )
    finding = result.scalar_one_or_none()
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Verify org ownership via scan
    scan_result = await db.execute(
        sa_select(Scan).where(Scan.id == finding.scan_id, Scan.org_id == org_id)
    )
    if scan_result.scalar_one_or_none() is None:
        raise HTTPException(status_code=403, detail="Finding not in your org")

    return finding
