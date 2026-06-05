"""AI Analyst — Claude-powered scan analysis.

Generates executive summaries, attack narratives, MITRE ATT&CK mappings,
and prioritised remediation plans from scan findings.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

import structlog

from config import settings

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

logger = structlog.get_logger(__name__)

SEVERITY_LABELS = {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Info"}

ANALYST_SYSTEM_PROMPT = """You are an elite penetration tester and security analyst working with the Xarex autonomous assessment platform.

Your role is to analyse automated network scan results and produce:
1. A concise executive summary (non-technical, for C-suite/board)
2. Key risk areas identified
3. A prioritised remediation plan (ordered by impact + effort)
4. An attack narrative — the technical story of how an adversary would move through this network
5. Quick wins — fixes that can be done today to cut risk immediately
6. MITRE ATT&CK techniques observed

Be direct. Use specific host IPs, CVEs, and port numbers. Quantify risk wherever possible.
Format your response as structured JSON matching the schema provided."""


class AIAnalyst:
    """Wraps the Anthropic SDK to analyse scan results."""

    def __init__(self) -> None:
        self._client = None

    def _get_client(self):
        if not settings.ANTHROPIC_API_KEY:
            raise RuntimeError("ANTHROPIC_API_KEY not configured")
        if self._client is None:
            import anthropic
            self._client = anthropic.AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY)
        return self._client

    async def analyse_scan(self, scan_id: str, db: "AsyncSession") -> dict[str, Any]:
        """Run AI analysis on a completed scan. Returns analysis dict and saves to Report."""
        from sqlalchemy import select, update
        from models.tables import Finding, Scan, AttackPath, Report

        # Load scan data
        scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = scan_result.scalar_one_or_none()
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")

        findings_result = await db.execute(
            select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.severity.desc())
        )
        findings = findings_result.scalars().all()

        paths_result = await db.execute(
            select(AttackPath).where(AttackPath.scan_id == scan_id).order_by(AttackPath.risk_score.desc())
        )
        attack_paths = paths_result.scalars().all()

        if not findings:
            return {"summary": "No findings in this scan.", "findings": []}

        # Build the prompt payload
        severity_counts = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0}
        for f in findings:
            severity_counts[min(f.severity, 4)] += 1

        top_findings = []
        for f in findings[:20]:  # top 20 by severity
            top_findings.append({
                "host": f.host,
                "port": f.port,
                "service": f.service,
                "severity": SEVERITY_LABELS.get(f.severity, "Unknown"),
                "title": f.title,
                "cve_id": f.cve_id,
                "description": f.description[:300] if f.description else "",
                "cvss_score": (f.metadata_ or {}).get("cvss_score"),
                "attack_techniques": (f.metadata_ or {}).get("attack_technique_ids", []),
            })

        top_paths = []
        for p in attack_paths[:5]:
            top_paths.append({
                "entry": p.entry_point,
                "target": p.target,
                "risk_score": p.risk_score,
                "impact": p.impact,
                "hops": len(p.nodes) if p.nodes else 0,
            })

        duration_str = "unknown"
        if scan.started_at and scan.completed_at:
            delta = scan.completed_at - scan.started_at
            mins = int(delta.total_seconds() / 60)
            duration_str = f"{mins} minutes"

        user_message = json.dumps({
            "scan_name": scan.name,
            "scan_id": scan_id,
            "duration": duration_str,
            "total_findings": len(findings),
            "findings_by_severity": {
                SEVERITY_LABELS[k]: v for k, v in severity_counts.items() if v > 0
            },
            "top_findings": top_findings,
            "attack_paths": top_paths,
            "response_schema": {
                "executive_summary": "string (2-3 paragraphs, non-technical)",
                "risk_score": "number 0-10",
                "key_risks": ["string", "..."],
                "attack_narrative": "string (technical story, 3-5 paragraphs)",
                "remediation_plan": [
                    {"priority": 1, "action": "string", "hosts_affected": ["..."], "effort": "low|medium|high", "impact": "string"}
                ],
                "quick_wins": ["string", "..."],
                "attack_techniques_observed": [
                    {"technique_id": "T1234", "name": "string", "description": "string"}
                ],
            }
        }, indent=2)

        if settings.ANTHROPIC_API_KEY:
            try:
                client = self._get_client()
                response = await client.messages.create(
                    model="claude-opus-4-6",
                    max_tokens=4096,
                    system=ANALYST_SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": user_message}],
                )

                raw_text = response.content[0].text
                try:
                    clean = raw_text.strip()
                    if clean.startswith("```"):
                        clean = clean.split("```", 2)[1]
                        if clean.startswith("json"):
                            clean = clean[4:]
                        clean = clean.rsplit("```", 1)[0].strip()
                    analysis = json.loads(clean)
                except json.JSONDecodeError:
                    analysis = {"executive_summary": raw_text, "raw": True}
            except Exception as exc:
                logger.error("AI analysis failed", scan_id=scan_id, error=str(exc))
                analysis = self._rules_based_analysis(scan, findings, attack_paths)
        else:
            logger.info("ANTHROPIC_API_KEY not set — using rules-based analysis", scan_id=scan_id)
            analysis = self._rules_based_analysis(scan, findings, attack_paths)

        # Persist analysis into the Report record
        from sqlalchemy import select as sa_select
        report_result = await db.execute(
            sa_select(Report).where(Report.scan_id == scan_id)
        )
        report = report_result.scalar_one_or_none()
        if report:
            report.ai_summary = json.dumps(analysis)
            await db.commit()

        logger.info("AI analysis saved", scan_id=scan_id)
        return analysis

    def _rules_based_analysis(self, scan: Any, findings: list, attack_paths: list) -> dict:
        """
        Rules-based analysis that works without an Anthropic API key.
        Produces an executive summary, remediation plan, MITRE techniques,
        and an attack narrative from finding data alone.
        """
        sev_counts = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0}
        for f in findings:
            sev_counts[min(f.severity, 4)] += 1

        total = len(findings)
        critical = sev_counts[4]
        high = sev_counts[3]
        medium = sev_counts[2]
        low = sev_counts[1]
        info = sev_counts[0]

        # Risk score (same formula as reports.py)
        risk_score = round(min(10.0, critical * 2.5 + high * 1.2 + medium * 0.4 + low * 0.1), 1)

        # Unique hosts
        hosts: set[str] = set(f.host for f in findings)
        affected_hosts = sorted(hosts)

        # High/critical findings for narrative
        serious = [f for f in findings if f.severity >= 3]
        serious.sort(key=lambda f: f.severity, reverse=True)

        # Executive summary
        if total == 0:
            exec_summary = (
                f"The automated assessment of '{scan.name}' did not detect any security findings. "
                "This may indicate the target was unreachable, the scan scope was limited, or the "
                "environment is well-hardened. Manual review is recommended to verify coverage."
            )
        elif critical > 0:
            exec_summary = (
                f"The automated assessment of '{scan.name}' identified {total} security findings across "
                f"{len(hosts)} host(s), including {critical} CRITICAL and {high} HIGH severity issues "
                f"that represent immediate compromise risk. The overall risk score is {risk_score}/10.\n\n"
                f"Critical issues include: {', '.join(f.title for f in serious[:3])}. "
                f"These vulnerabilities can be exploited without authentication and may allow an attacker "
                f"to achieve full system compromise, data exfiltration, or lateral movement within the network.\n\n"
                f"Immediate remediation is required. Address all Critical and High findings before the next "
                f"business day. Medium findings should be resolved within 30 days."
            )
        elif high > 0:
            exec_summary = (
                f"The automated assessment of '{scan.name}' identified {total} security findings across "
                f"{len(hosts)} host(s), including {high} HIGH severity issues. "
                f"The overall risk score is {risk_score}/10.\n\n"
                f"High-severity findings include: {', '.join(f.title for f in serious[:3])}. "
                f"While no critical vulnerabilities were detected, the identified issues represent "
                f"significant attack surface that should be addressed promptly.\n\n"
                f"High findings should be remediated within 7 days. Medium findings within 30 days."
            )
        else:
            exec_summary = (
                f"The automated assessment of '{scan.name}' identified {total} findings across "
                f"{len(hosts)} host(s), with no Critical or High severity issues. "
                f"The overall risk score is {risk_score}/10. "
                f"The environment appears reasonably well-secured at the network layer. "
                f"Address Medium and Low findings to further reduce the attack surface."
            )

        # Key risks
        key_risks: list[str] = []
        seen_titles: set[str] = set()
        for f in serious[:8]:
            if f.title not in seen_titles:
                host_str = f"on {f.host}" + (f":{f.port}" if f.port else "")
                key_risks.append(f"[{SEVERITY_LABELS[f.severity]}] {f.title} {host_str}")
                seen_titles.add(f.title)

        if not key_risks:
            medium_f = [f for f in findings if f.severity == 2]
            for f in medium_f[:3]:
                key_risks.append(f"[Medium] {f.title} on {f.host}")

        # Attack narrative
        if serious:
            entry = serious[-1]  # lowest severity serious finding = likely entry point
            chain = serious[:3]
            narrative_parts = [
                f"An attacker targeting '{scan.name}' would likely begin by scanning {len(hosts)} discovered "
                f"host(s) for exposed services.",
                f"The most accessible entry point appears to be {entry.host}"
                + (f" via port {entry.port} ({entry.service or 'unknown service'})" if entry.port else "")
                + f", where '{entry.title}' was detected.",
            ]
            if len(chain) > 1:
                narrative_parts.append(
                    f"From this foothold, the attacker could escalate by exploiting: "
                    + "; ".join(f"'{f.title}' on {f.host}" for f in chain[1:3]) + "."
                )
            if len(hosts) > 1:
                narrative_parts.append(
                    f"With access to one host, lateral movement across the {len(hosts)}-host network "
                    f"becomes viable, particularly through shared credentials or network-level vulnerabilities."
                )
            attack_narrative = " ".join(narrative_parts)
        else:
            attack_narrative = (
                f"No clear high-severity attack chain was identified. The network presents "
                f"a limited attack surface based on the {total} findings detected."
            )

        # Remediation plan
        remediation_plan: list[dict] = []
        priority = 1
        added: set[str] = set()
        for sev in [4, 3, 2, 1]:
            for f in findings:
                if f.severity == sev and f.title not in added:
                    effort = "low" if sev >= 3 else ("medium" if sev == 2 else "high")
                    hosts_affected = sorted({ff.host for ff in findings if ff.title == f.title})
                    remediation_plan.append({
                        "priority": priority,
                        "action": f.remediation or f"Remediate: {f.title}",
                        "hosts_affected": hosts_affected[:5],
                        "effort": effort,
                        "impact": f"Closes {SEVERITY_LABELS[sev]} risk: {f.title}",
                    })
                    added.add(f.title)
                    priority += 1
                    if priority > 10:
                        break
            if priority > 10:
                break

        # Quick wins — low effort / high impact
        quick_wins: list[str] = []
        for f in findings:
            if f.severity >= 3 and f.remediation:
                first_step = f.remediation.split(".")[0].strip()
                if first_step and first_step not in quick_wins:
                    quick_wins.append(first_step)
            if len(quick_wins) >= 5:
                break
        if not quick_wins:
            quick_wins = ["Run a full rescan after applying patches to verify remediation effectiveness"]

        # MITRE techniques (inferred from findings)
        MITRE_INFERENCE = {
            "redis":         [{"technique_id": "T1190",    "name": "Exploit Public-Facing Application", "description": "Unauthenticated Redis access"}],
            "mongodb":       [{"technique_id": "T1530",    "name": "Data from Cloud Storage", "description": "Unauthenticated MongoDB read/write access"}],
            "elasticsearch": [{"technique_id": "T1530",    "name": "Data from Cloud Storage", "description": "Unauthenticated Elasticsearch access"}],
            "ftp":           [{"technique_id": "T1078.004","name": "Valid Accounts: Cloud Accounts", "description": "FTP anonymous login"}],
            "smb":           [{"technique_id": "T1021.002","name": "Remote Services: SMB", "description": "SMB signing disabled — relay attack possible"}],
            "llmnr":         [{"technique_id": "T1557.001","name": "LLMNR/NBT-NS Poisoning", "description": "LLMNR/NBT-NS poisoning for credential capture"}],
            "smtp":          [{"technique_id": "T1566",    "name": "Phishing", "description": "SMTP open relay enables phishing abuse"}],
            "ssl":           [{"technique_id": "T1600",    "name": "Weaken Encryption", "description": "Outdated TLS/SSL protocol or weak cipher"}],
            "heartbleed":    [{"technique_id": "T1190",    "name": "Exploit Public-Facing Application", "description": "CVE-2014-0160 OpenSSL Heartbleed"}],
            "hsts":          [{"technique_id": "T1557",    "name": "Adversary-in-the-Middle", "description": "Missing HSTS enables SSL stripping"}],
            "default cred":  [{"technique_id": "T1078",    "name": "Valid Accounts", "description": "Default credentials accepted"}],
            "kerberos":      [{"technique_id": "T1558.003","name": "Kerberoasting", "description": "Kerberos ticket extraction"}],
            "memcached":     [{"technique_id": "T1498",    "name": "Network Denial of Service", "description": "Memcached DDoS amplification"}],
        }
        techniques_seen: dict[str, dict] = {}
        for f in findings:
            key = (f.title or "").lower() + " " + (f.service or "").lower()
            for kw, techs in MITRE_INFERENCE.items():
                if kw in key:
                    for t in techs:
                        techniques_seen[t["technique_id"]] = t

        return {
            "executive_summary": exec_summary,
            "risk_score": risk_score,
            "key_risks": key_risks,
            "attack_narrative": attack_narrative,
            "remediation_plan": remediation_plan,
            "quick_wins": quick_wins,
            "attack_techniques_observed": list(techniques_seen.values()),
            "ai_powered": False,
            "note": "Analysis generated by Xarex rules engine. For AI-powered analysis, configure ANTHROPIC_API_KEY.",
        }

    async def suggest_next_steps(
        self,
        findings: list[dict],
        current_hosts: list[str],
    ) -> list[str]:
        """Given findings so far, suggest what the autonomous engine should check next."""
        if not findings or not settings.ANTHROPIC_API_KEY:
            return []

        client = self._get_client()
        prompt = (
            "You are an autonomous pentest AI. Given these findings so far, "
            "list the 5 most valuable next checks to run (be specific: host, port, check type). "
            "Reply as a JSON array of strings only.\n\n"
            f"Current findings:\n{json.dumps(findings[:10], indent=2)}\n"
            f"Discovered hosts: {current_hosts}"
        )

        try:
            response = await client.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=512,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = response.content[0].text.strip()
            clean = raw.strip("`json \n")
            return json.loads(clean)
        except Exception:
            return []
