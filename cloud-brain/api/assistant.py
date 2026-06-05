"""Xarex AI Assistant — context-aware conversational help for the platform."""
from __future__ import annotations

import json

import structlog
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import get_org
from config import settings
from models.database import get_db
from models.tables import Org

router = APIRouter(prefix="/api/v1/assistant", tags=["assistant"])
logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are Xarex AI — the built-in assistant for Xarex, an Autonomous Penetration Testing Platform.

You help security professionals understand and use Xarex's features. You know everything about:

PLATFORM FEATURES:
• Dashboard — stats (critical/high findings, active probes, schedules), live scan panel with phase tracker, risk trend chart, breach probability gauge (Verizon DBIR-calibrated)
• Probes — lightweight Go agents deployed inside target networks; they register automatically on launch; run with sudo for full raw socket access
• Scans — autonomous jobs: host discovery → port scan → service detection → vuln scan → attack path builder → report generation; watch live via WebSocket stream
• Findings — vulnerabilities with CVE IDs, CVSS v3.1 scores, MITRE ATT&CK techniques, OWASP/PCI-DSS/NIST compliance tags, analyst notes, false positive suppression; filterable by severity/scan/host
• Attack Paths — modelled kill chains: entry point → pivot hops → target; risk scored 0-10; fixing the entry point breaks the whole chain
• Scan Diff — compare two scans to see new/fixed/persisting findings and risk delta; proves remediation ROI
• Crown Jewels — define critical assets (Domain Controller, payment DB, PII store); Xarex computes blast radius: how many attack paths lead to each one; shows estimated $K breach risk
• Network Map — force-directed canvas graph of discovered hosts with attack path overlays; drag/pan/zoom; click nodes for detail
• Reports — AI (Claude Opus) or rules-engine executive summary, risk score (0-10), attack narrative, prioritised remediation plan, quick wins, MITRE mapping
• Schedules — cron-based automated recurring scans; use "0 2 * * *" for 2am daily, "0 0 * * 1" for weekly Monday
• AI Intel — deep Claude Opus analysis: executive summary (C-suite), attack narrative (technical), remediation ROI, quick wins, MITRE ATT&CK mapping
• Threat Actors — 11 real APT groups (APT29/Cozy Bear, APT28/Fancy Bear, Lazarus, APT41, Sandworm, FIN7, MuddyWater, DarkSide, LAPSUS$, Cl0p, Scattered Spider); shows exposure score 0-10, matched findings, simulated kill chain
• CVE Watch — live NIST NVD feed matched against discovered services; flags "YOUR ENV" when a new CVE matches your assets; "PoC" when exploit reference detected
• Host Inventory — per-host risk cards with SVG ring charts; shows risk score, open ports, CVEs, MITRE techniques; click → drill to findings
• Pentest Tools — CVSS v3.1 calculator, encoder/decoder (Base64/URL/Hex/SHA-256/MD5), reverse shell generator (12 types + 4 listener commands), CIDR calculator, JWT decoder

TECHNICAL:
• Cloud Brain: Python/FastAPI at port 8005; probe gRPC on 50051
• Risk score formula: min(10, 2.5×Critical + 1.2×High + 0.4×Medium + 0.1×Low)
• Breach probability: 5% DBIR baseline + 4.5% per critical + 1.5% per high finding
• CVSS: 0=None, 0.1–3.9=Low, 4–6.9=Medium, 7–8.9=High, 9–10=Critical

YOUR STYLE:
• Direct, practical, no filler. Security professionals value precision.
• Bullet points for steps. Bold key UI element names.
• Reference exact page/button names. Under 250 words unless detail is genuinely needed.
• When recommending action, say exactly where to navigate and what to click.
• If context shows the user is on a specific page, tailor advice to that page."""

# ---------------------------------------------------------------------------
# Rules-based fallback (no API key needed)
# ---------------------------------------------------------------------------

RULES: dict[str, str] = {
    "scan": "**To run a scan:** Go to **Scans** → **+ New Scan** → enter a name and target subnet (e.g. `192.168.1.0/24`) → select a probe → Launch. Or use **Quick Scan** on the Dashboard. Phases: host discovery → port scan → service detection → vuln scan → attack paths → report.",
    "probe": "**To deploy a probe:** Go to **Probes** → **Deploy Probe** → follow the 5-step guide. Build the Go binary, then run: `sudo ./xarex-probe --brain-url http://localhost:8005 --api-key YOUR_KEY`. It registers automatically within 30 seconds.",
    "finding": "**Findings** are discovered vulnerabilities. Click any row to see: CVE ID, CVSS score, description, MITRE ATT&CK techniques, compliance tags (OWASP/PCI-DSS/NIST), resource links (NVD, Exploit-DB, Shodan), and an analyst notes field. Filter by severity, scan, or host IP using the dropdowns at the top.",
    "crown jewel": "**Crown Jewels** define your most critical assets (DC, payment DB, PII). Xarex counts how many attack paths lead to each one. Go to **Crown Jewels** → **+ Add Crown Jewel** → enter the asset name, IP, and category. The blast radius shows direct and indirect paths plus estimated breach cost.",
    "cve watch": "**CVE Watch** fetches the latest vulnerabilities from NIST NVD and matches them to your discovered services. Go to **CVE Watch** → **Refresh Feed**. CVEs matching your environment are flagged **YOUR ENV** in red. CVEs with public exploits are flagged **PoC**.",
    "threat actor": "**Threat Actor Simulation:** Go to **Threat Actors** → select an APT group. Xarex overlays their MITRE ATT&CK TTPs against your findings and shows: exposure score (0-10), which findings map to their techniques, and a simulated kill chain. A score above 5 means significant exposure.",
    "report": "**To generate a report:** Go to **Reports** → select a completed scan → **Generate Report**. If `ANTHROPIC_API_KEY` is configured, Claude Opus writes the analysis. Otherwise the rules engine produces risk scoring, attack narrative, and remediation plan. View full AI analysis under **AI Intel**.",
    "attack path": "**Attack Paths** show how an adversary would chain vulnerabilities across your network. Go to **Attack Paths** → select a scan. Each path shows entry → target, risk score, hop count, and impact. **Fix the entry point finding to break the entire chain** — you don't need to fix every hop.",
    "schedule": "**Schedules** automate recurring scans. Go to **Schedules** → **+ New Schedule** → enter name, cron (e.g. `0 2 * * *` = 2am daily), target subnet, and probe. Examples: `0 0 * * 1` = weekly Monday, `0 */6 * * *` = every 6 hours.",
    "cvss": "**CVSS v3.1 scoring:** 0=None, 0.1–3.9=Low, 4–6.9=Medium, 7–8.9=High, 9–10=Critical. Use the **CVSS Calculator** in **Pentest Tools** to compute scores and get the vector string. Key metrics: Attack Vector (Network=worst), Attack Complexity, Privileges Required, User Interaction, Scope, CIA Impact.",
    "risk score": "**Risk score (0-10):** `min(10, 2.5×Critical + 1.2×High + 0.4×Medium + 0.1×Low)`. Score ≥8 = critical environment, needs immediate action. The **Breach Probability** gauge on the dashboard converts this to a statistical likelihood based on Verizon DBIR industry data.",
    "network map": "**Network Map** shows discovered hosts as a force-directed graph. Drag to pan, scroll to zoom, click a node to see its risk score, open ports, CVEs, and a drill-down button. Red dashed arrows = attack paths. The danger of each path scales the arrow thickness and opacity.",
    "diff": "**Scan Diff** compares two completed scans. Go to **Scan Diff** → select Baseline (earlier) and Target (recent) → **Compare Scans**. **New** tab = regressions. **Fixed** tab = remediation wins. Risk Delta: negative (green) means you improved.",
    "jwt": "**JWT Decoder** in Pentest Tools: paste any JWT token (eyJ…) into the input. Xarex decodes the header (algorithm, type) and payload (claims, expiry, issuer). Watch for: `alg: none` (critical — no signature), `exp` timestamps, and sensitive claims in the payload.",
    "reverse shell": "**Reverse Shell Generator:** Go to **Pentest Tools** → **Rev Shell** tab. Enter your listener IP and port, select shell type (bash/python/php/powershell/nc/socat/etc). The output also shows listener commands for nc, socat, MSF multi/handler, and pwncat.",
    "cidr": "**CIDR Calculator:** Go to **Pentest Tools** → **CIDR** tab. Enter any subnet like `192.168.1.0/24`. Get: network address, broadcast, usable host range, total hosts, subnet mask, IP class, and whether it's private (RFC 1918).",
    "host": "**Host Inventory** shows per-host risk cards. The SVG ring chart colour encodes risk: red=critical (≥8), orange=high (≥6), yellow=medium (≥3), green=low. Click a card → View Findings to see all vulnerabilities for that host. Filter by scan using the dropdown.",
    "breach": "**Breach Probability:** Starts at 5% annual (Verizon DBIR SME baseline) and increases by 4.5% per critical finding and 1.5% per high finding. Above 60% = high risk requiring immediate action. Fixing all critical findings has the most impact on reducing this number.",
}


def _rules_reply(message: str) -> str:
    ml = message.lower()
    for kw, reply in RULES.items():
        if kw in ml:
            return reply
    return (
        "I'm **Xarex AI** — your guide to the platform. Ask me about anything:\n\n"
        "- **Scanning** — 'how do I start a scan?'\n"
        "- **Findings** — 'how do I prioritise findings?'\n"
        "- **Crown Jewels** — 'what are crown jewels?'\n"
        "- **Threat Actors** — 'how does threat simulation work?'\n"
        "- **CVE Watch** — 'how do CVE alerts work?'\n"
        "- **Attack Paths** — 'how do I break a kill chain?'\n"
        "- **Reports** — 'how do I generate a report?'\n"
        "- **Any feature** — just ask!"
    )


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class _AssistantService:
    def __init__(self) -> None:
        self._client = None

    def _client_(self):
        if not settings.ANTHROPIC_API_KEY:
            return None
        if self._client is None:
            import anthropic
            self._client = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)
        return self._client

    async def chat(self, message: str, context: dict, history: list) -> str:
        client = self._client_()

        context_note = ""
        if context:
            parts = []
            if context.get("page"):
                parts.append(f"currently on the '{context['page']}' page")
            if context.get("critical_count") is not None:
                parts.append(f"{context['critical_count']} critical findings")
            if context.get("scan_count") is not None:
                parts.append(f"{context['scan_count']} total scans")
            if context.get("probe_count") is not None:
                parts.append(f"{context['probe_count']} online probes")
            if parts:
                context_note = f"\n\n[User context: {', '.join(parts)}]"

        if not client:
            return _rules_reply(message)

        try:
            messages = []
            for h in history[-10:]:
                role = h.get("role", "user")
                if role in ("user", "assistant"):
                    messages.append({"role": role, "content": h["content"]})
            messages.append({"role": "user", "content": message + context_note})

            response = client.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=500,
                system=SYSTEM_PROMPT,
                messages=messages,
            )
            return response.content[0].text
        except Exception as exc:
            logger.warning("Assistant API call failed — using rules fallback", error=str(exc))
            return _rules_reply(message)


_svc = _AssistantService()


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@router.post("/chat")
async def assistant_chat(
    body: dict,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Context-aware AI assistant chat endpoint."""
    message = (body.get("message") or "").strip()
    context = body.get("context") or {}
    history = body.get("history") or []

    if not message:
        return {"reply": "What can I help you with?", "powered_by": "xarex"}

    reply = await _svc.chat(message, context, history)
    powered = "claude" if settings.ANTHROPIC_API_KEY else "rules"
    return {"reply": reply, "powered_by": powered}
