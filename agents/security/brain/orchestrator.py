"""
Security scan orchestrator — coordinates probe results through enrichment,
attack-path analysis, and Claude-powered reporting.
"""
import json
from dataclasses import dataclass, field
from typing import Optional
from core.claude_client import run_agent_loop

SYSTEM_PROMPT = """You are an expert penetration tester and security analyst.
You receive raw network scan data and produce a comprehensive security assessment.
Use the available tools to enrich findings, compute attack paths, and generate
an executive + technical report.

Always:
- Map CVEs to EPSS scores to prioritize by exploitability
- Identify lateral movement opportunities in the network graph
- Provide remediation steps ordered by risk × effort
- Use clear, non-technical language in the executive summary
"""

TOOLS = [
    {
        "name": "enrich_cves",
        "description": "Look up CVE details and EPSS scores for a list of CVE IDs",
        "input_schema": {
            "type": "object",
            "properties": {
                "cve_ids": {"type": "array", "items": {"type": "string"}, "description": "List of CVE IDs"}
            },
            "required": ["cve_ids"],
        },
    },
    {
        "name": "compute_attack_paths",
        "description": "Given a host graph, compute all multi-hop lateral movement paths to high-value targets",
        "input_schema": {
            "type": "object",
            "properties": {
                "hosts": {"type": "array", "description": "List of host objects with ip, services, vulnerabilities"},
                "targets": {"type": "array", "items": {"type": "string"}, "description": "High-value target IPs"},
            },
            "required": ["hosts"],
        },
    },
    {
        "name": "generate_report",
        "description": "Render the final HTML pentest report from structured findings",
        "input_schema": {
            "type": "object",
            "properties": {
                "executive_summary": {"type": "string"},
                "findings": {"type": "array"},
                "attack_paths": {"type": "array"},
                "remediation_plan": {"type": "array"},
            },
            "required": ["executive_summary", "findings", "remediation_plan"],
        },
    },
]


@dataclass
class ScanResult:
    scan_id: str
    target_subnet: str
    hosts: list = field(default_factory=list)
    report_html: Optional[str] = None
    attack_paths: list = field(default_factory=list)
    total_tokens: int = 0


def run_security_analysis(scan_id: str, target_subnet: str, probe_data: dict) -> ScanResult:
    """Entry point: takes raw probe output and returns a completed ScanResult."""
    from agents.security.brain.cve_enricher import enrich_cves_handler
    from agents.security.brain.attack_path import compute_attack_paths_handler
    from agents.security.brain.report_generator import generate_report_handler
    from core.claude_client import register_tool

    register_tool("enrich_cves", enrich_cves_handler)
    register_tool("compute_attack_paths", compute_attack_paths_handler)
    register_tool("generate_report", generate_report_handler)

    result = ScanResult(scan_id=scan_id, target_subnet=target_subnet, hosts=probe_data.get("hosts", []))

    initial_messages = [
        {
            "role": "user",
            "content": (
                f"Analyze this network scan for subnet {target_subnet}.\n\n"
                f"Raw probe data:\n```json\n{json.dumps(probe_data, indent=2)}\n```\n\n"
                "Enrich CVEs, compute attack paths, then generate the final HTML report."
            ),
        }
    ]

    messages = run_agent_loop(SYSTEM_PROMPT, initial_messages, TOOLS)

    # Extract report from last assistant message
    for msg in reversed(messages):
        if msg.get("role") == "assistant":
            for block in msg.get("content", []):
                if hasattr(block, "type") and block.type == "text" and "<html" in block.text.lower():
                    result.report_html = block.text
                    break
            break

    return result
