"""Generates a styled HTML pentest report from Claude's structured findings."""
import json
from datetime import datetime


PRIORITY_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#65a30d",
    "info": "#0284c7",
}


def generate_report_handler(
    executive_summary: str,
    findings: list,
    remediation_plan: list,
    attack_paths: list = None,
) -> str:
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    findings_html = _render_findings(findings)
    paths_html = _render_attack_paths(attack_paths or [])
    remediation_html = _render_remediation(remediation_plan)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Xarex Security Report — {now}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0f172a; color: #e2e8f0; line-height: 1.6; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 2rem; }}
  h1 {{ font-size: 2rem; color: #38bdf8; margin-bottom: 0.5rem; }}
  h2 {{ font-size: 1.3rem; color: #94a3b8; border-bottom: 1px solid #1e293b; padding-bottom: 0.5rem; margin: 2rem 0 1rem; }}
  .badge {{ display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 0.75rem; font-weight: 700; color: #fff; }}
  .card {{ background: #1e293b; border-radius: 8px; padding: 1.25rem; margin-bottom: 1rem; }}
  .meta {{ color: #64748b; font-size: 0.85rem; margin-bottom: 1rem; }}
  .exec {{ background: #172554; border-left: 4px solid #3b82f6; padding: 1.25rem; border-radius: 0 8px 8px 0; white-space: pre-wrap; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
  th {{ text-align: left; padding: 8px 12px; background: #0f172a; color: #94a3b8; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #1e293b; }}
  .path-hop {{ display: inline-block; background: #0f172a; border-radius: 4px; padding: 2px 8px; margin: 2px; font-family: monospace; font-size: 0.8rem; }}
  .arrow {{ color: #64748b; margin: 0 4px; }}
</style>
</head>
<body>
<div class="container">
  <h1>Xarex Autonomous Security Report</h1>
  <p class="meta">Generated: {now} &nbsp;|&nbsp; Powered by Claude AI</p>

  <h2>Executive Summary</h2>
  <div class="exec">{executive_summary}</div>

  <h2>Findings</h2>
  {findings_html}

  <h2>Attack Paths</h2>
  {paths_html}

  <h2>Remediation Plan</h2>
  {remediation_html}
</div>
</body>
</html>"""
    return html


def _render_findings(findings: list) -> str:
    if not findings:
        return "<p>No findings.</p>"
    rows = ""
    for f in findings:
        priority = f.get("priority", "info")
        color = PRIORITY_COLORS.get(priority, "#64748b")
        rows += f"""
        <tr>
          <td><span class="badge" style="background:{color}">{priority.upper()}</span></td>
          <td>{f.get('host', '')}</td>
          <td>{f.get('title', '')}</td>
          <td>{f.get('cve_id', '—')}</td>
          <td>{f.get('cvss_score', '—')}</td>
          <td>{f.get('epss_score', '—')}</td>
        </tr>"""
    return f"""
    <table>
      <thead><tr><th>Severity</th><th>Host</th><th>Finding</th><th>CVE</th><th>CVSS</th><th>EPSS</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>"""


def _render_attack_paths(paths: list) -> str:
    if not paths:
        return "<p>No exploitable attack paths identified.</p>"
    items = ""
    for p in paths:
        hops = " <span class='arrow'>→</span> ".join(
            f"<span class='path-hop'>{h}</span>" for h in p.get("hops", [])
        )
        items += f"<div class='card'>{hops}</div>"
    return items


def _render_remediation(plan: list) -> str:
    if not plan:
        return "<p>No remediation items.</p>"
    items = ""
    for i, item in enumerate(plan, 1):
        items += f"""
        <div class="card">
          <strong>{i}. {item.get('title', '')}</strong>
          <p style="margin-top:0.5rem;color:#94a3b8">{item.get('description', '')}</p>
          <p style="margin-top:0.25rem;font-size:0.8rem;color:#64748b">Effort: {item.get('effort', '?')} &nbsp;|&nbsp; Impact: {item.get('impact', '?')}</p>
        </div>"""
    return items
