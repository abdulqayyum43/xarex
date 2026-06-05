"""Personal Security Score engine.

Aggregates signals from all Xarex features into a 0-100 score with a letter
grade and a prioritised action list. Each component contributes up to 25 pts.

  Component       Weight  Signals
  ─────────────── ──────  ───────────────────────────────────────────────────
  Breach Health     25    Breach count, data classes exposed, password hygiene
  Network Posture   25    Critical/high findings from latest scans
  Exposure          25    Footprint scan hits, public data broker exposure
  Hygiene           25    SSL validity, email auth (SPF/DKIM/DMARC), 2FA hints
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

logger = structlog.get_logger(__name__)


def _grade(score: int) -> str:
    if score >= 90: return "A+"
    if score >= 80: return "A"
    if score >= 70: return "B"
    if score >= 55: return "C"
    if score >= 40: return "D"
    return "F"


async def compute_score(org_id: str, db: AsyncSession) -> dict[str, Any]:
    """Compute and return the current security score for an org."""
    from models.tables import BreachMonitor, BreachHit, Scan, Finding, FootprintScan

    breakdown: dict[str, Any] = {}
    actions: list[dict] = []

    # ── 1. Breach Health (0-25) ────────────────────────────────────
    breach_score = 25
    monitors_r = await db.execute(
        select(BreachMonitor).where(BreachMonitor.org_id == org_id, BreachMonitor.active == True)
    )
    monitors = monitors_r.scalars().all()
    total_breaches = sum(m.breach_count for m in monitors)

    if total_breaches == 0 and monitors:
        breach_score = 25
    elif total_breaches > 0:
        penalty = min(20, total_breaches * 5)
        breach_score = max(5, 25 - penalty)
        # Check for sensitive data classes
        hits_r = await db.execute(
            select(BreachHit).where(
                BreachHit.monitor_id.in_([m.id for m in monitors])
            )
        )
        hits = hits_r.scalars().all()
        sensitive = {"Passwords", "Credit Cards", "Social Security Numbers", "Banking"}
        has_sensitive = any(
            bool(set(h.data_classes or []) & sensitive) for h in hits
        )
        if has_sensitive:
            breach_score = max(2, breach_score - 8)
            actions.append({
                "priority": "critical",
                "title":    "Change exposed passwords immediately",
                "detail":   "Your credentials were found in a data breach that included passwords.",
                "icon":     "🔑",
            })

    if not monitors:
        actions.append({
            "priority": "high",
            "title":    "Add emails to Breach Monitor",
            "detail":   "You haven't set up breach monitoring. Add your email to get alerts.",
            "icon":     "📧",
        })

    breakdown["breach"] = {
        "score":    breach_score,
        "max":      25,
        "monitors": len(monitors),
        "breaches": total_breaches,
    }

    # ── 2. Network Posture (0-25) ──────────────────────────────────
    network_score = 25
    latest_scan_r = await db.execute(
        select(Scan)
        .where(Scan.org_id == org_id, Scan.status == "completed")
        .order_by(Scan.started_at.desc())
        .limit(1)
    )
    latest_scan = latest_scan_r.scalar_one_or_none()

    if latest_scan:
        sev_r = await db.execute(
            select(Finding.severity, func.count(Finding.id))
            .where(Finding.scan_id == latest_scan.id)
            .group_by(Finding.severity)
        )
        sev_counts = dict(sev_r.fetchall())
        crit  = sev_counts.get(4, 0)
        high  = sev_counts.get(3, 0)
        med   = sev_counts.get(2, 0)

        penalty = min(23, crit * 8 + high * 3 + med * 1)
        network_score = max(2, 25 - penalty)

        if crit > 0:
            actions.append({
                "priority": "critical",
                "title":    f"Fix {crit} critical vulnerabilit{'y' if crit == 1 else 'ies'}",
                "detail":   f"Your last scan found {crit} critical issue(s) that need immediate attention.",
                "icon":     "🚨",
            })
        if high > 0:
            actions.append({
                "priority": "high",
                "title":    f"Address {high} high-severity finding{'s' if high > 1 else ''}",
                "detail":   "High severity issues should be remediated within 7 days.",
                "icon":     "⚠️",
            })

        scan_age_days = (datetime.now(timezone.utc) - latest_scan.started_at).days if latest_scan.started_at else 999
        if scan_age_days > 30:
            network_score = max(5, network_score - 5)
            actions.append({
                "priority": "medium",
                "title":    "Run a network scan — last one was over 30 days ago",
                "detail":   "Regular scanning catches new vulnerabilities before attackers do.",
                "icon":     "🔍",
            })
    else:
        network_score = 10
        actions.append({
            "priority": "high",
            "title":    "Run your first network scan",
            "detail":   "You haven't scanned your network yet. Start with a quick scan of your home IP.",
            "icon":     "🌐",
        })

    breakdown["network"] = {
        "score":       network_score,
        "max":         25,
        "last_scan_id": str(latest_scan.id) if latest_scan else None,
    }

    # ── 3. Exposure (0-25) ─────────────────────────────────────────
    exposure_score = 25
    fp_r = await db.execute(
        select(FootprintScan)
        .where(FootprintScan.org_id == org_id, FootprintScan.status == "done")
        .order_by(FootprintScan.created_at.desc())
        .limit(3)
    )
    fp_scans = fp_r.scalars().all()

    if fp_scans:
        max_exposure = max(s.exposure_score for s in fp_scans)
        exposure_score = max(2, 25 - int(max_exposure * 0.25))
        if max_exposure >= 60:
            actions.append({
                "priority": "high",
                "title":    "Your personal data is widely exposed",
                "detail":   f"Data brokers have your information. Use the Footprint Scanner to request opt-outs.",
                "icon":     "👤",
            })
    else:
        exposure_score = 15
        actions.append({
            "priority": "medium",
            "title":    "Scan your digital footprint",
            "detail":   "Find out which data brokers are selling your personal information.",
            "icon":     "🕵️",
        })

    breakdown["exposure"] = {
        "score":          exposure_score,
        "max":            25,
        "scans_done":     len(fp_scans),
    }

    # ── 4. Hygiene (0-25) ──────────────────────────────────────────
    # Driven by analysis results: SSL validity, email auth, URL safety
    from models.tables import AnalysisResult
    hygiene_score = 20  # default reasonable value
    recent_analysis_r = await db.execute(
        select(AnalysisResult)
        .where(AnalysisResult.org_id == org_id)
        .order_by(AnalysisResult.created_at.desc())
        .limit(10)
    )
    recent_analyses = recent_analysis_r.scalars().all()

    if recent_analyses:
        avg_risk = sum(a.risk_score for a in recent_analyses) / len(recent_analyses)
        hygiene_score = max(5, 25 - int(avg_risk * 0.25))
        suspicious = [a for a in recent_analyses if a.verdict in ("suspicious", "malicious")]
        if suspicious:
            actions.append({
                "priority": "high",
                "title":    f"{len(suspicious)} suspicious link/email interaction(s)",
                "detail":   "You've analysed content recently flagged as suspicious. Stay vigilant.",
                "icon":     "🎣",
            })
    else:
        actions.append({
            "priority": "low",
            "title":    "Analyse suspicious links before clicking",
            "detail":   "Use the Link Analyzer to check URLs before you open them.",
            "icon":     "🔗",
        })

    breakdown["hygiene"] = {
        "score":   hygiene_score,
        "max":     25,
        "analyses": len(recent_analyses),
    }

    # ── Total ──────────────────────────────────────────────────────
    total = breach_score + network_score + exposure_score + hygiene_score
    grade = _grade(total)

    # Sort actions: critical → high → medium → low
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    actions.sort(key=lambda a: order.get(a["priority"], 9))

    return {
        "score":     total,
        "grade":     grade,
        "breakdown": breakdown,
        "actions":   actions[:6],  # top 6 most important
        "computed_at": datetime.now(timezone.utc).isoformat(),
    }
