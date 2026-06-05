"""Notifier — real-time alerting for critical findings and scan events.

Supports:
  - Slack (incoming webhook)
  - Generic webhook (JSON POST)
  - Console log fallback

Triggered by:
  - Critical (severity 4) or High (severity 3) finding discovered
  - Scan completed
  - Probe goes offline
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

import httpx
import structlog

from config import settings

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

logger = structlog.get_logger(__name__)

SEV_EMOJI = {4: ":red_circle:", 3: ":orange_circle:", 2: ":yellow_circle:", 1: ":blue_circle:", 0: ":white_circle:"}
SEV_LABEL = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "INFO"}
SEV_COLOR = {4: "#f04f59", 3: "#f0853a", 2: "#f0c93a", 1: "#4fc9f0", 0: "#8b90a7"}


class Notifier:
    """Dispatches notifications to configured channels."""

    def __init__(self) -> None:
        self._client = httpx.AsyncClient(timeout=10.0)

    # ──────────────────────────────────────────────
    #  Public API
    # ──────────────────────────────────────────────

    async def notify_critical_finding(self, finding: Any) -> None:
        """Alert when a critical or high-severity finding is discovered."""
        if not settings.NOTIFY_ON_CRITICAL:
            return
        if finding.severity < 3:
            return

        title = f"{SEV_EMOJI.get(finding.severity, ':white_circle:')} {SEV_LABEL.get(finding.severity, 'UNKNOWN')} Finding: {finding.title}"
        body_lines = [
            f"*Host:* `{finding.host}`" + (f":{finding.port}" if finding.port else ""),
            f"*Service:* {finding.service or '—'}",
            f"*CVE:* {finding.cve_id or '—'}",
            f"*CVSS:* {(finding.metadata_ or {}).get('cvss_score', '—')}",
            "",
            f"*Description:* {(finding.description or '')[:300]}",
            "",
            f"*Remediation:* {(finding.remediation or '')[:200]}",
        ]

        payload = self._build_slack_payload(
            title=title,
            body="\n".join(body_lines),
            color=SEV_COLOR.get(finding.severity, "#8b90a7"),
            fields={
                "Scan ID": finding.scan_id[:8],
                "Severity": SEV_LABEL.get(finding.severity, "?"),
                "Timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            },
        )

        await self._dispatch(payload, source=f"finding:{finding.id}")

    async def notify_scan_complete(self, scan_id: str, db: "AsyncSession") -> None:
        """Send a scan-complete summary notification."""
        if not settings.NOTIFY_ON_SCAN_COMPLETE:
            return

        from sqlalchemy import select, func
        from models.tables import Finding, Scan

        scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = scan_result.scalar_one_or_none()
        if not scan:
            return

        # Count by severity
        counts = {}
        for sev in range(5):
            count_result = await db.execute(
                select(func.count()).select_from(Finding)
                .where(Finding.scan_id == scan_id, Finding.severity == sev)
            )
            counts[sev] = count_result.scalar_one()

        title = f":checkered_flag: Scan Complete: *{scan.name}*"
        duration_str = "—"
        if scan.started_at and scan.completed_at:
            delta = scan.completed_at - scan.started_at
            mins = int(delta.total_seconds() / 60)
            secs = int(delta.total_seconds() % 60)
            duration_str = f"{mins}m {secs}s"

        body = (
            f"*Duration:* {duration_str}\n"
            f"*Findings:*  "
            f":red_circle: {counts[4]} Critical  "
            f":orange_circle: {counts[3]} High  "
            f":yellow_circle: {counts[2]} Medium  "
            f":blue_circle: {counts[1]} Low  "
            f":white_circle: {counts[0]} Info"
        )

        payload = self._build_slack_payload(
            title=title,
            body=body,
            color="#4cf098",
            fields={
                "Scan ID": scan_id[:8],
                "Probe": scan.probe_id[:16],
                "Total Findings": str(sum(counts.values())),
            },
        )

        await self._dispatch(payload, source=f"scan_complete:{scan_id}")

    async def notify_probe_offline(self, probe_id: str, org_id: str) -> None:
        """Alert when a probe stops sending heartbeats."""
        payload = self._build_slack_payload(
            title=f":warning: Probe Offline: `{probe_id[:16]}`",
            body="The probe has stopped sending heartbeats. Network connectivity may be lost.",
            color="#f0853a",
            fields={"Probe ID": probe_id[:16], "Org": org_id[:8]},
        )
        await self._dispatch(payload, source=f"probe_offline:{probe_id}")

    # ──────────────────────────────────────────────
    #  Dispatch
    # ──────────────────────────────────────────────

    async def _dispatch(self, payload: dict[str, Any], source: str) -> None:
        """Send to all configured channels."""
        tasks = []

        if settings.SLACK_WEBHOOK_URL:
            tasks.append(self._post_slack(settings.SLACK_WEBHOOK_URL, payload))

        if settings.TEAMS_WEBHOOK_URL:
            tasks.append(self._post_teams(settings.TEAMS_WEBHOOK_URL, payload))

        if settings.WEBHOOK_URL:
            tasks.append(self._post_generic(settings.WEBHOOK_URL, payload))

        if not tasks:
            logger.info("Notification (no channels configured)", source=source, title=payload.get("text", ""))
            return

        import asyncio
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                logger.warning("Notification dispatch error", source=source, error=str(r))

    async def _post_slack(self, url: str, payload: dict[str, Any]) -> None:
        resp = await self._client.post(url, json=payload)
        resp.raise_for_status()
        logger.info("Slack notification sent")

    async def _post_teams(self, url: str, payload: dict[str, Any]) -> None:
        """Convert Slack-style attachment payload to Microsoft Teams Adaptive Card."""
        attachment = payload.get("attachments", [{}])[0]
        teams_payload = {
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {
                            "type": "TextBlock",
                            "text": attachment.get("title", "Xarex Alert"),
                            "weight": "Bolder",
                            "size": "Medium",
                            "color": "Attention" if "#f04f59" in attachment.get("color", "") else "Default",
                        },
                        {
                            "type": "TextBlock",
                            "text": attachment.get("text", ""),
                            "wrap": True,
                        },
                    ],
                    "msteams": {"width": "Full"},
                },
            }],
        }
        resp = await self._client.post(url, json=teams_payload, headers={"Content-Type": "application/json"})
        resp.raise_for_status()
        logger.info("Teams notification sent")

    async def _post_generic(self, url: str, payload: dict[str, Any]) -> None:
        resp = await self._client.post(url, json=payload, headers={"Content-Type": "application/json"})
        resp.raise_for_status()
        logger.info("Webhook notification sent", url=url)

    # ──────────────────────────────────────────────
    #  Payload builders
    # ──────────────────────────────────────────────

    def _build_slack_payload(
        self,
        title: str,
        body: str,
        color: str = "#7c6af7",
        fields: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        attachment: dict[str, Any] = {
            "color": color,
            "title": title,
            "text": body,
            "footer": "Xarex Autonomous Pentest Platform",
            "ts": int(datetime.now(timezone.utc).timestamp()),
        }

        if fields:
            attachment["fields"] = [
                {"title": k, "value": v, "short": True}
                for k, v in fields.items()
            ]

        return {"attachments": [attachment]}
