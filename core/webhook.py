import os
import httpx
from typing import Optional


async def send_slack_notification(webhook_url: str, message: str, blocks: list = None):
    payload = {"text": message}
    if blocks:
        payload["blocks"] = blocks
    async with httpx.AsyncClient() as client:
        await client.post(webhook_url, json=payload, timeout=10)


async def send_email_notification(to: str, subject: str, body: str):
    """Send via SendGrid. Set SENDGRID_API_KEY env var."""
    api_key = os.environ.get("SENDGRID_API_KEY")
    if not api_key:
        return
    async with httpx.AsyncClient() as client:
        await client.post(
            "https://api.sendgrid.com/v3/mail/send",
            headers={"Authorization": f"Bearer {api_key}"},
            json={
                "personalizations": [{"to": [{"email": to}]}],
                "from": {"email": os.environ.get("FROM_EMAIL", "noreply@xarex.io")},
                "subject": subject,
                "content": [{"type": "text/html", "value": body}],
            },
            timeout=10,
        )


def build_scan_complete_blocks(scan_id: str, target: str, vuln_count: int, report_url: str) -> list:
    return [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "Xarex Scan Complete"},
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Target:*\n{target}"},
                {"type": "mrkdwn", "text": f"*Vulnerabilities Found:*\n{vuln_count}"},
            ],
        },
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "View Report"},
                    "url": report_url,
                    "style": "primary",
                }
            ],
        },
    ]
