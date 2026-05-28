"""Slack integration for the support agent — receive tickets via Slack events."""
import hmac
import hashlib
import time
from fastapi import Request, HTTPException


def verify_slack_signature(request_body: bytes, timestamp: str, signature: str, signing_secret: str) -> bool:
    if abs(time.time() - int(timestamp)) > 300:
        return False
    base = f"v0:{timestamp}:{request_body.decode()}"
    expected = "v0=" + hmac.new(signing_secret.encode(), base.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def parse_slack_event(payload: dict) -> dict | None:
    """Extract ticket info from a Slack app_mention or message event."""
    event = payload.get("event", {})
    if event.get("type") not in ("app_mention", "message"):
        return None
    return {
        "text": event.get("text", ""),
        "user": event.get("user"),
        "channel": event.get("channel"),
        "thread_ts": event.get("thread_ts") or event.get("ts"),
    }
