"""Inbound email parsing for support tickets via SendGrid Inbound Parse."""
from email import message_from_bytes
from email.utils import parseaddr


def parse_inbound_email(raw_payload: dict) -> dict:
    """Parse SendGrid Inbound Parse webhook payload into a ticket dict."""
    return {
        "from_name": parseaddr(raw_payload.get("from", ""))[0],
        "from_email": parseaddr(raw_payload.get("from", ""))[1],
        "subject": raw_payload.get("subject", ""),
        "text": raw_payload.get("text", "") or raw_payload.get("html", ""),
        "attachments": int(raw_payload.get("attachments", 0)),
    }
