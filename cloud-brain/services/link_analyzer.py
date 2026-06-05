"""Link & Email Analyzer service.

Analyses URLs and raw email text for phishing indicators, domain age,
SSL health, redirect chains, and reputation signals.
"""
from __future__ import annotations

import re
import ssl
import socket
import asyncio
from datetime import datetime, timezone, date
from email import message_from_string
from email.header import decode_header
from typing import Any
from urllib.parse import urlparse

import httpx
import structlog

from config import settings

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# URL Analyzer
# ---------------------------------------------------------------------------

# Known URL shorteners whose destination should always be followed
_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "short.io", "cutt.ly", "tiny.cc",
}

# Brand names whose typosquats indicate phishing
_IMPERSONATED_BRANDS = [
    "paypal", "apple", "amazon", "microsoft", "google", "netflix",
    "facebook", "instagram", "twitter", "linkedin", "dropbox",
    "onedrive", "sharepoint", "office365", "outlook", "icloud",
    "bankofamerica", "chase", "wellsfargo", "citibank", "hsbc",
    "dhl", "fedex", "ups", "usps",
]


async def analyze_url(url: str) -> dict[str, Any]:
    """Full analysis of a URL — returns verdict, risk_score, and breakdown."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower().lstrip("www.")
    result: dict[str, Any] = {
        "url":         url,
        "domain":      domain,
        "verdict":     "safe",
        "risk_score":  0,
        "checks":      {},
        "redirects":   [],
        "ssl":         {},
        "domain_info": {},
        "threats":     [],
    }

    checks = result["checks"]
    threats = result["threats"]
    score = 0

    # ── 1. Redirect chain ──────────────────────────────────────────
    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=8,
            headers={"User-Agent": settings.FOOTPRINT_USER_AGENT},
            verify=False,
        ) as client:
            resp = await client.get(url)
            chain = [str(r.url) for r in resp.history] + [str(resp.url)]
            result["redirects"] = chain
            final_domain = urlparse(str(resp.url)).netloc.lower().lstrip("www.")
            checks["reachable"] = {"ok": True, "status": resp.status_code}

            if domain in _SHORTENERS:
                score += 10
                threats.append("URL shortener used — destination hidden before click")

            if len(chain) > 3:
                score += 15
                threats.append(f"Unusual redirect chain ({len(chain)} hops)")

            if final_domain and final_domain != domain:
                result["final_domain"] = final_domain
                checks["redirect_mismatch"] = True
                score += 20
                threats.append(f"Redirects to different domain: {final_domain}")

    except Exception as exc:
        checks["reachable"] = {"ok": False, "error": str(exc)}
        score += 5

    # ── 2. SSL certificate ─────────────────────────────────────────
    ssl_info = await _check_ssl(domain)
    result["ssl"] = ssl_info
    if ssl_info.get("valid"):
        checks["ssl"] = {"ok": True}
        age_days = ssl_info.get("age_days", 0)
        if age_days is not None and age_days < 30:
            score += 20
            threats.append("SSL certificate is less than 30 days old — common in phishing")
    else:
        checks["ssl"] = {"ok": False}
        score += 25
        threats.append("Invalid or expired SSL certificate")

    # ── 3. URL structural analysis ─────────────────────────────────
    structural = _analyze_url_structure(url, domain)
    checks["structure"] = structural
    score += structural["risk_points"]
    threats.extend(structural["threats"])

    # ── 4. VirusTotal reputation (if key available) ─────────────────
    if settings.VIRUSTOTAL_API_KEY:
        vt = await _virustotal_url(url)
        result["virustotal"] = vt
        if vt.get("malicious", 0) > 0:
            score += min(40, vt["malicious"] * 10)
            threats.append(f"Flagged by {vt['malicious']} VirusTotal engines as malicious")
        elif vt.get("suspicious", 0) > 0:
            score += 15
            threats.append(f"Flagged by {vt['suspicious']} VirusTotal engines as suspicious")

    # ── 5. Google Safe Browsing (if key available) ──────────────────
    if settings.SAFE_BROWSING_KEY:
        sb = await _safe_browsing(url)
        result["safe_browsing"] = sb
        if sb.get("unsafe"):
            score += 50
            threats.append(f"Google Safe Browsing: {sb.get('threat_type', 'UNSAFE')}")

    # ── Verdict ────────────────────────────────────────────────────
    score = min(score, 100)
    result["risk_score"] = score
    result["verdict"] = (
        "malicious"   if score >= 70 else
        "suspicious"  if score >= 35 else
        "safe"
    )
    return result


def _analyze_url_structure(url: str, domain: str) -> dict[str, Any]:
    threats = []
    points = 0
    raw = domain.split(":")[0]  # strip port

    # IP address as host
    ip_re = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    if ip_re.match(raw):
        points += 30
        threats.append("URL uses a raw IP address instead of a domain name")

    # Excessive subdomains
    parts = raw.split(".")
    if len(parts) > 4:
        points += 15
        threats.append(f"Suspicious number of subdomains ({len(parts) - 2})")

    # Long URL
    if len(url) > 100:
        points += 5
        threats.append(f"Unusually long URL ({len(url)} chars)")

    # Special chars in domain
    if re.search(r"[%@!]", raw):
        points += 20
        threats.append("URL contains suspicious special characters")

    # Brand impersonation / lookalike detection
    for brand in _IMPERSONATED_BRANDS:
        if brand in raw and not raw.endswith(f"{brand}.com"):
            # e.g. paypal-secure.com, apple-id-verify.net
            points += 35
            threats.append(f"Domain may be impersonating '{brand}' (lookalike/typosquat)")
            break

    # Homograph / punycode
    if "xn--" in raw:
        points += 25
        threats.append("Punycode / homograph domain detected — visually mimics a legitimate domain")

    # HTTP (not HTTPS)
    if url.startswith("http://"):
        points += 15
        threats.append("Connection is unencrypted (HTTP)")

    return {"risk_points": points, "threats": threats}


async def _check_ssl(domain: str) -> dict[str, Any]:
    try:
        loop = asyncio.get_event_loop()
        ctx = ssl.create_default_context()

        def _do_ssl():
            conn = ctx.wrap_socket(
                socket.create_connection((domain, 443), timeout=settings.WHOIS_TIMEOUT),
                server_hostname=domain,
            )
            cert = conn.getpeercert()
            conn.close()
            return cert

        cert = await loop.run_in_executor(None, _do_ssl)
        not_after_str = cert.get("notAfter", "")
        not_before_str = cert.get("notBefore", "")
        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))

        not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc) if not_after_str else None
        not_before = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc) if not_before_str else None

        now = datetime.now(timezone.utc)
        age_days = (now - not_before).days if not_before else None
        expires_in = (not_after - now).days if not_after else None

        return {
            "valid":      True,
            "issuer":     issuer.get("organizationName", issuer.get("commonName", "")),
            "subject":    subject.get("commonName", ""),
            "expires":    not_after.isoformat() if not_after else None,
            "issued":     not_before.isoformat() if not_before else None,
            "age_days":   age_days,
            "expires_in": expires_in,
        }
    except ssl.SSLCertVerificationError:
        return {"valid": False, "error": "Certificate verification failed"}
    except Exception as exc:
        return {"valid": False, "error": str(exc)}


async def _virustotal_url(url: str) -> dict[str, Any]:
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
            )
            if resp.status_code == 404:
                # Submit for analysis
                submit = await client.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
                    data={"url": url},
                )
                return {"submitted": True, "malicious": 0, "suspicious": 0}
            resp.raise_for_status()
            stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "malicious":  stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless":   stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
            }
    except Exception as exc:
        return {"error": str(exc), "malicious": 0, "suspicious": 0}


async def _safe_browsing(url: str) -> dict[str, Any]:
    payload = {
        "client": {"clientId": "xarex", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes":      ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes":    ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries":    [{"url": url}],
        },
    }
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            resp = await client.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={settings.SAFE_BROWSING_KEY}",
                json=payload,
            )
            resp.raise_for_status()
            matches = resp.json().get("matches", [])
            if matches:
                return {"unsafe": True, "threat_type": matches[0].get("threatType", "UNSAFE")}
            return {"unsafe": False}
    except Exception as exc:
        return {"error": str(exc), "unsafe": False}


# ---------------------------------------------------------------------------
# Email Header Analyzer
# ---------------------------------------------------------------------------

async def analyze_email(raw_email: str) -> dict[str, Any]:
    """Parse a raw email and check authentication headers + embedded links."""
    result: dict[str, Any] = {
        "verdict":    "unknown",
        "risk_score": 0,
        "headers":    {},
        "auth":       {},
        "links":      [],
        "threats":    [],
        "summary":    "",
    }
    score = 0
    threats = result["threats"]

    try:
        msg = message_from_string(raw_email)
    except Exception:
        return {**result, "verdict": "error", "summary": "Could not parse email"}

    def _decode(val: str | None) -> str:
        if not val:
            return ""
        decoded, enc = decode_header(val)[0]
        if isinstance(decoded, bytes):
            return decoded.decode(enc or "utf-8", errors="replace")
        return str(decoded)

    result["headers"] = {
        "from":    _decode(msg.get("From")),
        "reply_to": _decode(msg.get("Reply-To")),
        "to":      _decode(msg.get("To")),
        "subject": _decode(msg.get("Subject")),
        "date":    msg.get("Date", ""),
        "message_id": msg.get("Message-ID", ""),
    }

    # ── Authentication Results header ──────────────────────────────
    auth_results = msg.get("Authentication-Results", "") or msg.get("ARC-Authentication-Results", "")
    auth = {"spf": "none", "dkim": "none", "dmarc": "none", "raw": auth_results}

    for line in auth_results.lower().split(";"):
        line = line.strip()
        if "spf="   in line: auth["spf"]   = _extract_result(line, "spf")
        if "dkim="  in line: auth["dkim"]  = _extract_result(line, "dkim")
        if "dmarc=" in line: auth["dmarc"] = _extract_result(line, "dmarc")

    result["auth"] = auth

    if auth["spf"] in ("fail", "softfail"):
        score += 30; threats.append("SPF check failed — sender not authorised by domain")
    elif auth["spf"] == "none":
        score += 10; threats.append("No SPF record found for sending domain")

    if auth["dkim"] == "fail":
        score += 30; threats.append("DKIM signature invalid — email may be tampered")
    elif auth["dkim"] == "none":
        score += 10; threats.append("Email not DKIM-signed")

    if auth["dmarc"] in ("fail", "none"):
        score += 20; threats.append("DMARC policy not enforced — spoofing risk")

    # ── From / Reply-To mismatch ────────────────────────────────────
    from_addr = result["headers"]["from"]
    reply_addr = result["headers"]["reply_to"]
    if reply_addr and reply_addr != from_addr:
        from_domain = re.search(r"@([\w.-]+)", from_addr)
        reply_domain = re.search(r"@([\w.-]+)", reply_addr)
        if from_domain and reply_domain and from_domain.group(1) != reply_domain.group(1):
            score += 25
            threats.append(f"Reply-To domain ({reply_domain.group(1)}) differs from From domain ({from_domain.group(1)})")

    # ── Extract and analyse links in body ──────────────────────────
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct in ("text/plain", "text/html"):
                try:
                    body += part.get_payload(decode=True).decode("utf-8", errors="replace")
                except Exception:
                    pass
    else:
        try:
            body = msg.get_payload(decode=True).decode("utf-8", errors="replace")
        except Exception:
            body = str(msg.get_payload())

    urls_found = list(set(re.findall(r"https?://[^\s\"'<>]+", body)))[:20]

    if urls_found:
        # Quick structural check on each link (no network call — fast)
        for u in urls_found:
            parsed = urlparse(u)
            domain = parsed.netloc.lower().lstrip("www.")
            struct = _analyze_url_structure(u, domain)
            result["links"].append({
                "url":         u,
                "domain":      domain,
                "risk_points": struct["risk_points"],
                "threats":     struct["threats"],
            })
        suspicious_links = [l for l in result["links"] if l["risk_points"] > 10]
        if suspicious_links:
            score += min(30, len(suspicious_links) * 10)
            threats.append(f"{len(suspicious_links)} suspicious link(s) detected in email body")

    # ── Urgency language ────────────────────────────────────────────
    urgency_words = ["urgent", "verify now", "account suspended", "click immediately",
                     "you have been selected", "act now", "limited time", "expires today",
                     "confirm your identity", "unusual activity", "security alert"]
    subject = result["headers"]["subject"].lower()
    body_lower = body.lower()[:2000]
    found = [w for w in urgency_words if w in subject or w in body_lower]
    if found:
        score += min(20, len(found) * 5)
        threats.append(f"Urgency language detected: {', '.join(found[:3])}")

    score = min(score, 100)
    result["risk_score"] = score
    result["verdict"] = (
        "malicious"   if score >= 70 else
        "suspicious"  if score >= 35 else
        "safe"
    )
    result["summary"] = _email_summary(result)
    return result


def _extract_result(line: str, protocol: str) -> str:
    m = re.search(rf"{protocol}=(\w+)", line)
    return m.group(1) if m else "none"


def _email_summary(result: dict) -> str:
    v = result["verdict"]
    score = result["risk_score"]
    n = len(result["threats"])
    if v == "malicious":
        return f"High risk ({score}/100) — {n} red flag(s). Do not interact with this email."
    if v == "suspicious":
        return f"Suspicious ({score}/100) — {n} warning(s). Verify with the sender before acting."
    return f"Appears safe ({score}/100). No major red flags detected."
