"""Domain Guardian — SSL, DNS health, WHOIS expiry, lookalike detection."""
from __future__ import annotations

import asyncio
import itertools
import socket
import ssl
import string
from datetime import datetime, timezone, timedelta
from typing import Any

import dns.resolver
import httpx

# ── Lookalike generation ──────────────────────────────────────────────────────

_COMMON_TLDS = ["com", "net", "org", "io", "co", "info", "biz", "us", "uk", "de", "app"]

_HOMOGLYPHS: dict[str, list[str]] = {
    "a": ["à", "á", "â", "ã", "ä", "å", "ɑ", "α"],
    "c": ["ç", "ć", "č"],
    "e": ["è", "é", "ê", "ë", "ε"],
    "i": ["ì", "í", "î", "ï", "1", "l"],
    "l": ["1", "i", "ĺ", "ļ"],
    "o": ["0", "ò", "ó", "ô", "õ", "ö", "ø"],
    "s": ["5", "ś", "š"],
    "u": ["ù", "ú", "û", "ü"],
}


def _generate_lookalikes(domain: str) -> list[str]:
    """Generate a targeted list of lookalike domain names for a given domain."""
    name, _, tld = domain.partition(".")
    candidates: set[str] = set()

    # 1. TLD swaps
    for alt_tld in _COMMON_TLDS:
        if alt_tld != tld:
            candidates.add(f"{name}.{alt_tld}")

    # 2. Common prefixes / suffixes
    for affix in ["secure", "login", "account", "app", "my", "portal", "mail", "support", "pay"]:
        candidates.add(f"{affix}-{name}.{tld}")
        candidates.add(f"{name}-{affix}.{tld}")
        candidates.add(f"{affix}{name}.{tld}")
        candidates.add(f"{name}{affix}.{tld}")

    # 3. Character omission (drop each char once)
    for i in range(len(name)):
        variant = name[:i] + name[i+1:]
        if len(variant) >= 3:
            candidates.add(f"{variant}.{tld}")

    # 4. Character doubling
    for i in range(len(name)):
        variant = name[:i] + name[i] + name[i:]
        candidates.add(f"{variant}.{tld}")

    # 5. Adjacent-key transpositions
    for i in range(len(name) - 1):
        variant = name[:i] + name[i+1] + name[i] + name[i+2:]
        candidates.add(f"{variant}.{tld}")

    # 6. Hyphen insertion
    for i in range(1, len(name)):
        candidates.add(f"{name[:i]}-{name[i:]}.{tld}")

    # Keep to a reasonable maximum; remove the real domain
    candidates.discard(domain)
    return sorted(candidates)[:120]


async def _is_domain_registered(domain: str, client: httpx.AsyncClient) -> bool:
    """Quick RDAP check — returns True if the domain appears to be registered."""
    # First try DNS resolution (fastest signal)
    try:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, socket.gethostbyname, domain)
        return True
    except Exception:
        pass
    # Fallback: RDAP lookup
    try:
        tld = domain.rsplit(".", 1)[-1]
        resp = await client.get(
            f"https://rdap.verisign.com/com/v1/domain/{domain}",
            timeout=4,
        )
        return resp.status_code == 200
    except Exception:
        return False


# ── SSL check ─────────────────────────────────────────────────────────────────

async def check_ssl(domain: str) -> dict:
    """Return SSL certificate details for a domain."""
    result: dict = {
        "valid": False,
        "issuer": None,
        "subject": None,
        "expires_at": None,
        "days_remaining": None,
        "error": None,
    }
    try:
        ctx = ssl.create_default_context()
        loop = asyncio.get_event_loop()

        def _get_cert():
            with ctx.wrap_socket(
                socket.create_connection((domain, 443), timeout=8),
                server_hostname=domain,
            ) as s:
                return s.getpeercert()

        cert = await loop.run_in_executor(None, _get_cert)
        if not cert:
            result["error"] = "No certificate returned"
            return result

        not_after_str = cert.get("notAfter", "")
        if not_after_str:
            expires = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_remaining = (expires - datetime.now(timezone.utc)).days
            result["expires_at"]     = expires.isoformat()
            result["days_remaining"] = days_remaining
            result["valid"]          = days_remaining > 0

        issuer_dict  = dict(x[0] for x in cert.get("issuer", []))
        subject_dict = dict(x[0] for x in cert.get("subject", []))
        result["issuer"]  = issuer_dict.get("organizationName") or issuer_dict.get("commonName")
        result["subject"] = subject_dict.get("commonName")

    except ssl.CertificateError as e:
        result["error"] = f"Certificate error: {e}"
    except Exception as e:
        result["error"] = str(e)

    return result


# ── DNS health check ──────────────────────────────────────────────────────────

def _txt_records(domain: str, resolver: dns.resolver.Resolver) -> list[str]:
    try:
        answers = resolver.resolve(domain, "TXT", lifetime=6)
        return [b.decode() for rdata in answers for b in rdata.strings]
    except Exception:
        return []


def _mx_records(domain: str, resolver: dns.resolver.Resolver) -> list[str]:
    try:
        answers = resolver.resolve(domain, "MX", lifetime=6)
        return [str(r.exchange).rstrip(".") for r in answers]
    except Exception:
        return []


def _ns_records(domain: str, resolver: dns.resolver.Resolver) -> list[str]:
    try:
        answers = resolver.resolve(domain, "NS", lifetime=6)
        return [str(r.target).rstrip(".") for r in answers]
    except Exception:
        return []


def check_dns_health(domain: str) -> dict:
    resolver = dns.resolver.Resolver()
    resolver.timeout  = 5
    resolver.lifetime = 8

    txt = _txt_records(domain, resolver)

    # SPF
    spf_records = [r for r in txt if r.lower().startswith("v=spf1")]
    spf_valid   = bool(spf_records)
    spf_value   = spf_records[0] if spf_records else None

    # DMARC
    dmarc_txt   = _txt_records(f"_dmarc.{domain}", resolver)
    dmarc_records = [r for r in dmarc_txt if r.lower().startswith("v=dmarc1")]
    dmarc_valid = bool(dmarc_records)
    dmarc_policy = None
    if dmarc_records:
        for part in dmarc_records[0].split(";"):
            part = part.strip()
            if part.lower().startswith("p="):
                dmarc_policy = part.split("=", 1)[1].strip().lower()

    # DKIM (check common selectors)
    dkim_valid    = False
    dkim_selector = None
    for sel in ["default", "google", "mail", "k1", "selector1", "selector2", "dkim", "email"]:
        records = _txt_records(f"{sel}._domainkey.{domain}", resolver)
        if any("v=DKIM1" in r for r in records):
            dkim_valid    = True
            dkim_selector = sel
            break

    # MX + NS
    mx = _mx_records(domain, resolver)
    ns = _ns_records(domain, resolver)

    # CAA
    caa = []
    try:
        answers = resolver.resolve(domain, "CAA", lifetime=5)
        caa = [f"{r.flags} {r.tag} {r.value.decode()}" for r in answers]
    except Exception:
        pass

    issues = []
    if not spf_valid:
        issues.append({"severity": "high", "title": "No SPF record",
                       "desc": "Without SPF, anyone can send email pretending to be from your domain."})
    if not dmarc_valid:
        issues.append({"severity": "high", "title": "No DMARC policy",
                       "desc": "DMARC tells receiving servers what to do with spoofed emails. Without it, phishing from your domain is easier."})
    elif dmarc_policy == "none":
        issues.append({"severity": "medium", "title": "DMARC policy is 'none' (monitor only)",
                       "desc": "Your DMARC record is set to 'p=none' — it monitors but doesn't block spoofed emails. Consider 'quarantine' or 'reject'."})
    if not dkim_valid:
        issues.append({"severity": "medium", "title": "No DKIM signature found",
                       "desc": "DKIM cryptographically signs outgoing emails. Without it, emails may be marked as spam or spoofed."})
    if not mx:
        issues.append({"severity": "info", "title": "No MX records",
                       "desc": "This domain cannot receive email. If intentional, add a null MX record to prevent abuse."})
    if not caa:
        issues.append({"severity": "low", "title": "No CAA record",
                       "desc": "CAA records restrict which Certificate Authorities can issue SSL certs for your domain, reducing mis-issuance risk."})

    return {
        "spf_valid":    spf_valid,
        "spf_value":    spf_value,
        "dmarc_valid":  dmarc_valid,
        "dmarc_policy": dmarc_policy,
        "dkim_valid":   dkim_valid,
        "dkim_selector":dkim_selector,
        "mx_records":   mx,
        "ns_records":   ns,
        "caa_records":  caa,
        "issues":       issues,
    }


# ── WHOIS expiry ──────────────────────────────────────────────────────────────

async def check_whois(domain: str) -> dict:
    result = {"registrar": None, "expires_at": None, "days_remaining": None, "error": None}
    try:
        import whois as _whois
        loop  = asyncio.get_event_loop()
        data  = await loop.run_in_executor(None, _whois.whois, domain)
        exp   = data.expiration_date
        if isinstance(exp, list):
            exp = exp[0]
        if exp:
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            result["expires_at"]     = exp.isoformat()
            result["days_remaining"] = (exp - datetime.now(timezone.utc)).days
        result["registrar"] = getattr(data, "registrar", None)
    except Exception as e:
        result["error"] = str(e)
    return result


# ── Full domain check ─────────────────────────────────────────────────────────

async def run_domain_check(domain: str) -> dict:
    """Run all checks for a domain concurrently. Returns consolidated result dict."""
    domain = domain.lower().strip().removeprefix("https://").removeprefix("http://").split("/")[0]

    ssl_task   = asyncio.create_task(check_ssl(domain))
    whois_task = asyncio.create_task(check_whois(domain))

    loop = asyncio.get_event_loop()
    dns_result = await loop.run_in_executor(None, check_dns_health, domain)
    ssl_result, whois_result = await asyncio.gather(ssl_task, whois_task, return_exceptions=True)

    if isinstance(ssl_result, Exception):
        ssl_result = {"valid": False, "error": str(ssl_result)}
    if isinstance(whois_result, Exception):
        whois_result = {"error": str(whois_result)}

    # Lookalike scan (fire in background, return count + sample)
    lookalikes_found: list[str] = []
    try:
        candidates = _generate_lookalikes(domain)
        async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=4) as client:
            tasks = [_is_domain_registered(c, client) for c in candidates[:80]]
            results = await asyncio.gather(*tasks, return_exceptions=True)
        lookalikes_found = [c for c, r in zip(candidates[:80], results) if r is True]
    except Exception:
        pass

    # Aggregate issues
    all_issues = list(dns_result.get("issues", []))

    ssl_days = ssl_result.get("days_remaining")
    if ssl_days is not None:
        if ssl_days <= 0:
            all_issues.insert(0, {"severity": "critical", "title": "SSL Certificate Expired",
                                   "desc": f"Your SSL certificate expired {abs(ssl_days)} day(s) ago. Visitors will see a security warning."})
        elif ssl_days <= 14:
            all_issues.insert(0, {"severity": "high", "title": f"SSL Certificate Expires in {ssl_days} Days",
                                   "desc": "Renew your certificate immediately to avoid a browser security warning."})
        elif ssl_days <= 30:
            all_issues.append({"severity": "medium", "title": f"SSL Certificate Expires Soon ({ssl_days} days)",
                                "desc": "Schedule a certificate renewal in the next few weeks."})
    elif ssl_result.get("error"):
        all_issues.append({"severity": "high", "title": "Could Not Verify SSL Certificate",
                           "desc": ssl_result["error"]})

    whois_days = whois_result.get("days_remaining")
    if whois_days is not None:
        if whois_days <= 30:
            sev = "critical" if whois_days <= 7 else "high" if whois_days <= 14 else "medium"
            all_issues.append({"severity": sev, "title": f"Domain Expires in {whois_days} Days",
                               "desc": "Renew your domain immediately to prevent it from being snapped up by someone else."})

    if lookalikes_found:
        all_issues.append({
            "severity": "medium",
            "title": f"{len(lookalikes_found)} Lookalike Domain{'' if len(lookalikes_found)==1 else 's'} Registered",
            "desc": f"Domains that look like yours are registered: {', '.join(lookalikes_found[:5])}{'…' if len(lookalikes_found)>5 else ''}. These could be used for phishing.",
        })

    # Overall health score
    sev_weights = {"critical": 30, "high": 15, "medium": 8, "low": 3, "info": 1}
    deduction   = sum(sev_weights.get(i["severity"], 0) for i in all_issues)
    health_score = max(0, 100 - deduction)

    return {
        "domain":          domain,
        "health_score":    health_score,
        "ssl":             ssl_result,
        "dns":             dns_result,
        "whois":           whois_result,
        "lookalikes":      lookalikes_found,
        "lookalike_count": len(lookalikes_found),
        "issues":          all_issues,
        "checked_at":      datetime.now(timezone.utc).isoformat(),
    }
