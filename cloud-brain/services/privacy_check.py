"""Privacy Check service — IP info, VPN/proxy detection, DNS resolver identification."""
from __future__ import annotations

import asyncio
import socket
from typing import Any

import httpx

# ── Known privacy-friendly DNS resolvers ─────────────────────────────────────
_PRIVACY_DNS: dict[str, str] = {
    "1.1.1.1":       "Cloudflare (1.1.1.1) — private, no logging",
    "1.0.0.1":       "Cloudflare (1.0.0.1) — private, no logging",
    "8.8.8.8":       "Google DNS — logs queries",
    "8.8.4.4":       "Google DNS — logs queries",
    "9.9.9.9":       "Quad9 — blocks malicious domains",
    "149.112.112.112":"Quad9 — blocks malicious domains",
    "208.67.222.222": "OpenDNS — logs queries, parental controls",
    "208.67.220.220": "OpenDNS — logs queries",
    "185.228.168.9":  "CleanBrowsing — family filter",
    "76.76.19.19":    "Alternate DNS — ad-blocking",
    "94.140.14.14":   "AdGuard DNS — ad-blocking",
    "94.140.15.15":   "AdGuard DNS — ad-blocking",
}

_PRIVACY_SCORES: dict[str, int] = {
    "1.1.1.1": 90, "1.0.0.1": 90,
    "9.9.9.9": 85, "149.112.112.112": 85,
    "94.140.14.14": 80, "94.140.15.15": 80,
    "76.76.19.19": 75,
    "208.67.222.222": 60, "208.67.220.220": 60,
    "8.8.8.8": 50, "8.8.4.4": 50,
}

# ISPs that are known VPN providers (partial list of ASN prefixes/org names)
_VPN_SIGNALS = [
    "vpn", "tunnel", "proxy", "datacenter", "data center", "hosting",
    "cloudflare", "digitalocean", "linode", "vultr", "amazon", "aws",
    "google cloud", "microsoft azure", "hetzner", "ovh", "leaseweb",
    "mullvad", "nordvpn", "expressvpn", "surfshark", "private internet",
    "protonvpn", "torguard", "ipvanish", "hidemyass", "windscribe",
]

_TOR_EXIT_LIST_URL = "https://check.torproject.org/torbulkexitlist"


async def lookup_ip(ip: str) -> dict:
    """
    Full IP intelligence lookup using ip-api.com (free, no key required).
    Returns geo, ISP, proxy/VPN/Tor/hosting flags, and privacy assessment.
    """
    result: dict = {
        "ip": ip,
        "country": None,
        "country_code": None,
        "region": None,
        "city": None,
        "timezone": None,
        "isp": None,
        "org": None,
        "asn": None,
        "is_proxy": False,
        "is_hosting": False,
        "is_mobile": False,
        "is_vpn_likely": False,
        "is_tor": False,
        "threat_level": "low",
        "threat_reasons": [],
        "privacy_score": 100,
        "error": None,
    }

    try:
        async with httpx.AsyncClient(timeout=8) as client:
            fields = "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,hosting,proxy,mobile,query"
            resp = await client.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": fields},
            )
            data = resp.json()

        if data.get("status") != "success":
            result["error"] = data.get("message", "Lookup failed")
            return result

        result.update({
            "ip":           data.get("query", ip),
            "country":      data.get("country"),
            "country_code": data.get("countryCode"),
            "region":       data.get("regionName"),
            "city":         data.get("city"),
            "timezone":     data.get("timezone"),
            "isp":          data.get("isp"),
            "org":          data.get("org"),
            "asn":          data.get("as"),
            "is_proxy":     data.get("proxy", False),
            "is_hosting":   data.get("hosting", False),
            "is_mobile":    data.get("mobile", False),
        })

        # Threat assessment
        reasons = []
        score   = 100

        if result["is_proxy"]:
            reasons.append("IP is flagged as a proxy/VPN by ip-api.com")
            score -= 30

        if result["is_hosting"]:
            reasons.append("IP belongs to a hosting/datacenter provider")
            score -= 20

        # Check org/ISP name against VPN signals
        org_lower = (result["org"] or "").lower() + " " + (result["isp"] or "").lower()
        for sig in _VPN_SIGNALS:
            if sig in org_lower:
                result["is_vpn_likely"] = True
                reasons.append(f"Organization name suggests VPN/hosting: {result['org'] or result['isp']}")
                score -= 15
                break

        result["threat_reasons"] = reasons
        result["privacy_score"]  = max(0, score)

        if score <= 40:
            result["threat_level"] = "high"
        elif score <= 70:
            result["threat_level"] = "medium"
        else:
            result["threat_level"] = "low"

    except Exception as e:
        result["error"] = str(e)

    return result


async def identify_dns_resolvers() -> dict:
    """
    Identify the DNS resolvers that the server is using.
    Returns a list with privacy assessment.
    """
    resolvers: list[str] = []
    try:
        import dns.resolver as _res
        cfg = _res.Resolver()
        resolvers = list(cfg.nameservers or [])
    except Exception:
        # Fallback: parse /etc/resolv.conf
        try:
            with open("/etc/resolv.conf") as f:
                for line in f:
                    if line.startswith("nameserver"):
                        resolvers.append(line.split()[1])
        except Exception:
            pass

    resolver_info = []
    for ip in resolvers[:6]:
        label = _PRIVACY_DNS.get(ip)
        score = _PRIVACY_SCORES.get(ip, 40)
        # Try reverse DNS for unknown resolvers
        if not label:
            try:
                loop  = asyncio.get_event_loop()
                rdns  = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
                label = rdns[0]
            except Exception:
                label = "Unknown resolver"
        resolver_info.append({"ip": ip, "label": label, "privacy_score": score})

    return {
        "resolvers":   resolver_info,
        "count":       len(resolver_info),
        "assessment":  _assess_resolvers(resolver_info),
    }


def _assess_resolvers(resolvers: list[dict]) -> str:
    if not resolvers:
        return "Could not determine DNS resolvers."
    scores = [r["privacy_score"] for r in resolvers]
    avg    = sum(scores) / len(scores)
    if avg >= 85:
        return "Excellent — using a privacy-respecting DNS resolver."
    if avg >= 70:
        return "Good — DNS is relatively private."
    if avg >= 50:
        return "Moderate — consider switching to a more private resolver like Cloudflare (1.1.1.1) or Quad9 (9.9.9.9)."
    return "Weak — your DNS resolver may be logging your browsing activity. Switch to 1.1.1.1 or 9.9.9.9."
