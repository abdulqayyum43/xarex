"""Home Guardian — translates technical findings to consumer-friendly language."""
from __future__ import annotations

import re
from typing import Any

# ── Device type fingerprinting ────────────────────────────────────────────────

_DEVICE_RULES: list[tuple[list[str], str, str]] = [
    # (port/service clues, device_type, icon)
    (["80","443","8080","8443","admin","http","nginx","apache","lighttpd"], "Router / Gateway", "🌐"),
    (["9100","515","631","ipp","lpd","printer"], "Printer", "🖨️"),
    (["554","1935","rtsp","8554","onvif"], "IP Camera / NVR", "📷"),
    (["5900","5901","vnc"], "Desktop / Workstation (VNC)", "🖥️"),
    (["3389","rdp"], "Windows PC / Server", "💻"),
    (["22","ssh"], "Server / NAS / Linux Device", "🖧"),
    (["445","139","smb","netbios"], "NAS / File Server", "💾"),
    (["548","afp"], "Mac / Apple Device", "🍎"),
    (["62078","lockdown","itunes"], "iPhone / iPad", "📱"),
    (["1883","8883","mqtt"], "Smart Home Hub / IoT", "🏠"),
    (["6668","6667","irc"], "Game Console / Media Server", "🎮"),
    (["5353","mdns"], "Apple / Bonjour Device", "📡"),
    (["1900","ssdp","upnp"], "Smart TV / Streaming Device", "📺"),
]

_SEVERITY_LABELS = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}

# ── Plain-English translations ─────────────────────────────────────────────────

_PLAIN_ENGLISH: list[tuple[re.Pattern, str, str]] = [
    # (title_pattern, plain_title, plain_desc)
    (re.compile(r"telnet|port.?23", re.I),
     "Telnet Access Is Open",
     "This device allows Telnet connections — an old protocol that transmits passwords in plain text. Anyone on your network could intercept your login credentials."),

    (re.compile(r"ftp|port.?21", re.I),
     "Unencrypted File Transfer (FTP) Exposed",
     "FTP is active on this device. It sends files and passwords without encryption, making them visible to anyone monitoring your network."),

    (re.compile(r"default.*(password|cred)|factory.*cred", re.I),
     "Default Password Still Set",
     "This device is using its factory-default username and password. Attackers know these defaults and can take full control of your device instantly."),

    (re.compile(r"http.*admin|admin.*http|web.*interface.*http", re.I),
     "Admin Page Not Using HTTPS",
     "The device's admin login page loads over regular HTTP, not HTTPS. Your password can be intercepted when you log in."),

    (re.compile(r"self.signed|expired.*cert|invalid.*cert|ssl.*error", re.I),
     "Security Certificate Problem",
     "This device has an invalid or self-signed security certificate. Encrypted connections to it cannot be fully trusted."),

    (re.compile(r"snmp.*public|snmp.*default|snmp.*community", re.I),
     "Network Management Protocol Exposed (SNMP)",
     "SNMP is open with a default community string ('public'). Attackers can read device configuration and potentially change settings."),

    (re.compile(r"smb|port.?445|port.?139", re.I),
     "Windows File Sharing Exposed",
     "Windows file sharing (SMB) is accessible. If not needed externally, this is a common entry point for ransomware."),

    (re.compile(r"rdp|remote.*desktop|port.?3389", re.I),
     "Remote Desktop Open to Network",
     "Remote Desktop Protocol (RDP) is accessible. This is frequently targeted by attackers attempting to gain control of your computer."),

    (re.compile(r"vnc|virtual.*network.*comput", re.I),
     "Remote Screen Access (VNC) Exposed",
     "VNC allows full visual control of this device. If not secured with a strong password, anyone on your network can take over the screen."),

    (re.compile(r"upnp|universal.*plug", re.I),
     "UPnP — Automatic Port Opening Enabled",
     "UPnP lets devices automatically open ports in your firewall without asking you. This has been exploited by malware to expose your network."),

    (re.compile(r"open.*port|unnecessary.*port|unused.*service", re.I),
     "Unnecessary Service Exposed",
     "A network service is running and visible on your network that doesn't need to be. Each extra service is a potential entry point for attackers."),

    (re.compile(r"cve-20", re.I),
     "Known Security Vulnerability (CVE)",
     "A publicly documented software vulnerability was found on this device. This means exploit code may already exist for it online."),

    (re.compile(r"ssh.*old|sshv1|ssh.*1\.", re.I),
     "Outdated SSH Version",
     "This device supports an old version of SSH (Secure Shell) that has known weaknesses. Upgrade to SSH version 2."),

    (re.compile(r"mysql|mssql|postgres|mongo|redis|database.*open", re.I),
     "Database Exposed on Network",
     "A database service is reachable from your local network. Databases should never be directly accessible unless strictly required."),
]


def _plain_english(title: str, description: str) -> tuple[str, str]:
    """Return consumer-friendly (title, description) for a technical finding."""
    combined = f"{title} {description}"
    for pattern, plain_title, plain_desc in _PLAIN_ENGLISH:
        if pattern.search(combined):
            return plain_title, plain_desc
    # Generic fallback: clean up technical jargon
    clean = re.sub(r"\b(CVSSv\d|CVSS|CWE-\d+|RFC\s?\d+)\b", "", title)
    clean = re.sub(r"[\[\(][^\]\)]{0,40}[\]\)]", "", clean).strip(" -:")
    return clean or title, description


def _detect_device(ports: list[int], services: list[str]) -> tuple[str, str]:
    """Guess the device type from its open ports and service banners."""
    combined = " ".join(str(p) for p in ports) + " " + " ".join(services).lower()
    for clues, dtype, icon in _DEVICE_RULES:
        if any(c in combined for c in clues):
            return dtype, icon
    return "Network Device", "📡"


def _risk_level(max_severity: int) -> tuple[str, str]:
    if max_severity >= 4: return "Critical", "#f04f59"
    if max_severity >= 3: return "High",     "#f0853a"
    if max_severity >= 2: return "Medium",   "#f0c03a"
    if max_severity >= 1: return "Low",      "#7c6af7"
    return "Minimal", "#3dd68c"


# ── Main formatter ─────────────────────────────────────────────────────────────

def format_guardian_scan(scan: Any, findings: list[Any]) -> dict:
    """
    Turn a raw Scan + Finding list into a consumer-friendly Home Guardian report.
    Returns a dict ready to JSON-serialize.
    """
    # Group findings by host
    hosts: dict[str, dict] = {}
    for f in findings:
        h = f.host
        if h not in hosts:
            hosts[h] = {
                "ip":            h,
                "ports":         [],
                "services":      [],
                "max_severity":  0,
                "findings":      [],
            }
        if f.port:
            hosts[h]["ports"].append(f.port)
        if f.service:
            hosts[h]["services"].append(f.service)
        if f.severity > hosts[h]["max_severity"]:
            hosts[h]["max_severity"] = f.severity

        plain_title, plain_desc = _plain_english(f.title, f.description)
        hosts[h]["findings"].append({
            "id":          f.id,
            "severity":    _SEVERITY_LABELS.get(f.severity, "info"),
            "sev_num":     f.severity,
            "title":       plain_title,
            "description": plain_desc,
            "remediation": f.remediation,
            "port":        f.port,
            "service":     f.service,
        })

    # Build device cards
    devices = []
    total_issues = 0
    for ip, h in hosts.items():
        device_type, icon = _detect_device(h["ports"], h["services"])
        risk_label, risk_colour = _risk_level(h["max_severity"])
        issue_count = len(h["findings"])
        total_issues += issue_count

        # Sort findings by severity desc
        h["findings"].sort(key=lambda x: x["sev_num"], reverse=True)

        devices.append({
            "ip":           ip,
            "device_type":  device_type,
            "icon":         icon,
            "risk":         risk_label,
            "risk_colour":  risk_colour,
            "issue_count":  issue_count,
            "max_severity": h["max_severity"],
            "open_ports":   sorted(set(h["ports"])),
            "findings":     h["findings"],
        })

    # Sort devices: riskiest first
    devices.sort(key=lambda d: d["max_severity"], reverse=True)

    # Overall network grade
    if not devices:
        net_score, net_grade = 100, "A+"
    else:
        crit  = sum(1 for f in findings if f.severity == 4)
        high  = sum(1 for f in findings if f.severity == 3)
        med   = sum(1 for f in findings if f.severity == 2)
        deductions = crit * 20 + high * 10 + med * 4
        net_score  = max(0, 100 - deductions)
        if net_score >= 90: net_grade = "A"
        elif net_score >= 75: net_grade = "B"
        elif net_score >= 60: net_grade = "C"
        elif net_score >= 40: net_grade = "D"
        else: net_grade = "F"

    # Top recommendations (deduplicated)
    seen: set[str] = set()
    recommendations: list[dict] = []
    for f in sorted(findings, key=lambda x: x.severity, reverse=True):
        pt, _ = _plain_english(f.title, f.description)
        if pt not in seen:
            seen.add(pt)
            recommendations.append({
                "title":    pt,
                "severity": _SEVERITY_LABELS.get(f.severity, "info"),
                "host":     f.host,
            })
        if len(recommendations) >= 8:
            break

    return {
        "scan_id":         str(scan.id),
        "scan_name":       scan.name,
        "status":          scan.status,
        "target":          (scan.config or {}).get("target", ""),
        "started_at":      scan.started_at.isoformat() if scan.started_at else None,
        "completed_at":    scan.completed_at.isoformat() if scan.completed_at else None,
        "network_score":   net_score,
        "network_grade":   net_grade,
        "device_count":    len(devices),
        "total_issues":    total_issues,
        "critical_issues": sum(1 for f in findings if f.severity == 4),
        "devices":         devices,
        "recommendations": recommendations,
    }
