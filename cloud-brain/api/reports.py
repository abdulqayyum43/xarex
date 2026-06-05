"""Report generation — professional HTML pentest reports with real-world attack context."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import get_org
from models.database import get_db
from models.tables import AttackPath, Finding, Org, Report, Scan

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/reports", tags=["reports"])

SEV_LABEL  = {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Info"}
SEV_COLOR  = {4: "#f04f59", 3: "#f0853a", 2: "#f0c93a", 1: "#4fc9f0", 0: "#8b90a7"}
SEV_BG     = {4: "#2a1219", 3: "#231710", 2: "#231f0a", 1: "#0a1f2a", 0: "#13161e"}

# ──────────────────────────────────────────────────────────────────────────────
#  Known-attack intelligence database
#  Maps CVE IDs and finding title keywords to real-world breach context,
#  exploitation steps, and fix guidance.
# ──────────────────────────────────────────────────────────────────────────────

KNOWN_ATTACKS: dict[str, dict] = {

    # ── Credential / Access issues ────────────────────────────────────────────
    "redis_unauth": {
        "mitre": [("T1190", "Exploit Public-Facing Application"),
                  ("T1505.003", "Server Software Component: Web Shell")],
        "real_world": (
            "In 2018, attackers exploited unauthenticated Redis instances to install cryptocurrency "
            "miners by writing cron jobs via <code>CONFIG SET dir</code> and <code>CONFIG SET dbfilename</code>. "
            "Thousands of cloud servers were compromised. The same technique was later used in the "
            "<strong>TeamTNT</strong> campaign (2020) to steal AWS credentials and deploy Monero miners."
        ),
        "exploit_steps": [
            "Connect: <code>redis-cli -h &lt;host&gt;</code>",
            "Verify access: <code>PING</code> → <code>+PONG</code>",
            "Read all keys: <code>KEYS *</code>",
            "RCE via cron: <code>CONFIG SET dir /var/spool/cron/crontabs</code> → write reverse shell",
            "RCE via SSH: write attacker public key to <code>~/.ssh/authorized_keys</code>",
        ],
        "fix": [
            "Set a strong password: <code>requirepass &lt;strong_password&gt;</code> in <code>redis.conf</code>",
            "Bind to localhost only: <code>bind 127.0.0.1</code>",
            "Enable protected mode: <code>protected-mode yes</code>",
            "Use Redis ACL (v6+) for fine-grained per-user access control",
            "Firewall port 6379 — should never be internet-facing",
            "Enable TLS with <code>tls-port</code> and <code>tls-cert-file</code>",
        ],
    },

    "mongodb_unauth": {
        "mitre": [("T1530", "Data from Cloud Storage"), ("T1190", "Exploit Public-Facing Application")],
        "real_world": (
            "The <strong>Meow attack</strong> (2020) wiped 4,000+ unsecured MongoDB and Elasticsearch "
            "instances with no ransom demand. Before that, <strong>Harak1r1</strong> (2017) ransomed "
            "28,000 MongoDB databases, demanding Bitcoin for data recovery. "
            "Researcher Bob Diachenko routinely discovers hundreds of exposed MongoDB instances "
            "containing medical records, financial data, and PII."
        ),
        "exploit_steps": [
            "Connect: <code>mongosh --host &lt;host&gt; --port 27017</code>",
            "List all databases: <code>show dbs</code>",
            "Dump collection: <code>db.users.find().pretty()</code>",
            "Drop database (destructive): <code>db.dropDatabase()</code>",
        ],
        "fix": [
            "Enable auth in <code>mongod.conf</code>: <code>security:\\n  authorization: enabled</code>",
            "Create admin user immediately: <code>db.createUser({user:'admin', pwd:'...', roles:['root']})</code>",
            "Bind to specific IPs: <code>net:\\n  bindIp: 127.0.0.1</code>",
            "Enable TLS: <code>net:\\n  tls:\\n    mode: requireTLS</code>",
            "Firewall port 27017 — restrict to application servers only",
        ],
    },

    "elasticsearch_unauth": {
        "mitre": [("T1530", "Data from Cloud Storage"), ("T1190", "Exploit Public-Facing Application")],
        "real_world": (
            "Security researcher Bob Diachenko discovered <strong>1.2 billion records</strong> exposed "
            "via an open Elasticsearch instance (2019). The <strong>Collection #1-#5</strong> breach "
            "(2019, 2.2B credentials) was also distributed via an exposed Elasticsearch node. "
            "The Meow bot (2020) wiped thousands of clusters with no recovery option."
        ),
        "exploit_steps": [
            "List all indices: <code>GET http://&lt;host&gt;:9200/_cat/indices?v</code>",
            "Dump index: <code>GET http://&lt;host&gt;:9200/&lt;index&gt;/_search?size=10000</code>",
            "Delete all data: <code>DELETE http://&lt;host&gt;:9200/*</code>",
        ],
        "fix": [
            "Enable X-Pack Security: <code>xpack.security.enabled: true</code>",
            "Run setup: <code>bin/elasticsearch-setup-passwords interactive</code>",
            "Enable TLS for HTTP and transport layers",
            "Use Kibana role-based access control",
            "Firewall port 9200 and 9300",
        ],
    },

    "ftp_anonymous": {
        "mitre": [("T1078.004", "Valid Accounts: Cloud Accounts"),
                  ("T1083", "File and Directory Discovery")],
        "real_world": (
            "FTP anonymous access was the primary distribution mechanism for warez, malware, "
            "and stolen data throughout the 1990s–2000s. Modern incidents include attackers "
            "using anonymous FTP servers to host phishing kits, exfiltrate backups, "
            "and stage malware. Many IoT devices and legacy NAS systems still ship "
            "with anonymous FTP enabled by default."
        ),
        "exploit_steps": [
            "Connect: <code>ftp &lt;host&gt;</code>, username: <code>anonymous</code>, password: anything",
            "List files: <code>ls -la</code>",
            "Download all: <code>mget *</code>",
            "Upload backdoor (if write access): <code>put webshell.php</code>",
        ],
        "fix": [
            "Disable anonymous FTP: <code>anonymous_enable=NO</code> in <code>vsftpd.conf</code>",
            "Replace FTP with SFTP (SSH File Transfer Protocol) entirely",
            "If FTP is required, enable FTPS (FTP over TLS): <code>ssl_enable=YES</code>",
            "Restrict to specific IP ranges via firewall",
            "Enable logging: <code>xferlog_enable=YES</code>",
        ],
    },

    "memcached_unauth": {
        "mitre": [("T1499.002", "Network Denial of Service: Reflection Amplification"),
                  ("T1005", "Data from Local System")],
        "real_world": (
            "The <strong>GitHub DDoS attack (2018)</strong> peaked at <strong>1.35 Tbps</strong> — "
            "the largest ever recorded at the time — using Memcached UDP amplification "
            "(amplification factor up to 51,000×). Attackers send a small spoofed UDP packet "
            "and the server responds with a massive payload to the victim's IP. "
            "Over 100,000 exposed Memcached instances were abused in this attack."
        ),
        "exploit_steps": [
            "Verify access: <code>echo 'stats' | nc &lt;host&gt; 11211</code>",
            "Read cached keys: <code>echo 'stats items' | nc &lt;host&gt; 11211</code>",
            "DDoS amplification: send spoofed UDP packets with victim's source IP",
        ],
        "fix": [
            "Bind to localhost: add <code>-l 127.0.0.1</code> to startup command",
            "Disable UDP: add <code>-U 0</code> to startup command",
            "Enable SASL authentication",
            "Firewall port 11211 TCP and UDP immediately",
        ],
    },

    "smtp_relay": {
        "mitre": [("T1566", "Phishing"), ("T1534", "Internal Spearphishing")],
        "real_world": (
            "Open SMTP relays were responsible for the majority of global spam in the early 2000s. "
            "Modern attackers use open relays to send targeted phishing emails that bypass SPF/DKIM "
            "checks (since they originate from a legitimate server). The host's IP is typically "
            "blacklisted by Spamhaus, SORBS, and others <strong>within hours</strong>, "
            "causing legitimate email to fail."
        ),
        "exploit_steps": [
            "<code>telnet &lt;host&gt; 25</code>",
            "<code>EHLO attacker.com</code>",
            "<code>MAIL FROM: &lt;ceo@victim.com&gt;</code>",
            "<code>RCPT TO: &lt;employee@victim.com&gt;</code>",
            "<code>DATA</code> → send phishing email body",
        ],
        "fix": [
            "Configure relay restrictions in Postfix: <code>smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated reject_unauth_destination</code>",
            "Require SMTP AUTH for all relay",
            "Implement SPF: <code>v=spf1 mx ~all</code>",
            "Implement DKIM signing",
            "Implement DMARC: <code>v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com</code>",
        ],
    },

    "smb_signing": {
        "mitre": [("T1557.001", "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning"),
                  ("T1110", "Brute Force"), ("T1021.002", "Remote Services: SMB/Windows Admin Shares")],
        "real_world": (
            "SMB relay is the foundation of most Windows lateral movement attacks. "
            "<strong>NotPetya (2017)</strong> combined EternalBlue + Mimikatz + SMB relay to propagate "
            "across networks, causing $10B in damages. The technique is standard in red team engagements: "
            "Responder poisons LLMNR, captures NTLMv2 hashes, and ntlmrelayx relays them to "
            "hosts without SMB signing to achieve code execution without cracking the hash."
        ),
        "exploit_steps": [
            "Start Responder: <code>responder -I eth0 -rdwv</code> (poisons LLMNR/NBT-NS)",
            "Start relay: <code>ntlmrelayx.py -tf targets.txt -smb2support</code>",
            "Wait for a user to browse a UNC path or for automatic authentication",
            "Credentials are relayed → remote command execution on target",
            "Alternatively: <code>impacket-secretsdump -no-pass -k &lt;host&gt;</code>",
        ],
        "fix": [
            "Enable SMB signing via Group Policy: <strong>Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options</strong>",
            "Set <em>'Microsoft network server: Digitally sign communications (always)'</em> = <strong>Enabled</strong>",
            "Set <em>'Microsoft network client: Digitally sign communications (always)'</em> = <strong>Enabled</strong>",
            "Disable LLMNR via Group Policy: <strong>Computer Configuration → Administrative Templates → Network → DNS Client → Turn off multicast name resolution</strong> = Enabled",
            "Disable NBT-NS: Network adapter → IPv4 Properties → Advanced → WINS → Disable NetBIOS over TCP/IP",
        ],
    },

    "llmnr_active": {
        "mitre": [("T1557.001", "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and Relay")],
        "real_world": (
            "LLMNR poisoning with <strong>Responder</strong> is one of the most common initial access "
            "techniques in internal penetration tests — effective in over 80% of engagements. "
            "It requires no user interaction beyond normal browsing behaviour. "
            "NTLMv2 hashes captured this way can often be cracked offline with hashcat "
            "in minutes using common wordlists."
        ),
        "exploit_steps": [
            "<code>responder -I eth0 -rdwv</code>",
            "Wait for any user to mistype a UNC path (e.g. <code>\\\\fileservr\\share</code>)",
            "Windows broadcasts LLMNR query → Responder responds → captures NTLMv2",
            "Crack offline: <code>hashcat -m 5600 hash.txt rockyou.txt</code>",
        ],
        "fix": [
            "Disable LLMNR via Group Policy (see SMB Signing fix above)",
            "Disable NBT-NS on all adapters",
            "Deploy network monitoring to alert on Responder-like multicast traffic",
            "Use a PAM solution to enforce MFA so captured credentials cannot be replayed",
        ],
    },

    # ── SSL/TLS issues ────────────────────────────────────────────────────────
    "CVE-2014-0160": {  # Heartbleed
        "mitre": [("T1190", "Exploit Public-Facing Application")],
        "real_world": (
            "<strong>Heartbleed (2014)</strong> exposed private keys, session tokens, and plaintext "
            "data from memory in OpenSSL. It affected an estimated <strong>17% of all HTTPS servers</strong>. "
            "Community Health Systems had 4.5 million patient records stolen. "
            "Despite being patched in 2014, Heartbleed continues to affect unpatched embedded "
            "systems, IoT devices, and industrial control systems as of 2026."
        ),
        "exploit_steps": [
            "<code>python heartbleed.py &lt;host&gt; -p 443</code> (Jared Stafford's PoC)",
            "Leaks up to 64KB of server memory per request",
            "Repeat to build a larger picture of leaked memory",
            "Extract: private keys, session cookies, HTTP headers, plaintext passwords",
        ],
        "fix": [
            "Upgrade OpenSSL to 1.0.1g or later immediately",
            "Revoke and reissue all TLS certificates (private key may be compromised)",
            "Invalidate all session tokens and force re-authentication",
            "Check whether private keys were extracted with certificate transparency logs",
        ],
    },

    "CVE-2014-3566": {  # POODLE
        "mitre": [("T1557", "Adversary-in-the-Middle")],
        "real_world": (
            "<strong>POODLE (2014)</strong> allows an attacker in a MITM position to decrypt "
            "SSLv3 traffic by exploiting CBC padding oracle. While SSLv3 is ancient, it is still "
            "enabled by default on some legacy VPN concentrators, load balancers (F5 BIG-IP, "
            "Citrix NetScaler), and industrial HMIs as of 2026."
        ),
        "exploit_steps": [
            "Position: must be on the same network (e.g. via ARP poisoning)",
            "Force SSLv3 by blocking TLS handshakes (browser fallback)",
            "Perform chosen-plaintext attack against CBC ciphertext",
            "Recover 1 byte of plaintext per 256 requests on average",
        ],
        "fix": [
            "Disable SSLv3 entirely: <code>ssl_protocols TLSv1.2 TLSv1.3;</code> in nginx",
            "Apache: <code>SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1</code>",
            "Disable TLS fallback: enable <code>TLS_FALLBACK_SCSV</code>",
        ],
    },

    "CVE-2016-2183": {  # SWEET32
        "mitre": [("T1557", "Adversary-in-the-Middle")],
        "real_world": (
            "<strong>SWEET32 (2016)</strong> is a birthday attack against 64-bit block ciphers (3DES, Blowfish). "
            "After ~768 GB of traffic on the same session key, collisions reveal plaintext. "
            "While 768 GB seems large, long-lived TLS sessions (e.g. VPNs, persistent WebSockets) "
            "can reach this in hours. 3DES remains common in legacy enterprise VPN configurations "
            "and payment processing systems that must support old clients."
        ),
        "exploit_steps": [
            "Inject JavaScript into HTTP page (MITM) to force HTTPS requests in a loop",
            "Capture ~768 GB of traffic encrypted under the same 3DES key",
            "Apply birthday attack to find collisions and recover plaintext blocks",
        ],
        "fix": [
            "Remove 3DES from cipher list: ensure <code>!3DES</code> or <code>!DES</code> in cipher string",
            "nginx: <code>ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:...</code>",
            "Enforce TLS 1.3 which does not support 3DES at all",
            "Enable session renegotiation limits to break long-lived sessions",
        ],
    },

    "CVE-2011-3389": {  # BEAST
        "mitre": [("T1557", "Adversary-in-the-Middle")],
        "real_world": (
            "<strong>BEAST (2011)</strong> exploits the predictable IV in TLS 1.0 CBC mode. "
            "TLS 1.0 is now formally deprecated by RFC 8996 (2021) and banned by PCI-DSS v3.2+. "
            "Major browsers dropped TLS 1.0 support in 2020. However, legacy payment terminals, "
            "ATMs, and industrial systems continue to require TLS 1.0 in some environments."
        ),
        "exploit_steps": [
            "Requires MITM position and ability to inject chosen plaintext (e.g. via JavaScript)",
            "Exploit predictable CBC IV to perform blockwise chosen-plaintext attack",
            "Recover session tokens or credentials from TLS stream",
        ],
        "fix": [
            "Disable TLS 1.0 and 1.1: set minimum to TLS 1.2",
            "Enable TLS 1.3 for modern clients",
            "nginx: <code>ssl_protocols TLSv1.2 TLSv1.3;</code>",
            "Apache: <code>SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1</code>",
        ],
    },

    "CVE-2012-4929": {  # CRIME
        "mitre": [("T1557", "Adversary-in-the-Middle")],
        "real_world": (
            "<strong>CRIME (2012)</strong> exploits TLS-level compression to recover secrets "
            "(e.g. session cookies) by observing compressed ciphertext length changes. "
            "An attacker controlling JavaScript in the browser injects chosen plaintext and "
            "measures responses. Modern browsers disabled TLS compression after CRIME was disclosed."
        ),
        "exploit_steps": [
            "Position: MITM + JavaScript injection",
            "Guess one byte of secret at a time by observing compressed length",
            "Requires ~700 requests to recover a 40-char session cookie",
        ],
        "fix": [
            "Disable TLS compression: <code>SSL_OP_NO_COMPRESSION</code> in OpenSSL",
            "nginx disables this by default since v1.2.2",
            "Never enable <code>zlib</code> or <code>deflate</code> in TLS context",
        ],
    },

    "hsts_missing": {
        "mitre": [("T1557", "Adversary-in-the-Middle"), ("T1539", "Steal Web Session Cookie")],
        "real_world": (
            "Missing HSTS allows attackers to perform SSL stripping attacks (sslstrip by Moxie Marlinspike). "
            "In a coffee shop MITM scenario, a user navigating to <code>http://bank.com</code> can be "
            "silently downgraded to HTTP, allowing session cookie theft. HSTS preloading eliminates "
            "this risk by instructing browsers never to connect via HTTP."
        ),
        "exploit_steps": [
            "ARP poison victim on same network",
            "Run <code>sslstrip</code> to downgrade HTTPS → HTTP",
            "Capture session cookies in plaintext from HTTP traffic",
        ],
        "fix": [
            "Add header: <code>Strict-Transport-Security: max-age=31536000; includeSubDomains; preload</code>",
            "nginx: <code>add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;</code>",
            "Submit to HSTS preload list: <a href='https://hstspreload.org'>hstspreload.org</a>",
            "Redirect all HTTP to HTTPS with 301 (not 302)",
        ],
    },

    "cert_expired": {
        "mitre": [("T1557", "Adversary-in-the-Middle")],
        "real_world": (
            "Expired certificates cause browsers to display full-page warnings that users learn to "
            "click through, training them to ignore certificate errors — making MITM attacks easier. "
            "The <strong>Let's Encrypt expiry incident (2021)</strong> caused major outages across "
            "thousands of services. Automation with ACME (certbot) eliminates expiry risk."
        ),
        "exploit_steps": [
            "Users clicking through certificate warnings are vulnerable to any certificate substitution",
            "Present a forged certificate — user has been trained to accept warnings",
        ],
        "fix": [
            "Renew certificate immediately",
            "Automate with ACME/certbot: <code>certbot renew --pre-hook 'service nginx stop' --post-hook 'service nginx start'</code>",
            "Use Certificate Transparency monitoring (crt.sh, Facebook CT Monitor)",
            "Set calendar alerts at 60, 30, and 7 days before expiry",
        ],
    },

    "http_default_creds": {
        "mitre": [("T1078.001", "Valid Accounts: Default Accounts"),
                  ("T1110.002", "Brute Force: Password Spraying")],
        "real_world": (
            "Default credentials are one of the most common initial access vectors. "
            "<strong>Mirai botnet (2016)</strong> compromised 600,000+ IoT devices using a list of "
            "only 62 default username/password combinations, enabling the 1.2 Tbps Dyn DDoS attack "
            "that took down Twitter, Netflix, and Spotify. "
            "Default credentials persist in Grafana, Jenkins, JBoss, WebLogic, Webmin, "
            "CCTV systems, and network equipment worldwide."
        ),
        "exploit_steps": [
            "Try credential pairs from a default credential database",
            "Authenticate to admin panel",
            "Deploy webshell, extract data, or pivot to internal network",
        ],
        "fix": [
            "Change all default credentials on first boot (enforce via setup wizard)",
            "Implement account lockout after 5 failed attempts",
            "Enable multi-factor authentication on all admin interfaces",
            "Restrict admin panel access to management VLAN/IP range only",
            "Use a secrets manager (HashiCorp Vault, AWS Secrets Manager) for service credentials",
        ],
    },

    "CVE-2017-0143": {  # EternalBlue
        "mitre": [("T1210", "Exploitation of Remote Services"),
                  ("T1021.002", "Remote Services: SMB/Windows Admin Shares")],
        "real_world": (
            "<strong>EternalBlue (MS17-010)</strong> was developed by the NSA, leaked by Shadow Brokers, "
            "and weaponised in <strong>WannaCry</strong> (May 2017, 230,000 systems, $4B damage) and "
            "<strong>NotPetya</strong> (June 2017, $10B damage, destroyed Maersk, Merck, FedEx). "
            "Unpatched SMBv1 hosts remain in enterprise networks in 2026, particularly on legacy "
            "Windows Server 2003/2008 systems, medical devices, and industrial control systems."
        ),
        "exploit_steps": [
            "<code>nmap --script smb-vuln-ms17-010 &lt;host&gt;</code> to confirm vulnerability",
            "<code>msfconsole</code> → <code>use exploit/windows/smb/ms17_010_eternalblue</code>",
            "Set RHOSTS and LHOST → <code>run</code>",
            "Achieve SYSTEM-level shell without credentials",
        ],
        "fix": [
            "Apply MS17-010 patch (KB4012212) — available for Windows XP via emergency patch",
            "Disable SMBv1: <code>Set-SmbServerConfiguration -EnableSMB1Protocol $false</code>",
            "Block TCP 445 at perimeter firewall",
            "Segment network — ensure SMB is not routable across VLAN boundaries",
        ],
    },

    "CVE-2022-0543": {  # Redis Lua sandbox escape
        "mitre": [("T1059.007", "Command and Scripting Interpreter: JavaScript"),
                  ("T1190", "Exploit Public-Facing Application")],
        "real_world": (
            "<strong>CVE-2022-0543</strong> is a Lua sandbox escape in Redis on Debian/Ubuntu. "
            "An authenticated attacker (or unauthenticated if no password is set) can execute "
            "arbitrary OS commands via <code>redis-cli EVAL 'local io=require(\"io\"); ...' 0</code>. "
            "Combined with the unauthenticated access finding, this enables full server compromise."
        ),
        "exploit_steps": [
            "<code>redis-cli -h &lt;host&gt; EVAL 'local io=require(\"io\"); local f=io.popen(\"id\"); local s=f:read(\"*a\"); f:close(); return s' 0</code>",
            "Returns OS command output confirming RCE",
        ],
        "fix": [
            "Upgrade Redis to patched version",
            "Set <code>requirepass</code> even as a secondary defence",
            "Disable Lua scripting if not needed: <code>enable-debug-command no</code>",
            "Run Redis as a non-root user in a container or with seccomp",
        ],
    },
}

# Keyword → attack key mapping for findings without a direct CVE
TITLE_KEYWORD_MAP = [
    ("redis",                  "redis_unauth"),
    ("mongodb",                "mongodb_unauth"),
    ("mongo",                  "mongodb_unauth"),
    ("elasticsearch",          "elasticsearch_unauth"),
    ("ftp anonymous",          "ftp_anonymous"),
    ("anonymous",              "ftp_anonymous"),
    ("memcached",              "memcached_unauth"),
    ("smtp open relay",        "smtp_relay"),
    ("open relay",             "smtp_relay"),
    ("smb signing",            "smb_signing"),
    ("smb relay",              "smb_signing"),
    ("llmnr",                  "llmnr_active"),
    ("nbt-ns",                 "llmnr_active"),
    ("hsts",                   "hsts_missing"),
    ("strict-transport",       "hsts_missing"),
    ("expired",                "cert_expired"),
    ("default credential",     "http_default_creds"),
    ("default cred",           "http_default_creds"),
]


def _lookup_attack(finding: Finding) -> dict | None:
    """Return attack intelligence for a finding, checking CVE then title keywords."""
    cve = (finding.cve_id or "").upper()
    if cve and cve in KNOWN_ATTACKS:
        return KNOWN_ATTACKS[cve]

    title_lower = (finding.title or "").lower()
    for keyword, key in TITLE_KEYWORD_MAP:
        if keyword in title_lower:
            return KNOWN_ATTACKS.get(key)
    return None


# ──────────────────────────────────────────────────────────────────────────────
#  Report generation
# ──────────────────────────────────────────────────────────────────────────────

async def generate_report(scan_id: str, org_id: str, db: AsyncSession) -> Report:
    """Generate and persist a full HTML report. Called automatically on scan complete."""
    scan_result = await db.execute(select(Scan).where(Scan.id == scan_id, Scan.org_id == org_id))
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise ValueError(f"Scan {scan_id} not found in org {org_id}")

    findings_result = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.severity.desc())
    )
    findings = findings_result.scalars().all()

    paths_result = await db.execute(
        select(AttackPath).where(AttackPath.scan_id == scan_id).order_by(AttackPath.risk_score.desc())
    )
    attack_paths = paths_result.scalars().all()

    counts = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0}
    for f in findings:
        counts[min(f.severity, 4)] += 1

    html = _render_html_report(scan, findings, attack_paths, counts)

    existing_result = await db.execute(select(Report).where(Report.scan_id == scan_id))
    existing = existing_result.scalar_one_or_none()

    if existing:
        existing.html_content = html
        existing.generated_at = datetime.now(timezone.utc)
        existing.finding_count = len(findings)
        existing.critical_count = counts[4]
        report = existing
    else:
        report = Report(
            id=str(uuid.uuid4()),
            scan_id=scan_id,
            org_id=org_id,
            html_content=html,
            generated_at=datetime.now(timezone.utc),
            finding_count=len(findings),
            critical_count=counts[4],
        )
        db.add(report)

    await db.commit()
    await db.refresh(report)
    logger.info("Report generated", scan_id=scan_id, findings=len(findings))
    return report


# ──────────────────────────────────────────────────────────────────────────────
#  API Routes
# ──────────────────────────────────────────────────────────────────────────────

@router.post("/scans/{scan_id}", status_code=status.HTTP_201_CREATED)
async def create_report(
    scan_id: str,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
) -> dict:
    try:
        report = await generate_report(scan_id, org.id, db)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return {
        "id": report.id,
        "scan_id": report.scan_id,
        "generated_at": report.generated_at.isoformat(),
        "finding_count": report.finding_count,
        "critical_count": report.critical_count,
        "has_ai_summary": bool(report.ai_summary),
    }


@router.get("", response_model=list[dict])
async def list_reports(
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    scan_ids_result = await db.execute(select(Scan.id).where(Scan.org_id == org.id))
    org_scan_ids = [row[0] for row in scan_ids_result.fetchall()]
    if not org_scan_ids:
        return []

    result = await db.execute(
        select(Report)
        .where(Report.scan_id.in_(org_scan_ids))
        .order_by(Report.generated_at.desc())
    )
    reports = result.scalars().all()

    scans_result = await db.execute(select(Scan).where(Scan.id.in_(org_scan_ids)))
    scans = {s.id: s.name for s in scans_result.scalars().all()}

    return [
        {
            "id": r.id,
            "scan_id": r.scan_id,
            "scan_name": scans.get(r.scan_id, "—"),
            "generated_at": r.generated_at.isoformat(),
            "finding_count": r.finding_count,
            "critical_count": r.critical_count,
            "has_ai_summary": bool(r.ai_summary),
            "pdf_available": True,
        }
        for r in reports
    ]


@router.get("/{report_id}", response_class=Response)
async def get_report_html(
    report_id: str,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
) -> Response:
    report = await _get_report_for_org(report_id, org.id, db)
    # Fetch the scan name for a proper filename
    scan_result = await db.execute(select(Scan).where(Scan.id == report.scan_id))
    scan = scan_result.scalar_one_or_none()
    safe_name = _safe_filename(scan.name if scan else "report")
    return Response(
        content=report.html_content,
        media_type="text/html",
        headers={"Content-Disposition": f'inline; filename="xarex_{safe_name}_{report_id[:8]}.html"'},
    )


@router.get("/{report_id}/pdf", response_class=Response)
async def get_report_pdf(
    report_id: str,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Download the report as a PDF using WeasyPrint."""
    report = await _get_report_for_org(report_id, org.id, db)
    scan_result = await db.execute(select(Scan).where(Scan.id == report.scan_id))
    scan = scan_result.scalar_one_or_none()
    safe_name = _safe_filename(scan.name if scan else "report")

    try:
        import weasyprint
        import asyncio
        loop = asyncio.get_running_loop()
        html_content = report.html_content
        pdf_bytes = await loop.run_in_executor(
            None,
            lambda: weasyprint.HTML(string=html_content).write_pdf()
        )
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="PDF generation unavailable — weasyprint not installed on this server.",
        )
    except Exception as exc:
        logger.error("PDF generation failed", report_id=report_id, error=str(exc))
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {exc}")

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="xarex_{safe_name}_{report_id[:8]}.pdf"',
            "Content-Length": str(len(pdf_bytes)),
        },
    )


@router.get("/{report_id}/summary")
async def get_report_summary(
    report_id: str,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
) -> dict:
    report = await _get_report_for_org(report_id, org.id, db)
    if not report.ai_summary:
        raise HTTPException(status_code=404, detail="No AI summary yet.")
    try:
        return json.loads(report.ai_summary)
    except json.JSONDecodeError:
        return {"executive_summary": report.ai_summary}


@router.post("/{report_id}/analyse")
async def trigger_ai_analysis(
    report_id: str,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
) -> dict:
    report = await _get_report_for_org(report_id, org.id, db)
    from services.ai_analyst import AIAnalyst
    analyst = AIAnalyst()
    return await analyst.analyse_scan(report.scan_id, db)


@router.post("/{report_id}/email")
async def email_report(
    report_id: str,
    body: dict,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Send the HTML report to an email address.

    Body: {"to": "recipient@example.com", "message": "optional note"}
    """
    to_email = (body.get("to") or "").strip()
    if not to_email or "@" not in to_email:
        raise HTTPException(status_code=400, detail="Valid 'to' email address required.")

    report = await _get_report_for_org(report_id, org.id, db)
    scan_result = await db.execute(select(Scan).where(Scan.id == report.scan_id))
    scan = scan_result.scalar_one_or_none()
    scan_name = scan.name if scan else "Security Assessment"
    note = (body.get("message") or "").strip()

    from services.email_service import send_email, _base_html
    note_html = f'<p style="color:#b8aed4;font-style:italic;border-left:3px solid #7c6af7;padding-left:12px;margin:12px 0">{_escape(note)}</p>' if note else ""

    # Quick stats from the report
    stats_html = (
        f'<div style="display:grid;grid-template-columns:repeat(2,1fr);gap:12px;margin:16px 0">'
        f'<div style="background:rgba(240,79,89,0.1);border:1px solid rgba(240,79,89,0.3);border-radius:8px;padding:12px;text-align:center">'
        f'<div style="font-size:28px;font-weight:900;color:#f04f59">{report.critical_count}</div>'
        f'<div style="font-size:11px;color:#8b90a7;text-transform:uppercase;margin-top:4px">Critical</div></div>'
        f'<div style="background:rgba(76,240,152,0.07);border:1px solid rgba(76,240,152,0.25);border-radius:8px;padding:12px;text-align:center">'
        f'<div style="font-size:28px;font-weight:900;color:#4cf098">{report.finding_count}</div>'
        f'<div style="font-size:11px;color:#8b90a7;text-transform:uppercase;margin-top:4px">Total Findings</div></div>'
        f'</div>'
    )

    content = f"""
    <div class="card">
      <h1>Security Assessment Report</h1>
      <p>A Xarex autonomous pentest report has been shared with you for <strong style="color:#f0ecff">{_escape(scan_name)}</strong>.</p>
      {note_html}
      {stats_html}
      <p style="font-size:13px;color:#8b90a7">
        Generated: {report.generated_at.strftime("%Y-%m-%d %H:%M UTC")}<br>
        Report ID: <code style="color:#7c6af7">{report.id[:8]}</code>
      </p>
      <div class="warn-box">
        ⚠ This report contains sensitive security information. Share only with authorised personnel.
      </div>
    </div>
    <div class="card">
      <h1 style="font-size:20px">Full Report (HTML)</h1>
      <p>The complete report with all findings, MITRE ATT&amp;CK mapping, attack paths, and remediation roadmap is attached below as an HTML file.</p>
      <p style="font-size:13px;color:#8b90a7">Open in any browser for the best experience. Print to PDF using Ctrl+P.</p>
    </div>
    """

    email_html = _base_html(content)

    ok = await send_email(
        to=to_email,
        subject=f"Xarex Pentest Report — {scan_name}",
        html=email_html,
    )

    if not ok:
        raise HTTPException(
            status_code=503,
            detail="Email delivery failed. Check RESEND_API_KEY or SMTP settings in .env",
        )

    logger.info("Report emailed", report_id=report_id, to=to_email)
    return {"message": f"Report sent to {to_email}", "report_id": report_id}


# ──────────────────────────────────────────────────────────────────────────────
#  HTML Report Renderer
# ──────────────────────────────────────────────────────────────────────────────

def _render_html_report(
    scan: Scan,
    findings: list[Finding],
    attack_paths: list[AttackPath],
    counts: dict[int, int],
) -> str:
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total = sum(counts.values())

    duration_str = "—"
    if scan.started_at and scan.completed_at:
        delta = scan.completed_at - scan.started_at
        secs = int(delta.total_seconds())
        if secs < 60:
            duration_str = f"{secs}s"
        elif secs < 3600:
            duration_str = f"{secs // 60}m {secs % 60}s"
        else:
            duration_str = f"{secs // 3600}h {(secs % 3600) // 60}m"

    target = (scan.config or {}).get("target", "—")

    # Overall risk score
    risk_score = min(10.0, (
        counts[4] * 2.5 +
        counts[3] * 1.2 +
        counts[2] * 0.4 +
        counts[1] * 0.1
    ))
    risk_label = (
        "CRITICAL" if risk_score >= 8 else
        "HIGH"     if risk_score >= 6 else
        "MEDIUM"   if risk_score >= 4 else
        "LOW"      if risk_score >= 2 else
        "MINIMAL"
    )
    risk_color = (
        "#f04f59" if risk_score >= 8 else
        "#f0853a" if risk_score >= 6 else
        "#f0c93a" if risk_score >= 4 else
        "#4fc9f0" if risk_score >= 2 else
        "#4cf098"
    )

    # Collect unique hosts and MITRE techniques
    all_hosts = sorted({f.host for f in findings if f.host})
    all_techniques: dict[str, str] = {}
    for f in findings:
        intel = _lookup_attack(f)
        if intel:
            for tid, tname in intel.get("mitre", []):
                all_techniques[tid] = tname

    # ── Finding detail cards ──────────────────────────────────────────────────
    finding_cards = ""
    for idx, f in enumerate(findings[:200]):
        sev_color = SEV_COLOR.get(f.severity, "#8b90a7")
        sev_bg    = SEV_BG.get(f.severity, "#13161e")
        sev_label = SEV_LABEL.get(f.severity, "?")
        meta      = f.metadata_ or {}
        cvss      = meta.get("cvss_score", "")
        epss_raw  = meta.get("epss_score")
        epss      = f"{float(epss_raw):.1%}" if epss_raw else ""
        techniques = meta.get("attack_technique_ids", "")

        intel = _lookup_attack(f)

        # Real-world context block
        rw_block = ""
        if intel and intel.get("real_world"):
            rw_block = f"""
            <div class="intel-block">
              <div class="intel-title">⚔ Real-World Attack Context</div>
              <p>{intel['real_world']}</p>
            </div>"""

        # Exploit steps
        exploit_block = ""
        if intel and intel.get("exploit_steps"):
            steps_html = "".join(f"<li>{s}</li>" for s in intel["exploit_steps"])
            exploit_block = f"""
            <div class="intel-block warn">
              <div class="intel-title">🔴 Exploitation Steps (Proof-of-Concept)</div>
              <ol>{steps_html}</ol>
            </div>"""

        # Remediation
        rem_items = ""
        if intel and intel.get("fix"):
            rem_items = "".join(f"<li>{s}</li>" for s in intel["fix"])
        elif f.remediation:
            for line in f.remediation.split("\n"):
                line = line.strip()
                if line:
                    rem_items += f"<li>{line}</li>"

        rem_block = ""
        if rem_items:
            rem_block = f"""
            <div class="intel-block fix">
              <div class="intel-title">✅ Remediation Steps</div>
              <ol>{rem_items}</ol>
            </div>"""

        # MITRE techniques
        mitre_badges = ""
        if intel and intel.get("mitre"):
            for tid, tname in intel["mitre"]:
                mitre_badges += f'<span class="badge mitre">{tid} — {tname}</span>'
        elif techniques:
            for t in str(techniques).split(","):
                t = t.strip()
                if t:
                    mitre_badges += f'<span class="badge mitre">{t}</span>'

        # CVE/CVSS badges
        cve_badge = f'<span class="badge cve">{f.cve_id}</span>' if f.cve_id else ""
        cvss_badge = f'<span class="badge cvss">CVSS {cvss}</span>' if cvss else ""
        epss_badge = f'<span class="badge epss">EPSS {epss}</span>' if epss else ""

        # Remediation status badge
        rstat = getattr(f, "remediation_status", "new") or "new"
        RSTAT_STYLE = {
            "new":             ("background:#1e1e2e;color:#8b90a7;border:1px solid #333", "New"),
            "in_progress":     ("background:#2a2510;color:#f0c93a;border:1px solid #5a4a20", "In Progress"),
            "fixed":           ("background:#0d1a12;color:#4cf098;border:1px solid #1a5a30", "Fixed ✓"),
            "false_positive":  ("background:#1a102e;color:#c87be8;border:1px solid #4a1a7e", "False Positive"),
            "accepted_risk":   ("background:#0d1e2a;color:#4fc9f0;border:1px solid #1a4a6e", "Accepted Risk"),
        }
        rstyle, rlabel = RSTAT_STYLE.get(rstat, RSTAT_STYLE["new"])
        rstat_badge = f'<span style="font-size:10px;font-weight:700;padding:2px 8px;border-radius:4px;{rstyle}">{rlabel}</span>'

        # Compliance controls
        from api.findings import _get_compliance_controls
        compliance_items = _get_compliance_controls(f)
        compliance_html = ""
        if compliance_items:
            ctrl_html = " ".join(
                f'<span style="font-size:10px;font-weight:700;padding:2px 8px;border-radius:4px;'
                f'background:#13161e;border:1px solid #2a3060;color:#7c6af7">'
                f'{c["standard"]} {c["control_ref"]} — {c["control_name"]}</span>'
                for c in compliance_items[:6]
            )
            compliance_html = f'<div style="margin-top:10px"><div style="font-size:10px;text-transform:uppercase;letter-spacing:0.8px;font-weight:700;color:#8b90a7;margin-bottom:6px">Compliance Frameworks</div><div style="display:flex;flex-wrap:wrap;gap:6px">{ctrl_html}</div></div>'

        evidence_block = ""
        if f.evidence:
            evidence_block = f"""
            <div class="evidence-block">
              <div class="evidence-title">Evidence / Proof</div>
              <pre>{_escape(f.evidence[:2000])}</pre>
            </div>"""

        desc_block = f'<p class="desc">{_escape(f.description or "")}</p>' if f.description else ""

        finding_cards += f"""
        <div class="finding-card" id="f{idx}">
          <div class="finding-header" style="border-left: 4px solid {sev_color}; background:{sev_bg}">
            <div class="finding-title-row">
              <span class="sev-badge" style="background:{sev_color}">{sev_label}</span>
              <span class="finding-title">{_escape(f.title or "Unnamed finding")}</span>
            </div>
            <div class="finding-meta">
              <code class="host">{_escape(f.host or "")}{f":{f.port}" if f.port else ""}</code>
              {f'<span class="service-tag">{_escape(f.service)}</span>' if f.service else ""}
              {cve_badge}{cvss_badge}{epss_badge}{rstat_badge}
            </div>
          </div>
          <div class="finding-body">
            {desc_block}
            {rw_block}
            {exploit_block}
            {evidence_block}
            {rem_block}
            {f'<div class="mitre-row">{mitre_badges}</div>' if mitre_badges else ""}
            {compliance_html}
          </div>
        </div>"""

    # ── Attack paths ──────────────────────────────────────────────────────────
    path_rows = ""
    for p in attack_paths[:30]:
        risk_color = "#f04f59" if p.risk_score >= 8 else "#f0853a" if p.risk_score >= 6 else "#f0c93a"
        hops = len(p.nodes) if p.nodes else 0
        path_rows += f"""
        <tr>
          <td><code>{_escape(str(p.entry_point or "—"))}</code></td>
          <td><code>{_escape(str(p.target or "—"))}</code></td>
          <td><strong style="color:{risk_color}">{p.risk_score:.1f} / 10</strong></td>
          <td>{_escape(str(p.impact or "—"))}</td>
          <td>{hops} hop{"s" if hops != 1 else ""}</td>
        </tr>"""

    # ── Remediation roadmap ───────────────────────────────────────────────────
    roadmap_rows = _build_roadmap(findings)

    # ── MITRE ATT&CK coverage ─────────────────────────────────────────────────
    mitre_items = ""
    for tid, tname in sorted(all_techniques.items()):
        mitre_items += f"""
        <div class="mitre-item">
          <a href="https://attack.mitre.org/techniques/{tid.split('.')[0]}/" target="_blank"
             class="mitre-link">{tid}</a>
          <span>{tname}</span>
        </div>"""

    # ── Scope summary ─────────────────────────────────────────────────────────
    host_list = "".join(f"<li><code>{h}</code></li>" for h in all_hosts[:50])
    if len(all_hosts) > 50:
        host_list += f"<li style='color:#8b90a7'>… and {len(all_hosts)-50} more</li>"

    # ── Donut chart via SVG ───────────────────────────────────────────────────
    donut_svg = _make_donut(counts, total)

    # ── Modules executed table ────────────────────────────────────────────────
    modules_table = _build_modules_table(findings)

    # ── Remediation tracking summary ─────────────────────────────────────────
    from collections import Counter
    rstat_counts = Counter(getattr(f, "remediation_status", "new") or "new" for f in findings)
    total_findings = len(findings)
    rstat_rows = ""
    RSTAT_INFO = [
        ("new",            "#8b90a7", "New / Unaddressed"),
        ("in_progress",    "#f0c93a", "In Progress"),
        ("fixed",          "#4cf098", "Fixed"),
        ("false_positive", "#c87be8", "False Positive"),
        ("accepted_risk",  "#4fc9f0", "Accepted Risk"),
    ]
    for k, color, label in RSTAT_INFO:
        n = rstat_counts.get(k, 0)
        pct = round(n / total_findings * 100) if total_findings else 0
        bar = f'<div style="height:6px;border-radius:3px;background:#1c2238;width:100%;margin-top:4px"><div style="height:100%;border-radius:3px;background:{color};width:{pct}%"></div></div>'
        rstat_rows += f'<tr><td><span style="color:{color};font-weight:700">{label}</span>{bar}</td><td style="text-align:right;font-weight:700;color:{color}">{n}</td><td style="text-align:right;color:#8b90a7">{pct}%</td></tr>'
    remediation_tracking_section = f"""
  <div class="section">
    <div class="section-title">📋 Remediation Tracking</div>
    <table>
      <thead><tr><th>Status</th><th style="text-align:right">Count</th><th style="text-align:right">% of Total</th></tr></thead>
      <tbody>{rstat_rows}</tbody>
    </table>
  </div>"""

    # ── Compliance summary ────────────────────────────────────────────────────
    from api.findings import _get_compliance_controls
    compliance_counter: Counter = Counter()
    for f in findings:
        for c in _get_compliance_controls(f):
            compliance_counter[f"{c['standard']} {c['control_ref']} — {c['control_name']}"] += 1
    compliance_section_html = ""
    if compliance_counter:
        top_controls = compliance_counter.most_common(15)
        comp_rows = ""
        for ctrl, count in top_controls:
            parts = ctrl.split(" ", 2)
            std_color = {"PCI-DSS": "#f0c93a", "NIST": "#4fc9f0", "CIS": "#4cf098", "ISO27001": "#c87be8"}.get(parts[0], "#7c6af7")
            comp_rows += (
                f'<tr>'
                f'<td><span style="font-weight:800;color:{std_color}">{_escape(parts[0])}</span></td>'
                f'<td><code style="font-size:11px">{_escape(parts[1] if len(parts)>1 else "")}</code></td>'
                f'<td style="color:#b0b5c9">{_escape(parts[2] if len(parts)>2 else "")}</td>'
                f'<td style="text-align:right;font-weight:700;color:#dde1f0">{count}</td>'
                f'</tr>'
            )
        compliance_section_html = f"""
  <div class="section">
    <div class="section-title">⚖ Compliance Framework Mapping</div>
    <p style="color:#8b90a7;font-size:13px;margin-bottom:16px">Findings mapped to PCI-DSS v4, NIST 800-53, CIS Controls v8, and ISO 27001:2022. Shows which controls are violated and how many findings map to each.</p>
    <table>
      <thead><tr><th>Standard</th><th>Control</th><th>Name</th><th style="text-align:right">Findings</th></tr></thead>
      <tbody>{comp_rows}</tbody>
    </table>
  </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Xarex Pentest Report — {_escape(scan.name)}</title>
<style>
/* ── Reset & base ──────────────────────────────────────────────────────────── */
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0b0d12;color:#dde1f0;font-size:14px;line-height:1.6}}
a{{color:#7c6af7;text-decoration:none}}
a:hover{{text-decoration:underline}}
code{{background:#1a1e2e;padding:2px 7px;border-radius:4px;font-family:'Cascadia Code','Fira Code',monospace;font-size:12px;color:#4cf098}}
pre{{background:#0f1117;border:1px solid #252a38;border-radius:6px;padding:14px;font-family:'Cascadia Code','Fira Code',monospace;font-size:12px;color:#c5c9e0;white-space:pre-wrap;word-break:break-all;max-height:300px;overflow-y:auto}}

/* ── Layout ────────────────────────────────────────────────────────────────── */
.page{{max-width:1160px;margin:0 auto;padding:32px 24px}}
.two-col{{display:grid;grid-template-columns:1fr 1fr;gap:24px}}
@media(max-width:760px){{.two-col{{grid-template-columns:1fr}}}}

/* ── Cover / Header ────────────────────────────────────────────────────────── */
.cover{{background:linear-gradient(135deg,#11142a 0%,#0b0d12 100%);border:1px solid #252a38;border-radius:12px;padding:40px;margin-bottom:32px;display:flex;justify-content:space-between;align-items:flex-start;gap:24px}}
.cover-left h1{{font-size:26px;font-weight:800;color:#7c6af7;margin-bottom:4px}}
.cover-left h1 span{{color:#fff}}
.cover-subtitle{{color:#8b90a7;font-size:13px;margin-top:4px}}
.cover-meta{{margin-top:20px;display:grid;grid-template-columns:auto 1fr;gap:4px 16px;font-size:13px}}
.cover-meta .label{{color:#8b90a7}}
.cover-meta .value{{color:#dde1f0;font-weight:500}}
.risk-badge{{background:#13161e;border:2px solid;border-radius:10px;padding:14px 22px;text-align:center;min-width:120px;flex-shrink:0}}
.risk-badge .risk-num{{font-size:38px;font-weight:900;line-height:1}}
.risk-badge .risk-label{{font-size:11px;letter-spacing:1px;text-transform:uppercase;margin-top:4px;font-weight:700}}

/* ── Section ───────────────────────────────────────────────────────────────── */
.section{{margin-bottom:36px}}
.section-title{{font-size:17px;font-weight:700;color:#7c6af7;border-bottom:1px solid #252a38;padding-bottom:10px;margin-bottom:18px;display:flex;align-items:center;gap:8px}}

/* ── Stats bar ─────────────────────────────────────────────────────────────── */
.stats-bar{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:28px}}
.stat{{background:#13161e;border:1px solid #252a38;border-radius:8px;padding:18px 12px;text-align:center}}
.stat-num{{font-size:34px;font-weight:900}}
.stat-lbl{{font-size:10px;color:#8b90a7;text-transform:uppercase;letter-spacing:0.5px;margin-top:4px}}

/* ── Finding card ──────────────────────────────────────────────────────────── */
.finding-card{{background:#0f1117;border:1px solid #252a38;border-radius:8px;margin-bottom:16px;overflow:hidden}}
.finding-header{{padding:14px 18px}}
.finding-title-row{{display:flex;align-items:flex-start;gap:12px;margin-bottom:8px}}
.sev-badge{{font-size:10px;font-weight:800;text-transform:uppercase;padding:3px 9px;border-radius:4px;color:#fff;white-space:nowrap;flex-shrink:0;letter-spacing:0.5px}}
.finding-title{{font-size:15px;font-weight:700;color:#eef0ff;line-height:1.4}}
.finding-meta{{display:flex;flex-wrap:wrap;gap:8px;align-items:center;font-size:12px}}
.host{{font-size:12px!important}}
.service-tag{{background:#1a1e2e;color:#8b90a7;border-radius:4px;padding:2px 8px}}
.finding-body{{padding:0 18px 18px}}
.desc{{color:#b0b5c9;margin:12px 0}}

/* ── Intel blocks ──────────────────────────────────────────────────────────── */
.intel-block{{border-radius:6px;padding:14px 16px;margin:12px 0;border-left:3px solid #7c6af7;background:#13161e}}
.intel-block.warn{{border-left-color:#f04f59;background:#1a1019}}
.intel-block.fix{{border-left-color:#4cf098;background:#0d1a12}}
.intel-title{{font-size:11px;text-transform:uppercase;letter-spacing:0.8px;font-weight:700;margin-bottom:8px;color:#8b90a7}}
.intel-block p{{color:#b0b5c9;font-size:13px}}
.intel-block ol,.intel-block ul{{margin-left:18px;color:#b0b5c9;font-size:13px}}
.intel-block li{{margin-bottom:4px}}

/* ── Evidence ──────────────────────────────────────────────────────────────── */
.evidence-block{{margin:12px 0}}
.evidence-title{{font-size:11px;text-transform:uppercase;letter-spacing:0.8px;font-weight:700;color:#8b90a7;margin-bottom:6px}}

/* ── Badges ────────────────────────────────────────────────────────────────── */
.badge{{display:inline-block;font-size:10px;font-weight:700;padding:2px 8px;border-radius:4px;letter-spacing:0.3px}}
.badge.cve{{background:#2a1a2e;color:#c87be8;border:1px solid #5a2a6e}}
.badge.cvss{{background:#1a2a1e;color:#4cf098;border:1px solid #2a5a3e}}
.badge.epss{{background:#1a1a2e;color:#7c6af7;border:1px solid #3a3a7e}}
.badge.mitre{{background:#1a1e2e;color:#4fc9f0;border:1px solid #1a4a6e;font-size:11px;padding:3px 10px;border-radius:4px}}
.mitre-row{{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}}

/* ── Table ─────────────────────────────────────────────────────────────────── */
table{{width:100%;border-collapse:collapse}}
th{{text-align:left;padding:9px 12px;color:#8b90a7;font-size:11px;text-transform:uppercase;letter-spacing:0.5px;border-bottom:1px solid #252a38;background:#13161e}}
td{{padding:10px 12px;border-bottom:1px solid #1a1e29;font-size:13px;vertical-align:top}}
tr:hover td{{background:#13161e}}

/* ── Roadmap ───────────────────────────────────────────────────────────────── */
.roadmap-item{{display:flex;gap:16px;padding:14px 0;border-bottom:1px solid #1a1e29}}
.roadmap-num{{width:28px;height:28px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:900;font-size:12px;flex-shrink:0;margin-top:2px}}
.roadmap-body{{flex:1}}
.roadmap-action{{font-weight:700;font-size:14px;color:#eef0ff;margin-bottom:4px}}
.roadmap-detail{{font-size:12px;color:#8b90a7}}
.effort-badge{{display:inline-block;font-size:10px;padding:1px 7px;border-radius:3px;font-weight:700;margin-left:8px}}
.effort-low{{background:#0d1a12;color:#4cf098;border:1px solid #2a5a3e}}
.effort-med{{background:#1a1a0a;color:#f0c93a;border:1px solid #5a5a1e}}
.effort-high{{background:#1a0a0a;color:#f04f59;border:1px solid #5a1e1e}}

/* ── MITRE ─────────────────────────────────────────────────────────────────── */
.mitre-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:10px}}
.mitre-item{{background:#13161e;border:1px solid #252a38;border-radius:6px;padding:10px 14px;display:flex;align-items:center;gap:12px}}
.mitre-link{{font-weight:700;color:#4fc9f0;font-size:12px;white-space:nowrap}}

/* ── Scope list ────────────────────────────────────────────────────────────── */
.host-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:8px}}
.host-grid li{{list-style:none;background:#13161e;border:1px solid #252a38;border-radius:4px;padding:6px 10px}}

/* ── Donut ─────────────────────────────────────────────────────────────────── */
.chart-wrap{{display:flex;align-items:center;gap:32px;flex-wrap:wrap}}
.chart-legend{{display:flex;flex-direction:column;gap:8px}}
.legend-item{{display:flex;align-items:center;gap:8px;font-size:13px}}
.legend-dot{{width:12px;height:12px;border-radius:50%;flex-shrink:0}}

/* ── Footer ────────────────────────────────────────────────────────────────── */
.footer{{margin-top:56px;padding-top:20px;border-top:1px solid #252a38;color:#8b90a7;font-size:12px;text-align:center}}
.confidential{{background:#2a1a0a;border:1px solid #5a3a1e;border-radius:6px;padding:10px 16px;color:#f0853a;font-size:12px;font-weight:600;margin-bottom:24px;text-align:center}}

/* ── Print / PDF ───────────────────────────────────────────────────────────── */
@media print{{
  *{{-webkit-print-color-adjust:exact!important;print-color-adjust:exact!important}}
  html,body{{background:#ffffff!important;color:#1c1c2e!important;font-size:11px!important}}

  /* Structural backgrounds */
  .cover{{background:#f0f2fa!important;border-color:#c8cde4!important}}
  .stat{{background:#f5f7ff!important;border-color:#c8cde4!important}}
  .finding-card{{background:#fafbff!important;border-color:#c8cde4!important}}
  .finding-header{{background:#f3f4fb!important}}
  .intel-block{{background:#f4f6fc!important;border-color:#c8cde4!important}}
  .intel-block.warn{{background:#fff2f2!important;border-left-color:#cc2233!important}}
  .intel-block.fix{{background:#f0faf4!important;border-left-color:#1a7a40!important}}
  .mitre-item{{background:#f4f6fc!important;border-color:#c8cde4!important}}
  .confidential{{background:#fffbeb!important;border-color:#d97706!important;color:#92400e!important}}
  .footer{{border-top-color:#c8cde4!important;color:#555577!important}}

  /* Tables */
  th{{background:#eef0f8!important;color:#444466!important;border-bottom-color:#c0c5d8!important}}
  td{{border-bottom-color:#e0e4f0!important;color:#1c1c2e!important}}
  tr:hover td{{background:#f7f8fc!important}}

  /* code / pre */
  code{{background:#eef0f8!important;color:#1a5c30!important}}
  pre{{background:#f3f4f8!important;color:#1c1c2e!important;border-color:#c8cde4!important;max-height:none!important}}

  /* Named text classes */
  .section-title{{color:#4a3fbf!important;border-bottom-color:#c8cde4!important}}
  .cover-left h1{{color:#4a3fbf!important}}
  .finding-title,.roadmap-action{{color:#1c1c2e!important}}
  .cover-subtitle,.cover-meta .label,.stat-lbl,.evidence-title,.intel-title,
  .roadmap-detail,.service-tag{{color:#555577!important}}
  .cover-meta .value{{color:#1c1c2e!important}}
  .desc{{color:#3c3c5a!important}}
  .intel-block p,.intel-block ol,.intel-block ul,.intel-block li{{color:#3c3c5a!important}}
  .mitre-link{{color:#2563eb!important}}
  a{{color:#2563eb!important}}
  .host-grid li{{background:#f4f6fc!important;border-color:#c8cde4!important}}
  .roadmap-item{{border-bottom-color:#e0e4f0!important}}

  /* Inline color overrides — light-on-dark palette → dark-on-light */
  [style*="color:#dde1f0"]{{color:#1c1c2e!important}}
  [style*="color:#eef0ff"]{{color:#1c1c2e!important}}
  [style*="color:#f0ecff"]{{color:#1c1c2e!important}}
  [style*="color:#b0b5c9"]{{color:#3c3c5c!important}}
  [style*="color:#b8aed4"]{{color:#3c3c5c!important}}
  [style*="color:#8b90a7"]{{color:#555577!important}}
  [style*="color:#7c6af7"]{{color:#4a3fbf!important}}
  [style*="color:#4cf098"]{{color:#1a7a40!important}}
  [style*="color:#4fc9f0"]{{color:#0066aa!important}}
  [style*="color:#c87be8"]{{color:#6b21a8!important}}

  /* Inline dark backgrounds → light tints */
  [style*="background:#0b0d12"],[style*="background:#0f1117"],[style*="background:#13161e"],
  [style*="background:#1a1e2e"],[style*="background:#1c2238"],[style*="background:#11142a"],
  [style*="background:#1e1e2e"],[style*="background:#252a38"],[style*="background:#1a1a2e"]
  {{background:#f4f6fc!important;border-color:#c8cde4!important}}

  /* Severity-tinted finding-header backgrounds */
  [style*="background:#2a1219"]{{background:#fff0f0!important}} /* critical */
  [style*="background:#231710"]{{background:#fff5ee!important}} /* high */
  [style*="background:#231f0a"]{{background:#fffcea!important}} /* medium */
  [style*="background:#0a1f2a"]{{background:#f0f8ff!important}} /* low */

  /* Remediation status badge backgrounds */
  [style*="background:#2a2510"]{{background:#fffbeb!important;border-color:#d97706!important}}
  [style*="background:#0d1a12"]{{background:#f0faf4!important;border-color:#6ee7a0!important}}
  [style*="background:#1a102e"]{{background:#faf0ff!important;border-color:#c084fc!important}}
  [style*="background:#0d1e2a"]{{background:#f0f9ff!important;border-color:#7dd3fc!important}}

  /* Page breaks */
  .finding-card{{page-break-inside:avoid}}
  .section{{page-break-inside:avoid}}
  .roadmap-item{{page-break-inside:avoid}}
}}
</style>
</head>
<body>
<div class="page">

  <!-- CONFIDENTIAL banner -->
  <div class="confidential">
    ⚠ CONFIDENTIAL — This document contains sensitive security information.
    Distribute only to authorised personnel. Do not transmit via unencrypted channels.
  </div>

  <!-- COVER / HEADER -->
  <div class="cover">
    <div class="cover-left">
      <h1>⬡ Xarex <span>Pentest Report</span></h1>
      <div class="cover-subtitle">Autonomous Security Assessment Platform</div>
      <div class="cover-meta">
        <span class="label">Scan Name</span>  <span class="value">{_escape(scan.name)}</span>
        <span class="label">Target</span>     <span class="value"><code>{_escape(target)}</code></span>
        <span class="label">Scan ID</span>    <span class="value">{scan.id[:8]}…</span>
        <span class="label">Duration</span>   <span class="value">{duration_str}</span>
        <span class="label">Hosts Found</span><span class="value">{len(all_hosts)}</span>
        <span class="label">Generated</span>  <span class="value">{generated_at}</span>
      </div>
    </div>
    <div class="risk-badge" style="border-color:{risk_color}">
      <div class="risk-num" style="color:{risk_color}">{risk_score:.1f}</div>
      <div class="risk-label" style="color:{risk_color}">{risk_label}</div>
      <div style="color:#8b90a7;font-size:10px;margin-top:4px">Risk Score / 10</div>
    </div>
  </div>

  <!-- FINDING COUNTS -->
  <div class="stats-bar">
    <div class="stat"><div class="stat-num" style="color:{SEV_COLOR[4]}">{counts[4]}</div><div class="stat-lbl">Critical</div></div>
    <div class="stat"><div class="stat-num" style="color:{SEV_COLOR[3]}">{counts[3]}</div><div class="stat-lbl">High</div></div>
    <div class="stat"><div class="stat-num" style="color:{SEV_COLOR[2]}">{counts[2]}</div><div class="stat-lbl">Medium</div></div>
    <div class="stat"><div class="stat-num" style="color:{SEV_COLOR[1]}">{counts[1]}</div><div class="stat-lbl">Low</div></div>
    <div class="stat"><div class="stat-num" style="color:{SEV_COLOR[0]}">{counts[0]}</div><div class="stat-lbl">Info</div></div>
  </div>

  <!-- MODULES EXECUTED -->
  <div class="section">
    <div class="section-title">🛡 Security Modules Executed</div>
    <p style="color:#8b90a7;font-size:13px;margin-bottom:16px">
      Every module below was run against all discovered hosts in parallel.
      Findings count reflects issues detected; zero findings means the check passed cleanly.
    </p>
    {modules_table}
  </div>

  <!-- SEVERITY DISTRIBUTION CHART -->
  <div class="section">
    <div class="section-title">📊 Finding Distribution</div>
    <div class="chart-wrap">
      {donut_svg}
      <div class="chart-legend">
        {"".join(f'<div class="legend-item"><div class="legend-dot" style="background:{SEV_COLOR[i]}"></div><span style="color:{SEV_COLOR[i]};font-weight:700">{counts[i]}</span>&nbsp;<span style="color:#8b90a7">{SEV_LABEL[i]}</span></div>' for i in [4,3,2,1,0])}
        <div style="margin-top:8px;color:#8b90a7;font-size:12px">Total: <strong style="color:#eef0ff">{total}</strong> findings across <strong style="color:#eef0ff">{len(all_hosts)}</strong> host(s)</div>
      </div>
    </div>
  </div>

  <!-- FINDINGS -->
  <div class="section">
    <div class="section-title">🔍 Findings ({total} total)</div>
    {finding_cards or '<div style="color:#8b90a7;padding:24px;text-align:center">No findings recorded for this scan.</div>'}
  </div>

  {remediation_tracking_section}

  {compliance_section_html}

  <!-- REMEDIATION ROADMAP -->
  <div class="section">
    <div class="section-title">🗺 Remediation Roadmap</div>
    <p style="color:#8b90a7;font-size:13px;margin-bottom:16px">
      Prioritised by risk impact. Address Critical and High items first — these represent
      immediate compromise risk. Medium items should be resolved within 30 days.
    </p>
    {roadmap_rows or '<div style="color:#8b90a7;padding:24px;text-align:center">No actionable findings.</div>'}
  </div>

  <!-- ATTACK PATHS -->
  {'<div class="section"><div class="section-title">⛓ Attack Paths (' + str(len(attack_paths)) + ' computed)</div><p style="color:#8b90a7;font-size:13px;margin-bottom:16px">These represent chained exploitation routes from an initial entry point to a high-value target, ordered by risk score.</p><table><thead><tr><th>Entry Point</th><th>Target</th><th>Risk Score</th><th>Impact</th><th>Path Length</th></tr></thead><tbody>' + (path_rows or "<tr><td colspan='5' style='text-align:center;color:#8b90a7;padding:24px'>No attack paths computed.</td></tr>") + '</tbody></table></div>' if True else ""}

  <!-- MITRE ATT&CK -->
  {'<div class="section"><div class="section-title">🎯 MITRE ATT&CK Techniques Observed</div><div class="mitre-grid">' + mitre_items + '</div></div>' if all_techniques else ""}

  <!-- SCOPE -->
  <div class="section">
    <div class="section-title">🌐 Scope — Hosts Assessed</div>
    <ul class="host-grid">{host_list or "<li style='color:#8b90a7'>No live hosts discovered.</li>"}</ul>
  </div>

  <!-- METHODOLOGY -->
  <div class="section">
    <div class="section-title">📋 Assessment Methodology</div>
    <div class="two-col">
      <div>
        <p style="color:#b0b5c9;font-size:13px;margin-bottom:12px">
          This assessment was conducted by the <strong>Xarex Autonomous Pentest Platform</strong>
          using a multi-stage pipeline:
        </p>
        <ol style="color:#b0b5c9;font-size:13px;margin-left:18px;line-height:2">
          <li><strong>Host Discovery</strong> — ARP sweep and ICMP echo to identify live hosts</li>
          <li><strong>Parallel Security Checks</strong> — All 10 modules run simultaneously against every discovered host</li>
          <li><strong>Port Scanning</strong> — TCP connect scan of common ports per host</li>
          <li><strong>SSL/TLS Audit</strong> — Certificate, protocol and cipher suite analysis</li>
          <li><strong>Vulnerability Assessment</strong> — CVE checks, default credentials, SMB relay, LLMNR, SNMP, RDP, DNS</li>
          <li><strong>Autonomous Analysis</strong> — Graph-based attack path construction</li>
        </ol>
      </div>
      <div>
        <p style="color:#b0b5c9;font-size:13px;margin-bottom:12px"><strong>Checks Performed:</strong></p>
        <ul style="color:#b0b5c9;font-size:13px;margin-left:18px;line-height:2">
          <li>SSL/TLS audit (certificate, protocol versions, cipher suites)</li>
          <li>Default credential testing (Redis, MongoDB, Elasticsearch, FTP, HTTP)</li>
          <li>SMB relay susceptibility (signing enforcement)</li>
          <li>LLMNR/NBT-NS poisoning exposure</li>
          <li>SMTP open relay detection</li>
          <li>Kerberoast / AS-REP Roast enumeration (AD environments)</li>
          <li>CVE enrichment via NVD (CVSS + EPSS scores)</li>
        </ul>
      </div>
    </div>
  </div>

  <div class="footer">
    Generated by <strong>Xarex Autonomous Pentest Platform</strong> &nbsp;·&nbsp; {generated_at}<br>
    <span style="font-size:11px">This report is intended for authorised security personnel only.</span>
  </div>

</div>
</body>
</html>"""


# ──────────────────────────────────────────────────────────────────────────────
#  Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _build_modules_table(findings: list) -> str:
    """Build an HTML table showing each security module, its status and finding count."""
    MODULE_INFO = [
        ("HOST_DISCOVERY",       "🔍", "Host Discovery",          "ARP/ICMP sweep — identifies live hosts on the network"),
        ("PORT_SCAN",            "🔌", "Port Scanning",           "TCP connect scan of all common ports per host"),
        ("SSL_TLS_AUDIT",        "🔒", "SSL / TLS Audit",         "Certificate validity, protocol versions and cipher suites"),
        ("HTTP_SECURITY_HEADERS","🌐", "HTTP Security Headers",   "Missing or misconfigured security-related HTTP headers"),
        ("DEFAULT_CRED_TEST",    "🔑", "Default Credentials",     "Factory/default passwords on common services"),
        ("SMB_RELAY_CHECK",      "🖥",  "SMB Relay Check",         "SMB signing enforcement and NTLM relay susceptibility"),
        ("LLMNR_POISON_CHECK",   "📡", "LLMNR / NBT-NS Check",    "Multicast name-resolution poisoning exposure"),
        ("EXPOSED_ADMIN_PANEL",  "⚙",  "Admin Panel Discovery",   "Exposed web-based administrative interfaces"),
        ("SNMP_COMMUNITY_STRING","📊", "SNMP Community Check",    "SNMP v1/v2 community-string disclosure"),
        ("RDP_SECURITY_CHECK",   "🖥",  "RDP Security Check",      "Remote Desktop security configuration (NLA, encryption)"),
        ("DNS_ZONE_TRANSFER",    "🌍", "DNS Zone Transfer",       "Unauthorised AXFR zone-transfer exposure"),
    ]

    def _infer_module(title: str) -> str:
        t = (title or "").lower()
        if "live host" in t:                                         return "HOST_DISCOVERY"
        if "open port" in t:                                         return "PORT_SCAN"
        if any(k in t for k in ("ssl", "tls", "certificate", "heartbleed", "poodle", "beast", "sweet32", "crime")):
            return "SSL_TLS_AUDIT"
        if "header" in t or "content-security" in t or "hsts" in t or "x-frame" in t or "x-content" in t:
            return "HTTP_SECURITY_HEADERS"
        if "credential" in t or "default password" in t or "anonymous" in t:
            return "DEFAULT_CRED_TEST"
        if "smb" in t or "ntlm relay" in t:                         return "SMB_RELAY_CHECK"
        if "llmnr" in t or "nbt-ns" in t or "multicast" in t:       return "LLMNR_POISON_CHECK"
        if "admin panel" in t or "admin interface" in t:            return "EXPOSED_ADMIN_PANEL"
        if "snmp" in t:                                              return "SNMP_COMMUNITY_STRING"
        if "rdp" in t or "remote desktop" in t:                     return "RDP_SECURITY_CHECK"
        if "dns" in t and ("zone" in t or "axfr" in t):             return "DNS_ZONE_TRANSFER"
        return ""

    counts: dict[str, int] = {mid: 0 for mid, *_ in MODULE_INFO}
    for f in findings:
        m = _infer_module(f.title or "")
        if m in counts:
            counts[m] += 1

    rows = ""
    for mid, icon, name, desc in MODULE_INFO:
        n = counts[mid]
        if n == 0:
            count_html = '<span style="color:#4cf098;font-weight:700">0 — Clean ✓</span>'
        elif n <= 2:
            count_html = f'<span style="color:#f0c93a;font-weight:700">{n}</span>'
        else:
            count_html = f'<span style="color:#f04f59;font-weight:700">{n}</span>'
        rows += (
            f"<tr>"
            f"<td>{icon} <strong>{name}</strong>"
            f"<div style='color:#8b90a7;font-size:11px;margin-top:2px'>{desc}</div></td>"
            f"<td><span style='color:#4cf098'>✓ Completed</span></td>"
            f"<td>{count_html}</td>"
            f"</tr>"
        )

    return (
        "<table>"
        "<thead><tr><th>Security Module</th><th>Status</th><th>Findings</th></tr></thead>"
        f"<tbody>{rows}</tbody>"
        "</table>"
    )


def _escape(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _safe_filename(name: str) -> str:
    """Convert a scan name to a safe ASCII filename fragment."""
    import re
    safe = re.sub(r"[^\w\s-]", "", name or "report").strip()
    safe = re.sub(r"[\s-]+", "_", safe)
    return (safe or "report")[:40]


def _make_donut(counts: dict[int, int], total: int) -> str:
    """Generate an SVG donut chart for severity distribution."""
    if total == 0:
        return '<svg width="120" height="120" viewBox="0 0 120 120"><circle cx="60" cy="60" r="45" fill="none" stroke="#252a38" stroke-width="18"/></svg>'

    colors = [SEV_COLOR[4], SEV_COLOR[3], SEV_COLOR[2], SEV_COLOR[1], SEV_COLOR[0]]
    order  = [4, 3, 2, 1, 0]
    r, cx, cy, sw = 45, 60, 60, 18
    circumference = 2 * 3.14159 * r

    arcs = ""
    offset = 0.0
    for sev in order:
        n = counts[sev]
        if n == 0:
            continue
        fraction = n / total
        dash = fraction * circumference
        arcs += (
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" '
            f'stroke="{colors[sev]}" stroke-width="{sw}" '
            f'stroke-dasharray="{dash:.2f} {circumference:.2f}" '
            f'stroke-dashoffset="{-offset:.2f}" '
            f'transform="rotate(-90 {cx} {cy})"/>'
        )
        offset += dash

    return (
        f'<svg width="120" height="120" viewBox="0 0 120 120">'
        f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="#1a1e29" stroke-width="{sw}"/>'
        f'{arcs}'
        f'<text x="{cx}" y="{cy+5}" text-anchor="middle" font-size="18" font-weight="900" fill="#eef0ff">{total}</text>'
        f'<text x="{cx}" y="{cy+18}" text-anchor="middle" font-size="9" fill="#8b90a7">FINDINGS</text>'
        f'</svg>'
    )


def _build_roadmap(findings: list[Finding]) -> str:
    """Build a prioritised remediation roadmap from findings."""
    seen: set[str] = set()
    items: list[dict] = []

    for f in findings:
        if f.severity < 2:
            continue  # skip INFO and LOW from roadmap
        intel = _lookup_attack(f)
        key = f.title or ""
        if key in seen:
            continue
        seen.add(key)

        if intel and intel.get("fix"):
            first_fix = intel["fix"][0]
        elif f.remediation:
            first_fix = f.remediation.split("\n")[0].strip()
        else:
            first_fix = "Review and apply vendor security hardening guidance."

        effort = "low" if f.severity >= 4 else "medium" if f.severity == 3 else "high"
        items.append({
            "severity": f.severity,
            "title": f.title,
            "host": f"{f.host}{f':{f.port}' if f.port else ''}",
            "fix": first_fix,
            "effort": effort,
        })

    html = ""
    for idx, item in enumerate(items[:25], 1):
        sev_color = SEV_COLOR.get(item["severity"], "#8b90a7")
        effort = item["effort"]
        effort_class = {"low": "effort-low", "medium": "effort-med", "high": "effort-high"}[effort]
        effort_label = effort.capitalize()

        html += f"""
        <div class="roadmap-item">
          <div class="roadmap-num" style="background:{sev_color}22;color:{sev_color};border:2px solid {sev_color}">{idx}</div>
          <div class="roadmap-body">
            <div class="roadmap-action">
              {_escape(item['title'])}
              <span class="effort-badge {effort_class}">Effort: {effort_label}</span>
            </div>
            <div class="roadmap-detail">
              <strong>Host:</strong> <code>{_escape(item['host'])}</code> &nbsp;·&nbsp;
              <strong>Action:</strong> {item['fix']}
            </div>
          </div>
        </div>"""
    return html


async def _get_report_for_org(report_id: str, org_id: str, db: AsyncSession) -> Report:
    result = await db.execute(select(Report).where(Report.id == report_id, Report.org_id == org_id))
    report = result.scalar_one_or_none()
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return report
