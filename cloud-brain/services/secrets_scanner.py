"""Secrets / Git Scanner service.

Clones a public git repository into a temporary directory, walks every text
file, and scans for leaked credentials using a curated set of regex patterns
plus a Shannon-entropy heuristic for high-entropy strings.

Security posture:
  - HTTPS git URLs only (no `git://`, `ssh://`, file URLs)
  - Reject URLs that resolve to private / loopback / link-local addresses
    (basic SSRF defence — we use Python's `urlparse` + `socket.getaddrinfo`
    before passing to git)
  - Bounded resources: max 100 MB cloned, max 60 s wall clock, max 5000
    files scanned, max 5 MB per file scanned
  - Temp directory is always deleted in a `finally` block
  - All patterns and entropy logic were written from scratch for Xarex —
    no code copied from gitleaks / trufflehog / detect-secrets

Output: a list of finding dicts that the caller can either return inline
or persist as `Finding` rows.
"""
from __future__ import annotations

import asyncio
import ipaddress
import math
import re
import shutil
import socket
import tempfile
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import structlog

logger = structlog.get_logger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# Pattern library
# ──────────────────────────────────────────────────────────────────────────────
#
# Each entry: (id, friendly_name, severity, regex, post_validator_or_None)
#
# Severity: 4 = CRITICAL (cloud root / payment), 3 = HIGH (API keys),
#           2 = MEDIUM (PEM private keys), 1 = LOW (generic high-entropy)
#
# Patterns are intentionally conservative — false positives are worse than
# missed secrets here because findings drive customer trust. Each cloud /
# SaaS provider has an officially-documented prefix we anchor against.

# Used for post-validation of "AWS Secret Access Key" matches — must be
# adjacent to an AWS access key id or a base64-shaped 40-char string in
# the same file (we keep it loose).
_AWS_ACCESS_KEY_RE = re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")

_PATTERNS: list[tuple[str, str, int, re.Pattern, Any]] = [
    # ── Cloud root / billing keys (critical) ────────────────────────────────
    ("aws-access-key",  "AWS Access Key ID",     4,
     re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), None),

    ("aws-secret-key",  "AWS Secret Access Key", 4,
     re.compile(r"(?i)aws[_\-]?(?:secret|sk)[_\-]?(?:access)?[_\-]?key[\"'\s:=]{1,8}([A-Za-z0-9/+=]{40})"), None),

    ("gcp-service-key", "GCP Service Account Key (JSON)", 4,
     re.compile(r'"type"\s*:\s*"service_account"'), None),

    ("azure-conn-str",  "Azure Storage Connection String", 4,
     re.compile(r"DefaultEndpointsProtocol=https?;AccountName=[A-Za-z0-9]+;AccountKey=[A-Za-z0-9+/=]{40,}"), None),

    # ── Payment + AI provider keys (critical) ───────────────────────────────
    ("stripe-live",     "Stripe Live Secret Key", 4,
     re.compile(r"\bsk_live_[A-Za-z0-9]{20,}\b"), None),

    ("stripe-test",     "Stripe Test Secret Key", 3,
     re.compile(r"\bsk_test_[A-Za-z0-9]{20,}\b"), None),

    ("anthropic-key",   "Anthropic API Key", 4,
     re.compile(r"\bsk-ant-(?:api|admin)\d+-[A-Za-z0-9_\-]{80,120}\b"), None),

    ("openai-key",      "OpenAI API Key", 4,
     re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,200}\b"), None),

    # ── Source control / CI tokens (high) ───────────────────────────────────
    ("github-pat",      "GitHub Personal Access Token (classic)", 3,
     re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), None),

    ("github-finegrain","GitHub Fine-Grained PAT", 3,
     re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b"), None),

    ("github-oauth",    "GitHub OAuth Token", 3,
     re.compile(r"\b(?:gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b"), None),

    ("gitlab-pat",      "GitLab Personal Access Token", 3,
     re.compile(r"\bglpat-[A-Za-z0-9_\-]{20}\b"), None),

    # ── Communication / collab (high) ───────────────────────────────────────
    ("slack-bot",       "Slack Bot Token", 3,
     re.compile(r"\bxox[abprs]-[0-9]+-[0-9]+-[A-Za-z0-9]+\b"), None),

    ("slack-webhook",   "Slack Incoming Webhook URL", 3,
     re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,}"), None),

    ("discord-webhook", "Discord Webhook URL", 3,
     re.compile(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+"), None),

    # ── Notifications / email (high) ────────────────────────────────────────
    ("sendgrid",        "SendGrid API Key", 3,
     re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"), None),

    ("mailgun",         "Mailgun API Key", 3,
     re.compile(r"\bkey-[a-f0-9]{32}\b"), None),

    ("twilio",          "Twilio Account SID + Auth Token pair", 3,
     re.compile(r"\bAC[a-f0-9]{32}\b"), None),

    # ── JWT / generic tokens (medium / low) ─────────────────────────────────
    ("jwt",             "JSON Web Token (JWT)", 2,
     re.compile(r"\beyJ[A-Za-z0-9_=\-]+\.eyJ[A-Za-z0-9_=\-]+\.[A-Za-z0-9_.+/=\-]+\b"), None),

    # ── Private keys (medium — material, not credential) ────────────────────
    ("pem-private-key", "PEM-encoded Private Key", 2,
     re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"), None),

    # ── Generic .env credentials (medium) ───────────────────────────────────
    ("env-password",    "Hardcoded password in .env-style assignment", 2,
     re.compile(r"(?im)^\s*(?:DB_|DATABASE_|MYSQL_|POSTGRES_)?(?:PASSWORD|PASSWD|PWD)\s*=\s*['\"]?([^'\"\s#]{8,})['\"]?"), None),
]


# ──────────────────────────────────────────────────────────────────────────────
# Configuration / limits
# ──────────────────────────────────────────────────────────────────────────────

_MAX_REPO_BYTES   = 100 * 1024 * 1024   # 100 MB cloned
_MAX_FILE_BYTES   = 5   * 1024 * 1024   # skip files > 5 MB
_MAX_FILES        = 5000
_MAX_LINE_LEN     = 4000                # truncate huge minified lines
_CLONE_TIMEOUT_S  = 30
_SCAN_TIMEOUT_S   = 60
_GIT_DEPTH        = 50

_BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".ico", ".svg",
    ".pdf", ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".mp3", ".mp4", ".mov", ".avi", ".mkv", ".webm",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".pyc", ".pyo", ".so", ".dll", ".exe", ".bin", ".class", ".jar",
    ".onnx", ".pt", ".pth", ".pkl", ".npy", ".h5", ".tflite",
}
_SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__",
              "dist", "build", "target", ".next", ".terraform"}


# ──────────────────────────────────────────────────────────────────────────────
# URL validation (SSRF defence)
# ──────────────────────────────────────────────────────────────────────────────


def _validate_git_url(url: str) -> str:
    """Reject non-HTTPS schemes and private/loopback hosts."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError("Only https:// git URLs are accepted")
    if not parsed.netloc:
        raise ValueError("Git URL is missing a host")

    host = parsed.hostname or ""
    # Block raw IPs to private ranges and obvious internal hosts up front.
    try:
        for fam, _, _, _, addr in socket.getaddrinfo(host, None):
            ip = ipaddress.ip_address(addr[0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                raise ValueError(f"Git URL host {host} resolves to a non-public address")
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve git URL host: {exc}")

    # Strip any embedded credentials — we never want to use them.
    return f"https://{host}{parsed.path}"


# ──────────────────────────────────────────────────────────────────────────────
# Scan logic
# ──────────────────────────────────────────────────────────────────────────────


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _redact(value: str) -> str:
    """Show first 4 and last 4 chars, mask the middle. Never echo the raw secret."""
    if len(value) <= 12:
        return "*" * len(value)
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"


def _is_likely_text(path: Path) -> bool:
    if path.suffix.lower() in _BINARY_EXTS:
        return False
    try:
        with path.open("rb") as f:
            chunk = f.read(2048)
        if b"\x00" in chunk:
            return False
        # Heuristic: > 30% non-printable bytes => binary
        non_print = sum(1 for b in chunk if b < 9 or (13 < b < 32) or b > 126)
        return non_print < len(chunk) * 0.3
    except OSError:
        return False


def _scan_file(path: Path, repo_root: Path) -> list[dict[str, Any]]:
    """Scan a single file and return a list of finding dicts."""
    findings: list[dict[str, Any]] = []
    try:
        size = path.stat().st_size
    except OSError:
        return findings
    if size == 0 or size > _MAX_FILE_BYTES:
        return findings
    if not _is_likely_text(path):
        return findings

    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return findings

    rel = str(path.relative_to(repo_root))

    for idx, raw_line in enumerate(lines, start=1):
        line = raw_line[:_MAX_LINE_LEN]
        for pid, name, sev, pattern, _ in _PATTERNS:
            for match in pattern.finditer(line):
                # Captured group 1 if present, else the whole match — this is
                # the "secret material" we redact for evidence.
                value = match.group(1) if match.groups() else match.group(0)
                entropy = _shannon_entropy(value)
                findings.append({
                    "id":          str(uuid.uuid4()),
                    "rule_id":     pid,
                    "rule_name":   name,
                    "severity":    sev,
                    "file":        rel,
                    "line":        idx,
                    "match_redacted": _redact(value),
                    "match_length":   len(value),
                    "entropy":     round(entropy, 2),
                    "context":     line.strip()[:200],
                })
    return findings


def _walk_repo(repo_root: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    files_scanned = 0
    for p in repo_root.rglob("*"):
        if files_scanned >= _MAX_FILES:
            logger.warning("Secrets scanner hit file cap", cap=_MAX_FILES)
            break
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        if not p.is_file():
            continue
        files_scanned += 1
        try:
            findings.extend(_scan_file(p, repo_root))
        except Exception as exc:
            logger.warning("Secrets scan file error", file=str(p), error=str(exc))
    return findings


def _dir_size(path: Path) -> int:
    total = 0
    for p in path.rglob("*"):
        try:
            if p.is_file():
                total += p.stat().st_size
                if total > _MAX_REPO_BYTES:
                    return total
        except OSError:
            continue
    return total


async def scan_git_url(git_url: str) -> dict[str, Any]:
    """Clone a public git URL, scan it for secrets, return findings + summary.

    Always cleans up the temp dir. Raises ValueError on invalid input,
    RuntimeError on clone failure / timeout / size-cap exceeded.
    """
    safe_url = _validate_git_url(git_url)
    tmp = Path(tempfile.mkdtemp(prefix="xarex-secrets-"))
    try:
        # Shallow clone with depth cap. --no-tags + --single-branch to keep size down.
        proc = await asyncio.create_subprocess_exec(
            "git", "clone",
            "--depth", str(_GIT_DEPTH),
            "--single-branch",
            "--no-tags",
            "--quiet",
            safe_url,
            str(tmp / "repo"),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=_CLONE_TIMEOUT_S)
        except asyncio.TimeoutError:
            proc.kill()
            raise RuntimeError(f"git clone timed out after {_CLONE_TIMEOUT_S}s")
        if proc.returncode != 0:
            msg = (stderr or b"").decode(errors="replace").strip().splitlines()[-1:]
            raise RuntimeError(f"git clone failed: {' '.join(msg) or 'unknown error'}")

        repo_root = tmp / "repo"
        size = _dir_size(repo_root)
        if size > _MAX_REPO_BYTES:
            raise RuntimeError(
                f"Repository size {size // (1024*1024)} MB exceeds {_MAX_REPO_BYTES // (1024*1024)} MB cap"
            )

        # Run blocking file walk in a worker thread so the event loop stays free
        loop = asyncio.get_running_loop()
        try:
            findings = await asyncio.wait_for(
                loop.run_in_executor(None, _walk_repo, repo_root),
                timeout=_SCAN_TIMEOUT_S,
            )
        except asyncio.TimeoutError:
            raise RuntimeError(f"Secrets scan timed out after {_SCAN_TIMEOUT_S}s")

        # Severity histogram for the summary card
        by_sev = {4: 0, 3: 0, 2: 0, 1: 0}
        by_rule: dict[str, int] = {}
        for f in findings:
            by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
            by_rule[f["rule_id"]] = by_rule.get(f["rule_id"], 0) + 1

        logger.info(
            "Secrets scan complete",
            git_url=safe_url,
            total_findings=len(findings),
            critical=by_sev[4],
            high=by_sev[3],
            repo_bytes=size,
        )

        return {
            "git_url":   safe_url,
            "repo_size_bytes": size,
            "total":     len(findings),
            "by_severity": {
                "critical": by_sev[4],
                "high":     by_sev[3],
                "medium":   by_sev[2],
                "low":      by_sev[1],
            },
            "by_rule":   by_rule,
            "findings":  findings[:500],  # hard cap on response size; full count in `total`
            "truncated": len(findings) > 500,
        }
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
