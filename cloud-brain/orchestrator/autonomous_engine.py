"""Autonomous Decision Engine — the 'brain' of Xarex.

Analyses each finding as it arrives and autonomously queues follow-up tasks:

  Port 445 open   →  SMB_RELAY_CHECK + EXPLOIT_CHECK:ms17_010
  Port 88 open    →  KERBEROAST_ENUM + ASREP_ROAST_ENUM
  Port 389/636    →  ACTIVE_DIRECTORY_ENUM
  Any cred port   →  DEFAULT_CRED_TEST
  Critical CVE    →  Immediate notification
  Scan complete   →  AI analysis + report generation

Maintains per-scan deduplication so the same check is never queued twice.
"""
from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import structlog

from sqlalchemy.ext.asyncio import AsyncSession

logger = structlog.get_logger(__name__)

# ──────────────────────────────────────────────
#  Port → task-type mapping
# ──────────────────────────────────────────────

# Maps port numbers to additional task types to queue
PORT_TASK_MAP: dict[int, list[str]] = {
    443:   ["SSL_TLS_AUDIT", "HTTP_SECURITY_HEADERS", "EXPOSED_ADMIN_PANEL", "NUCLEI_SCAN"],  # HTTPS
    8443:  ["SSL_TLS_AUDIT", "HTTP_SECURITY_HEADERS", "EXPOSED_ADMIN_PANEL", "NUCLEI_SCAN"],  # HTTPS alt
    80:    ["HTTP_SECURITY_HEADERS", "EXPOSED_ADMIN_PANEL", "NUCLEI_SCAN"],                   # HTTP
    8080:  ["HTTP_SECURITY_HEADERS", "EXPOSED_ADMIN_PANEL", "VULN_CHECK", "NUCLEI_SCAN"],    # HTTP alt
    8888:  ["HTTP_SECURITY_HEADERS", "EXPOSED_ADMIN_PANEL", "NUCLEI_SCAN"],                   # HTTP alt 2
    993:   ["SSL_TLS_AUDIT"],                            # IMAPS
    995:   ["SSL_TLS_AUDIT"],                            # POP3S
    465:   ["SSL_TLS_AUDIT"],                            # SMTPS
    445:   ["SMB_RELAY_CHECK", "VULN_CHECK"],            # SMB → relay + MS17-010
    139:   ["SMB_RELAY_CHECK"],                          # NetBIOS SMB
    88:    ["KERBEROAST_ENUM", "ASREP_ROAST_ENUM"],      # Kerberos → AD attacks
    389:   ["ACTIVE_DIRECTORY_ENUM"],                    # LDAP
    636:   ["ACTIVE_DIRECTORY_ENUM", "SSL_TLS_AUDIT"],   # LDAPS
    3268:  ["ACTIVE_DIRECTORY_ENUM"],                    # LDAP Global Catalog
    22:    ["DEFAULT_CRED_TEST"],                        # SSH
    21:    ["DEFAULT_CRED_TEST"],                        # FTP
    23:    ["DEFAULT_CRED_TEST"],                        # Telnet
    25:    ["DEFAULT_CRED_TEST"],                        # SMTP → open relay check
    587:   ["DEFAULT_CRED_TEST"],                        # SMTP submission → open relay check
    3389:  ["DEFAULT_CRED_TEST", "RDP_SECURITY_CHECK"],  # RDP → cred test + security audit
    5900:  ["DEFAULT_CRED_TEST"],                        # VNC
    5432:  ["DEFAULT_CRED_TEST"],                        # PostgreSQL
    3306:  ["DEFAULT_CRED_TEST"],                        # MySQL
    1433:  ["DEFAULT_CRED_TEST"],                        # MSSQL
    6379:  ["DEFAULT_CRED_TEST"],                        # Redis
    27017: ["DEFAULT_CRED_TEST"],                        # MongoDB
    9200:  ["DEFAULT_CRED_TEST"],                        # Elasticsearch
    11211: ["DEFAULT_CRED_TEST"],                        # Memcached
    161:   ["SNMP_COMMUNITY_STRING"],                    # SNMP → dedicated community string check
    53:    ["DNS_ZONE_TRANSFER"],                        # DNS → zone transfer attempt
    4848:  ["DEFAULT_CRED_TEST"],                        # GlassFish admin
    7001:  ["VULN_CHECK"],                               # WebLogic
    2375:  ["VULN_CHECK"],                               # Docker daemon (unauthenticated)
    6443:  ["VULN_CHECK"],                               # Kubernetes API
    9090:  ["VULN_CHECK"],                               # Prometheus
    10000: ["DEFAULT_CRED_TEST"],                        # Webmin
    502:   ["VULN_CHECK"],                               # Modbus (ICS)
    102:   ["VULN_CHECK"],                               # S7comm (ICS)
}

# Title substrings that indicate "open port" findings (to extract port from)
OPEN_PORT_TITLES = ("open port", "port discovered", "live host")

# In-memory dedup: scan_id → set of (probe_id, task_type, target) already queued
_queued_checks: dict[str, set[tuple[str, str, str]]] = {}


class AutonomousEngine:
    """Decides what to do next based on incoming findings."""

    def __init__(self) -> None:
        pass

    # ──────────────────────────────────────────────
    #  Public API
    # ──────────────────────────────────────────────

    async def on_finding(
        self,
        finding: Any,                   # models.tables.Finding ORM object
        probe_id: str,
        scan_id: str,
        db: "AsyncSession",
    ) -> list[dict[str, Any]]:
        """
        Called every time a new finding is persisted.

        Returns a list of task dicts to queue:
            [{"task_type": ..., "target": ..., "options": {...}}, ...]
        """
        tasks: list[dict[str, Any]] = []

        port = finding.port
        host = finding.host
        severity = finding.severity
        cve_id = finding.cve_id
        title = (finding.title or "").lower()

        # 1a. Fingerprint every open port
        if port:
            key = (scan_id, "SERVICE_FINGERPRINT", f"{host}:{port}")
            if self._dedup_check(scan_id, key):
                tasks.append({
                    "task_type": "SERVICE_FINGERPRINT",
                    "target": host,
                    "options": {
                        "host": host,
                        "port": str(port),
                        "service": finding.service or "",
                    },
                })

        # 1b-pre. On host discovery (no port), queue broad host-level checks:
        #   - SNMP community string check (UDP 161 — probed by scanner itself)
        #   - DNS zone transfer attempt (TCP 53 — scanner derives zones from hostname)
        if not port and "live host" in title:
            for host_task in ("SNMP_COMMUNITY_STRING", "DNS_ZONE_TRANSFER"):
                key = (scan_id, host_task, host)
                if self._dedup_check(scan_id, key):
                    tasks.append({
                        "task_type": host_task,
                        "target": host,
                        "options": {"host": host},
                    })
                    logger.info(
                        "Autonomous task queued",
                        reason="host discovery",
                        task=host_task,
                        host=host,
                        scan_id=scan_id,
                    )

        # 1b. Port-based autonomous task dispatch
        # Dedup key includes port so cred checks fire once per (host, port) — not
        # once per host. Without the port, only the first open-port finding would
        # trigger DEFAULT_CRED_TEST and every other open service would be skipped.
        if port and port in PORT_TASK_MAP:
            for task_type in PORT_TASK_MAP[port]:
                key = (scan_id, task_type, f"{host}:{port}")
                if self._dedup_check(scan_id, key):
                    tasks.append({
                        "task_type": task_type,
                        "target": host,
                        "options": {
                            "host": host,
                            "port": str(port),
                            "service": finding.service or "",
                            "check_type": _port_check_type(port),
                            "subnet": "",
                        },
                    })
                    logger.info(
                        "Autonomous task queued",
                        reason=f"port {port} open",
                        task=task_type,
                        host=host,
                        scan_id=scan_id,
                    )

        # 2. CVE enrichment trigger (handled by cve_enricher separately)
        if cve_id and severity >= 3:
            logger.info("High/Critical CVE finding — enrichment triggered", cve_id=cve_id, host=host)

        # 3. Lateral movement: if host has critical vuln, probe neighbours
        if severity == 4:
            lateral_tasks = await self._plan_lateral_checks(host, probe_id, scan_id, db)
            tasks.extend(lateral_tasks)

        return tasks

    async def on_scan_complete(
        self,
        scan_id: str,
        org_id: str,
    ) -> None:
        """Called when all pipeline stages complete. Triggers AI analysis + report."""
        from services.ai_analyst import AIAnalyst
        from services.notifier import Notifier
        from api.reports import generate_report
        from models.database import AsyncSessionLocal

        async with AsyncSessionLocal() as db:
            try:
                await generate_report(scan_id, org_id, db)
                logger.info("Report generated on scan complete", scan_id=scan_id)
            except Exception as exc:
                logger.warning("Report generation failed", scan_id=scan_id, error=str(exc))

            try:
                analyst = AIAnalyst()
                await analyst.analyse_scan(scan_id, db)
                logger.info("AI analysis complete", scan_id=scan_id)
            except Exception as exc:
                logger.warning("AI analysis failed", scan_id=scan_id, error=str(exc))

            try:
                notifier = Notifier()
                await notifier.notify_scan_complete(scan_id, db)
            except Exception as exc:
                logger.warning("Scan-complete notification failed", scan_id=scan_id, error=str(exc))

        # Clean up dedup state
        _queued_checks.pop(scan_id, None)

    # ──────────────────────────────────────────────
    #  Private helpers
    # ──────────────────────────────────────────────

    def _dedup_check(self, scan_id: str, key: tuple[str, str, str]) -> bool:
        """Return True (and register) if this key has NOT been queued yet."""
        if scan_id not in _queued_checks:
            _queued_checks[scan_id] = set()
        if key in _queued_checks[scan_id]:
            return False
        _queued_checks[scan_id].add(key)
        return True

    async def _plan_lateral_checks(
        self,
        compromised_host: str,
        probe_id: str,
        scan_id: str,
        db: "AsyncSession",
    ) -> list[dict[str, Any]]:
        """
        When a critical vuln is found on a host, queue credential tests and
        SMB relay checks against hosts in the same /24 subnet.
        """
        from sqlalchemy import select
        from models.tables import Finding

        tasks: list[dict[str, Any]] = []

        # Find other live hosts in the same /24
        parts = compromised_host.split(".")
        if len(parts) != 4:
            return tasks
        subnet_prefix = ".".join(parts[:3]) + "."

        result = await db.execute(
            select(Finding.host)
            .where(Finding.scan_id == scan_id)
            .distinct()
        )
        all_hosts: list[str] = [row[0] for row in result.fetchall()]

        for host in all_hosts:
            if host == compromised_host:
                continue
            if not host.startswith(subnet_prefix):
                continue
            key = (scan_id, "SMB_RELAY_CHECK", host)
            if self._dedup_check(scan_id, key):
                tasks.append({
                    "task_type": "SMB_RELAY_CHECK",
                    "target": host,
                    "options": {"host": host, "reason": f"lateral from critical host {compromised_host}"},
                })
                logger.info("Lateral movement task queued", target=host, source=compromised_host, scan_id=scan_id)

        return tasks


# ──────────────────────────────────────────────
#  Module-level singleton
# ──────────────────────────────────────────────

engine = AutonomousEngine()


def _port_check_type(port: int) -> str:
    """Map a port number to a VULN_CHECK check_type hint for the probe dispatcher."""
    return {
        445:   "smb_relay",
        2375:  "docker_unauth",
        6443:  "k8s_unauth",
        502:   "modbus",
        102:   "s7comm",
        7001:  "weblogic",
        9090:  "prometheus_unauth",
    }.get(port, "generic")
