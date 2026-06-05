"""Scan orchestration: task queue, pipeline management, finding processing."""
from __future__ import annotations

import asyncio
import queue as stdlib_queue
import uuid
from datetime import datetime, timezone
from typing import Any

import structlog
from sqlalchemy import select, update, text
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from graph.engine import FindingInput, GraphEngine
from models.schemas import ScanTask
from models.tables import Finding, GraphEdge, GraphNode, AttackPath, Scan

logger = structlog.get_logger(__name__)

# First pipeline stage — always HOST_DISCOVERY
DEFAULT_PIPELINE: list[str] = ["HOST_DISCOVERY"]

# Security checks run per-host after HOST_DISCOVERY completes.
#
# Only port-agnostic checks belong here. Anything that depends on which port
# a service runs on (SSL_TLS_AUDIT, HTTP_SECURITY_HEADERS, DEFAULT_CRED_TEST,
# SMB_RELAY_CHECK, EXPOSED_ADMIN_PANEL, RDP_SECURITY_CHECK, WEB_APP_SCAN,
# NUCLEI_SCAN) is dispatched per-open-port by `autonomous_engine.PORT_TASK_MAP`
# after PORT_SCAN findings stream in. Including those types here as well
# caused every web-port finding to appear TWICE in the dashboard.
PER_HOST_CHECKS: list[str] = [
    "PORT_SCAN",
    "LLMNR_POISON_CHECK",
    "SNMP_COMMUNITY_STRING",
    "DNS_ZONE_TRANSFER",
]

# In-memory stores (per-process; shared via singleton pattern)
# stdlib_queue.SimpleQueue is thread-safe — required because the gRPC server
# runs in a dedicated OS thread with its own event loop, while the API runs
# in the main uvicorn event loop. asyncio.Queue is NOT safe across threads.
_task_queues: dict[str, stdlib_queue.SimpleQueue] = {}  # probe_id → queue
_scan_graphs: dict[str, GraphEngine] = {}               # scan_id → engine
_task_type_map: dict[str, str] = {}                     # task_id → task_type (thread-safe reads/writes via GIL)
_pending_tasks: dict[str, int] = {}                     # scan_id → remaining per-host task count


class TaskManager:
    """Create scans, dispatch tasks, and process results."""

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    # ------------------------------------------------------------------
    # Scan creation
    # ------------------------------------------------------------------

    async def create_scan(
        self, org_id: str, probe_id: str, config: dict[str, Any], name: str
    ) -> Scan:
        """
        Persist a new scan record and seed its initial task queue.

        The first stage (HOST_DISCOVERY) is enqueued immediately; subsequent
        stages are enqueued as each stage completes.
        """
        scan = Scan(
            id=str(uuid.uuid4()),
            org_id=org_id,
            probe_id=probe_id,
            name=name,
            status="pending",
            config=config,
        )
        self._db.add(scan)
        await self._db.flush()  # get scan.id before committing

        # Initialise graph engine for this scan
        _scan_graphs[scan.id] = GraphEngine(scan_id=scan.id)

        # Mark running immediately so the UI shows activity
        await self._db.execute(
            update(Scan)
            .where(Scan.id == scan.id)
            .values(status="running", started_at=datetime.now(timezone.utc))
        )

        # Seed the probe's task queue with the first pipeline stage
        target = config.get("target", "")
        await self._enqueue_task(
            probe_id=probe_id,
            scan_id=scan.id,
            task_type=DEFAULT_PIPELINE[0],
            target=target,
            options=config,
        )

        # Immediately tell the UI the probe has the task — gives live feedback
        # before the probe picks it up on its next heartbeat (up to 3s later)
        from services.websocket_manager import ws_manager
        await ws_manager.broadcast(str(scan.id), {
            "type": "TASK_STARTED",
            "scan_id": str(scan.id),
            "task_type": DEFAULT_PIPELINE[0],
            "target": target,
        })

        logger.info("Scan created", scan_id=scan.id, org_id=org_id, probe_id=probe_id)
        return scan

    # ------------------------------------------------------------------
    # Task retrieval
    # ------------------------------------------------------------------

    async def get_pending_tasks(self, probe_id: str) -> list[ScanTask]:
        """
        Drain all pending tasks across ALL probe queues and return them.

        We drain all queues (not just probe_id's) because the probe gets a new
        random ID on every restart, so tasks queued for a previous probe_id
        would otherwise be lost. In a single-probe deployment this is correct;
        in multi-probe setups a DB-backed queue would be used instead.
        """
        tasks: list[ScanTask] = []
        for q in list(_task_queues.values()):
            while True:
                try:
                    tasks.append(q.get_nowait())
                except stdlib_queue.Empty:
                    break

        if tasks:
            logger.debug("Pending tasks dispatched", probe_id=probe_id, count=len(tasks))
        return tasks

    # ------------------------------------------------------------------
    # Task completion
    # ------------------------------------------------------------------

    async def mark_task_complete(
        self, task_id: str, scan_id: str, task_type: str, probe_id: str, results: dict[str, Any]
    ) -> None:
        """
        Record task completion and advance the scan pipeline.

        After HOST_DISCOVERY, enqueues all PER_HOST_CHECKS for every discovered host
        in parallel. The scan completes when all per-host tasks have reported back.
        """
        log = logger.bind(task_id=task_id, scan_id=scan_id, task_type=task_type)

        if task_type == "HOST_DISCOVERY":
            target = results.get("target", "")
            hosts = [h.strip() for h in target.split(",") if h.strip()] if target else []

            if not hosts:
                log.info("No hosts discovered — completing scan immediately")
                await self._complete_pipeline(scan_id)
                return

            # Fetch the original scan config so per-host tasks inherit it.
            scan_result = await self._db.execute(select(Scan).where(Scan.id == scan_id))
            scan_row = scan_result.scalar_one_or_none()
            scan_options = (scan_row.config or {}) if scan_row else {}

            # Enqueue every security check for every discovered host in parallel.
            # ADD to whatever counter already exists — on_finding may have already
            # queued autonomous tasks from the live-host findings (SNMP, DNS zone
            # transfer, etc.) BEFORE this branch ran. Without the `+=`, those
            # tasks decrement an under-initialised counter and the scan completes
            # prematurely.
            total = len(hosts) * len(PER_HOST_CHECKS)
            _pending_tasks[scan_id] = _pending_tasks.get(scan_id, 0) + total
            for host in hosts:
                for check_type in PER_HOST_CHECKS:
                    await self._enqueue_task(
                        probe_id=probe_id,
                        scan_id=scan_id,
                        task_type=check_type,
                        target=host,
                        options=scan_options,
                    )
            log.info("Per-host checks enqueued", hosts=len(hosts), checks_per_host=len(PER_HOST_CHECKS), total=total)

            from services.websocket_manager import ws_manager
            await ws_manager.broadcast(scan_id, {
                "type": "TASK_COMPLETED",
                "scan_id": scan_id,
                "task_type": "HOST_DISCOVERY",
                "success": True,
                "finding_count": len(hosts),
                "hosts": hosts,
                "message": f"{len(hosts)} host{'s' if len(hosts) != 1 else ''} discovered — dispatching {total} security checks",
            })

        elif task_type != "HOST_DISCOVERY":
            # Any non-HOST_DISCOVERY task is part of the per-scan workload: the
            # initial PER_HOST_CHECKS plus anything the autonomous engine queued
            # in response to findings (SERVICE_FINGERPRINT, extra DEFAULT_CRED_TEST
            # per port, KERBEROAST_ENUM, etc.). All of them must drain before we
            # mark the scan complete; otherwise findings that arrive after
            # _complete_pipeline() get dropped or attached to an already-closed scan.
            if scan_id in _pending_tasks:
                _pending_tasks[scan_id] -= 1
                remaining = _pending_tasks[scan_id]
                log.debug("Scan task done", remaining=remaining)
                if remaining <= 0:
                    del _pending_tasks[scan_id]
                    log.info("All scan tasks complete — finishing scan")
                    await self._complete_pipeline(scan_id)
            else:
                # Counter is gone — scan already completed or this is a stray late result.
                log.debug("Task result arrived after counter cleared; ignoring")

    async def _complete_pipeline(self, scan_id: str) -> None:
        """Mark scan as completed, persist graph, and trigger post-scan actions."""
        log = logger.bind(scan_id=scan_id)
        # Guard: don't re-complete an already-completed scan (prevents infinite loops
        # when late-arriving task results retrigger completion after the scan is done).
        from models.tables import Scan as _ScanCheck
        from sqlalchemy import select as _sel
        _chk = await self._db.execute(_sel(_ScanCheck).where(_ScanCheck.id == scan_id))
        _row = _chk.scalar_one_or_none()
        if _row and _row.status in ("completed", "failed"):
            log.debug("Pipeline already finished; ignoring duplicate completion", status=_row.status)
            return
        await self._update_scan_status(scan_id, "completed", completed=True)
        await self._persist_graph(scan_id)
        log.info("Scan pipeline completed")
        from services.websocket_manager import ws_manager
        ws_manager.broadcast_from_thread(scan_id, {"type": "SCAN_COMPLETED", "scan_id": scan_id})
        from sqlalchemy import select as sa_select
        from models.tables import Scan as ScanTable
        scan_result = await self._db.execute(sa_select(ScanTable).where(ScanTable.id == scan_id))
        scan = scan_result.scalar_one_or_none()
        if scan:
            # Schedule post-scan actions on the MAIN uvicorn event loop so they can
            # safely use AsyncSessionLocal (which is bound to the main loop).
            # _complete_pipeline() may run inside the gRPC thread's own event loop,
            # so we must not use asyncio.create_task() here directly.
            from services.websocket_manager import ws_manager as _wsm
            main_loop = _wsm._main_loop  # set during lifespan startup
            if main_loop is not None and main_loop.is_running():
                from orchestrator.autonomous_engine import engine as auto_engine

                async def _post_scan_work():
                    try:
                        await auto_engine.on_scan_complete(scan_id, scan.org_id)
                    except Exception as exc:
                        log.warning("Autonomous engine on_scan_complete error", error=str(exc))
                    try:
                        from services.notifier import Notifier
                        from models.database import AsyncSessionLocal
                        async with AsyncSessionLocal() as notify_db:
                            await Notifier().notify_scan_complete(scan_id, notify_db)
                    except Exception as exc:
                        log.warning("Scan-complete notification error", error=str(exc))

                asyncio.run_coroutine_threadsafe(_post_scan_work(), main_loop)
            else:
                log.warning("Main event loop unavailable; skipping post-scan actions")

    # ------------------------------------------------------------------
    # Finding processing
    # ------------------------------------------------------------------

    async def process_findings_batch(self, findings_data: list[dict[str, Any]]) -> list[Finding]:
        """
        Persist a batch of findings in one DB round-trip, then process each for
        graph, CVE enrichment, and autonomous engine tasks.
        """
        if not findings_data:
            return []

        now = datetime.now(timezone.utc)
        findings: list[Finding] = []
        scan_id = findings_data[0].get("scan_id", "")
        total_count = len(findings_data)
        critical_count = 0

        # Defensive: strip NUL bytes from every text field. Postgres rejects
        # \x00 in text/varchar columns (CharacterNotInRepertoireError) and a
        # single bad row kills the whole atomic batch insert, silently dropping
        # every finding in the batch. Scanners that exfiltrate binary-protocol
        # responses (Nuclei against Redis/memcached, fingerprint banners, etc.)
        # are the usual culprits.
        def _scrub(s):
            if isinstance(s, str) and "\x00" in s:
                return s.replace("\x00", "")
            return s

        for fd in findings_data:
            sev = int(fd.get("severity", 0))
            if sev >= 4:
                critical_count += 1
            f = Finding(
                id=str(uuid.uuid4()),
                scan_id=fd.get("scan_id", scan_id),
                host=_scrub(fd.get("host", "")),
                port=fd.get("port"),
                protocol=_scrub(fd.get("protocol")),
                service=_scrub(fd.get("service")),
                severity=sev,
                cve_id=_scrub(fd.get("cve_id")),
                title=_scrub(fd.get("title", "Unnamed finding")),
                description=_scrub(fd.get("description", "")),
                evidence=_scrub(fd.get("evidence", "")),
                remediation=_scrub(fd.get("remediation", "")),
                metadata_=fd.get("metadata", {}),
                timestamp=now,
            )
            self._db.add(f)
            findings.append(f)

        # Single UPDATE for all count increments
        await self._db.execute(
            text("UPDATE scans SET finding_count = finding_count + :n WHERE id = :sid"),
            {"n": total_count, "sid": scan_id},
        )
        if critical_count:
            await self._db.execute(
                text("UPDATE scans SET critical_count = critical_count + :n WHERE id = :sid"),
                {"n": critical_count, "sid": scan_id},
            )

        # Graph + enrichment + notifications per finding
        for finding, fd in zip(findings, findings_data):
            self._feed_graph(finding, scan_id)
            if finding.cve_id and settings.AUTO_ENRICH_CVE:
                await self._enrich_cve(finding)
            if finding.severity >= 3:
                await self._notify_finding(finding)
            probe_id = fd.get("probe_id", "")
            if probe_id:
                await self._run_autonomous_engine(finding, probe_id, scan_id)

        return findings

    async def process_finding(self, finding_data: dict[str, Any]) -> Finding:
        """Persist a single finding. Prefer process_findings_batch for multi-finding results."""
        results = await self.process_findings_batch([finding_data])
        return results[0]

    def _feed_graph(self, finding: Finding, scan_id: str) -> None:
        engine = _scan_graphs.get(scan_id)
        if engine is None:
            engine = GraphEngine(scan_id=scan_id)
            _scan_graphs[scan_id] = engine
        engine.add_finding(FindingInput(
            id=finding.id, scan_id=scan_id, host=finding.host, port=finding.port,
            protocol=finding.protocol, service=finding.service, severity=finding.severity,
            cve_id=finding.cve_id, title=finding.title, description=finding.description,
            evidence=finding.evidence, remediation=finding.remediation, metadata=finding.metadata_,
        ))

    async def _enrich_cve(self, finding: Finding) -> None:
        """Fetch CVSS/EPSS data from NVD and update finding metadata."""
        try:
            from services.cve_enricher import get_enricher
            enricher = get_enricher()
            data = await enricher.enrich(finding.cve_id)
            if data and not data.get("error"):
                meta = dict(finding.metadata_ or {})
                meta.update(data)
                finding.metadata_ = meta
                logger.info("CVE enriched", cve_id=finding.cve_id, cvss=data.get("cvss_score"))
        except Exception as exc:
            logger.warning("CVE enrichment error", cve_id=finding.cve_id, error=str(exc))

    async def _notify_finding(self, finding: Finding) -> None:
        """Fire-and-forget notification for critical/high findings."""
        try:
            from services.notifier import Notifier
            notifier = Notifier()
            await notifier.notify_critical_finding(finding)
        except Exception as exc:
            logger.warning("Notification error", finding_id=finding.id, error=str(exc))

    async def _run_autonomous_engine(self, finding: Finding, probe_id: str, scan_id: str) -> None:
        """Let the autonomous engine decide what tasks to queue next."""
        try:
            from orchestrator.autonomous_engine import engine as autonomous_engine
            extra_tasks = await autonomous_engine.on_finding(finding, probe_id, scan_id, self._db)
            if extra_tasks:
                # Always count, even if _pending_tasks[scan_id] hasn't been set
                # yet. on_finding can fire DURING the HOST_DISCOVERY-result
                # batch — before mark_task_complete(HOST_DISCOVERY) initialises
                # the counter. Initialising to 0 here means the HOST_DISCOVERY
                # branch's `+= total` adds correctly on top, instead of clobbering.
                _pending_tasks[scan_id] = _pending_tasks.get(scan_id, 0) + len(extra_tasks)
            for task_spec in extra_tasks:
                await self._enqueue_task(
                    probe_id=probe_id,
                    scan_id=scan_id,
                    task_type=task_spec["task_type"],
                    target=task_spec["target"],
                    options=task_spec.get("options", {}),
                )
        except Exception as exc:
            logger.warning("Autonomous engine error", error=str(exc))

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    async def _enqueue_task(
        self,
        probe_id: str,
        scan_id: str,
        task_type: str,
        target: str,
        options: dict[str, Any],
    ) -> ScanTask:
        if probe_id not in _task_queues:
            _task_queues[probe_id] = stdlib_queue.SimpleQueue()

        task = ScanTask(
            task_id=str(uuid.uuid4()),
            scan_id=scan_id,
            task_type=task_type,
            target=target,
            options=options,
        )
        _task_queues[probe_id].put(task)  # thread-safe, no await needed
        _task_type_map[task.task_id] = task_type  # record so gRPC thread can look up type from result
        return task

    async def _update_scan_status(
        self, scan_id: str, status: str, completed: bool = False
    ) -> None:
        values: dict[str, Any] = {"status": status}
        if status == "running":
            values["started_at"] = datetime.now(timezone.utc)
        if completed:
            values["completed_at"] = datetime.now(timezone.utc)

        await self._db.execute(
            update(Scan).where(Scan.id == scan_id).values(**values)
        )

    async def _persist_graph(self, scan_id: str) -> None:
        """
        Build attack paths from the graph engine and persist nodes/edges/paths.
        """
        engine = _scan_graphs.get(scan_id)
        if engine is None:
            return

        graph_dict = engine.to_dict()
        node_id_map: dict[str, str] = {}

        # Persist nodes
        for node in graph_dict["nodes"]:
            db_node = GraphNode(
                id=str(uuid.uuid4()),
                scan_id=scan_id,
                node_type=node["node_type"],
                identifier=node["identifier"],
                properties=node["properties"],
            )
            self._db.add(db_node)
            node_id_map[node["id"]] = db_node.id
        await self._db.flush()

        # Persist edges
        for edge in graph_dict["edges"]:
            src_db_id = node_id_map.get(edge["source"])
            tgt_db_id = node_id_map.get(edge["target"])
            if src_db_id is None or tgt_db_id is None:
                continue
            db_edge = GraphEdge(
                id=str(uuid.uuid4()),
                scan_id=scan_id,
                source_node_id=src_db_id,
                target_node_id=tgt_db_id,
                edge_type=edge["edge_type"],
                weight=edge["weight"],
                metadata_={},
            )
            self._db.add(db_edge)
        await self._db.flush()

        # Build and persist attack paths
        attack_paths = engine.build_attack_paths()
        for ap in attack_paths:
            db_ap = AttackPath(
                id=ap.id,
                scan_id=scan_id,
                nodes=[node_id_map.get(n, n) for n in ap.nodes],
                risk_score=ap.risk_score,
                impact=ap.impact,
                entry_point=node_id_map.get(ap.entry_point, ap.entry_point),
                target=node_id_map.get(ap.target, ap.target),
            )
            self._db.add(db_ap)

        logger.info(
            "Graph persisted",
            scan_id=scan_id,
            nodes=len(graph_dict["nodes"]),
            edges=len(graph_dict["edges"]),
            attack_paths=len(attack_paths),
        )
