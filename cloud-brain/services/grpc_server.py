"""gRPC server implementing the XarexService."""
from __future__ import annotations

import asyncio
import concurrent.futures
import sys
from datetime import datetime, timezone
from pathlib import Path

import structlog

logger = structlog.get_logger(__name__)

# Ensure both the cloud-brain root AND the proto/ directory are on sys.path.
_brain_root = str(Path(__file__).parent.parent)
_proto_dir  = str(Path(__file__).parent.parent / "proto")
for _p in (_brain_root, _proto_dir):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# ---------------------------------------------------------------------------
# Proto stubs
# ---------------------------------------------------------------------------
try:
    import proto.xarex_pb2      as pb2
    import proto.xarex_pb2_grpc as pb2_grpc
    _PROTO_AVAILABLE = True
except ImportError as e:
    logger.warning("Proto stubs not found", error=str(e))
    pb2 = pb2_grpc = None
    _PROTO_AVAILABLE = False

from models.tables import Probe
from sqlalchemy import select, update

# Scan IDs re-queued in this process lifetime — prevents double-recovery.
_recovered_this_session: set[str] = set()


# ---------------------------------------------------------------------------
# Main-loop dispatcher
# ---------------------------------------------------------------------------

def _main_loop():
    """Return the main uvicorn event loop (set during lifespan startup)."""
    from services.websocket_manager import ws_manager
    return ws_manager._main_loop


def _run_on_main(coro, timeout: float = 20.0):
    """
    Schedule *coro* on the main uvicorn event loop and block until it returns.

    Must be called from a NON-main thread (i.e. the gRPC thread).
    Uses run_in_executor internally so the gRPC event loop stays responsive.
    """
    loop = _main_loop()
    if loop is None or not loop.is_running():
        raise RuntimeError("Main event loop not available")
    future = asyncio.run_coroutine_threadsafe(coro, loop)
    return future.result(timeout)


async def _run_on_main_async(coro, timeout: float = 20.0):
    """
    Await-friendly wrapper: offloads the blocking .result() call to a thread
    so the gRPC event loop is not blocked while waiting for the main loop.
    """
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None,
        lambda: _run_on_main(coro, timeout),
    )


# ---------------------------------------------------------------------------
# DB helpers — all run on the MAIN loop via AsyncSessionLocal
# ---------------------------------------------------------------------------

async def _db_upsert_probe(request) -> None:
    """Upsert probe row and mark others offline. Runs on main loop."""
    from models.database import AsyncSessionLocal
    org_id = getattr(request, "org_id", "")
    capabilities    = {"modules": list(request.capabilities)}
    nc = getattr(request, "network_context", None)
    network_context = {
        "subnets":  list(nc.subnets)  if nc else [],
        "gateways": list(nc.gateways) if nc else [],
        "hostname": nc.hostname        if nc else "",
        "os":       nc.os              if nc else "",
    }
    async with AsyncSessionLocal() as db:
        # Mark other probes for this org offline
        await db.execute(
            update(Probe)
            .where(Probe.org_id == org_id, Probe.probe_id != request.probe_id)
            .values(status="offline")
        )
        result = await db.execute(select(Probe).where(Probe.probe_id == request.probe_id))
        probe  = result.scalar_one_or_none()
        now    = datetime.now(timezone.utc)
        if probe is None:
            probe = Probe(
                probe_id=request.probe_id,
                org_id=org_id,
                version=request.version,
                capabilities=capabilities,
                network_context=network_context,
                last_seen=now,
                status="online",
            )
            db.add(probe)
        else:
            probe.org_id          = org_id
            probe.version         = request.version
            probe.capabilities    = capabilities
            probe.network_context = network_context
            probe.last_seen       = now
            probe.status          = "online"
        await db.commit()


async def _db_heartbeat_update(probe_id: str) -> None:
    """Update probe last_seen/status. Runs on main loop as fire-and-forget."""
    from models.database import AsyncSessionLocal
    async with AsyncSessionLocal() as db:
        await db.execute(
            update(Probe)
            .where(Probe.probe_id == probe_id)
            .values(last_seen=datetime.now(timezone.utc), status="online")
        )
        await db.commit()


async def _db_recover_stuck_scans(probe_id: str) -> None:
    """Re-enqueue HOST_DISCOVERY for scans stuck running with 0 findings."""
    from models.database import AsyncSessionLocal
    from models.tables import Scan
    from orchestrator.task_manager import TaskManager, _pending_tasks

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Scan).where(Scan.status == "running", Scan.finding_count == 0)
        )
        stuck = result.scalars().all()
        if not stuck:
            return
        tm = TaskManager(db)
        recovered = 0
        for scan in stuck:
            sid = str(scan.id)
            if sid in _pending_tasks or sid in _recovered_this_session:
                continue
            target = (scan.config or {}).get("target", "")
            if not target:
                scan.status = "failed"
                logger.warning("Stuck scan has no target; marking failed", scan_id=sid)
                continue
            await tm._enqueue_task(
                probe_id=probe_id, scan_id=sid,
                task_type="HOST_DISCOVERY", target=target, options=scan.config or {},
            )
            _recovered_this_session.add(sid)
            recovered += 1
            logger.info("Recovered stuck scan", scan_id=sid, target=target)
        await db.commit()
        if recovered:
            logger.info("Stuck-scan recovery complete", recovered=recovered)


async def _db_process_result(result) -> list:
    """Process one ScanResult — persist findings and advance pipeline. Returns new tasks."""
    from models.database import AsyncSessionLocal
    from orchestrator.task_manager import TaskManager, _task_type_map

    pid     = result.probe_id
    scan_id = result.scan_id
    task_id = result.task_id

    findings_data   = []
    discovered_hosts = []
    for f in result.findings:
        if f.host:
            discovered_hosts.append(f.host)
        findings_data.append({
            "scan_id":     scan_id,
            "probe_id":    pid,
            "host":        f.host,
            "port":        f.port if f.port else None,
            "protocol":    f.protocol or None,
            "service":     f.service or None,
            "severity":    int(f.severity),
            "cve_id":      f.cve_id or None,
            "title":       f.title,
            "description": f.description,
            "evidence":    f.evidence,
            "remediation": f.remediation,
            "metadata":    dict(f.metadata),
        })

    from services.websocket_manager import ws_manager

    async with AsyncSessionLocal() as db:
        tm = TaskManager(db)
        await tm.process_findings_batch(findings_data)

        for f in result.findings:
            ws_manager.broadcast_from_thread(scan_id, {
                "type":    "FINDING_DISCOVERED",
                "scan_id": scan_id,
                "finding": {
                    "host":        f.host,
                    "port":        f.port if f.port else None,
                    "severity":    int(f.severity),
                    "title":       f.title,
                    "description": f.description,
                    "service":     f.service or None,
                    "cve_id":      f.cve_id or None,
                },
            })

        if task_id:
            actual_task_type = _task_type_map.pop(task_id, "HOST_DISCOVERY")
            target = ",".join(discovered_hosts) if discovered_hosts else ""
            await tm.mark_task_complete(
                task_id=task_id, scan_id=scan_id,
                task_type=actual_task_type, probe_id=pid,
                results={"success": result.success, "error": result.error, "target": target},
            )
            ws_manager.broadcast_from_thread(scan_id, {
                "type":          "TASK_COMPLETED",
                "scan_id":       scan_id,
                "task_id":       task_id,
                "task_type":     actual_task_type,
                "success":       result.success,
                "finding_count": len(result.findings),
            })

        await db.commit()
        new_tasks = await tm.get_pending_tasks(pid)

    return new_tasks


# ---------------------------------------------------------------------------
# Task type string → proto enum int
# ---------------------------------------------------------------------------

_TASK_TYPE_MAP: dict[str, int] = {}

# Aliases: task_type strings used internally → canonical proto enum name
_TASK_TYPE_ALIASES: dict[str, str] = {
    "SERVICE_DETECTION": "SERVICE_FINGERPRINT",
    "VULN_SCAN":         "VULN_CHECK",
    "KERBEROAST":        "KERBEROAST_ENUM",
    "AD_ENUM":           "ACTIVE_DIRECTORY_ENUM",
}


def _get_task_type_map():
    global _TASK_TYPE_MAP
    if _TASK_TYPE_MAP or not _PROTO_AVAILABLE:
        return _TASK_TYPE_MAP
    # Build from the enum descriptor — never breaks on class attribute changes.
    proto_values = {v.name: v.number for v in pb2._SCANTASK_TASKTYPE.values}
    # Add canonical names directly
    _TASK_TYPE_MAP.update(proto_values)
    # Add aliases so internal task-type strings map to the right proto value
    for alias, canonical in _TASK_TYPE_ALIASES.items():
        if canonical in proto_values:
            _TASK_TYPE_MAP[alias] = proto_values[canonical]
    return _TASK_TYPE_MAP


def _schema_task_to_proto(task):
    tmap = _get_task_type_map()
    task_type_int = tmap.get(task.task_type, 0)  # 0 = HOST_DISCOVERY
    target  = task.target or ""
    options = {k: str(v) for k, v in (task.options or {}).items() if k != "target"}

    if task.task_type == "HOST_DISCOVERY":
        # Probe reads 'subnet' param; convert bare IP to /32 CIDR for single-host scans
        subnet = target if "/" in target else (target + "/32" if target else "")
        params = {"subnet": subnet, **options}
    else:
        # All per-host checks read 'host' param; also keep 'target' as fallback
        params = {"host": target, "target": target, **options}

    return pb2.ScanTask(
        task_id=task.task_id,
        scan_id=task.scan_id,
        type=task_type_int,
        params=params,
    )


# ---------------------------------------------------------------------------
# Servicer
# ---------------------------------------------------------------------------

class XarexServiceServicer:

    async def Register(self, request, context):
        # All DB work dispatched to main loop — no asyncpg cross-loop issues
        await _run_on_main_async(_db_upsert_probe(request))
        await _run_on_main_async(_db_recover_stuck_scans(request.probe_id))

        # Pending tasks live in-memory — safe to read from any thread
        from orchestrator.task_manager import _task_queues
        import queue as stdlib_queue
        tasks = []
        for q in list(_task_queues.values()):
            while True:
                try:
                    tasks.append(q.get_nowait())
                except stdlib_queue.Empty:
                    break

        logger.info("Probe registered", probe_id=request.probe_id, version=request.version,
                    pending_tasks=len(tasks))
        return self._build_heartbeat_response(tasks)

    async def Heartbeat(self, request, context):
        # ── Hot path: no DB at all ──────────────────────────────────────────
        # Drain in-memory task queue (thread-safe stdlib.SimpleQueue)
        from orchestrator.task_manager import _task_queues
        import queue as stdlib_queue
        tasks = []
        for q in list(_task_queues.values()):
            while True:
                try:
                    tasks.append(q.get_nowait())
                except stdlib_queue.Empty:
                    break

        # Update probe last_seen on main loop — fire and forget, never awaited
        main = _main_loop()
        if main and main.is_running():
            asyncio.run_coroutine_threadsafe(
                _db_heartbeat_update(request.probe_id), main
            )

        logger.debug("Heartbeat", probe_id=request.probe_id, pending=len(tasks))
        return self._build_heartbeat_response(tasks)

    async def ScanStream(self, request_iterator, context):
        """Bidirectional stream: probe sends results, cloud sends tasks."""
        probe_id: str | None = None
        sent_task_ids: set   = set()
        write_lock = asyncio.Lock()

        logger.info("ScanStream opened")

        async def _safe_write(proto_task):
            async with write_lock:
                try:
                    await context.write(proto_task)
                except Exception as exc:
                    logger.warning("ScanStream write error", error=str(exc))

        async def _process_result(result) -> list:
            nonlocal probe_id
            probe_id = result.probe_id
            logger.info("ScanResult received",
                        task_id=result.task_id, scan_id=result.scan_id,
                        findings=len(result.findings), success=result.success)
            # Dispatch all DB + notification work to main loop
            return await _run_on_main_async(_db_process_result(result))

        async def _poll_tasks() -> list:
            if not probe_id:
                return []
            from orchestrator.task_manager import _task_queues
            import queue as stdlib_queue
            tasks = []
            q = _task_queues.get(probe_id)
            if q:
                while True:
                    try:
                        tasks.append(q.get_nowait())
                    except stdlib_queue.Empty:
                        break
            if tasks:
                logger.info("ScanStream poll found tasks", count=len(tasks))
            return tasks

        loop     = asyncio.get_event_loop()
        last_poll = 0.0
        read_task: asyncio.Task = asyncio.create_task(context.read())

        try:
            while not context.cancelled():
                done, _ = await asyncio.wait({read_task}, timeout=1.0)

                if read_task in done:
                    try:
                        result = read_task.result()
                    except Exception as exc:
                        logger.warning("ScanStream read() raised", error=str(exc))
                        break

                    if result is None:
                        logger.info("ScanStream: probe closed stream")
                        break

                    try:
                        new_tasks = await _process_result(result)
                        for t in new_tasks:
                            if t.task_id not in sent_task_ids:
                                sent_task_ids.add(t.task_id)
                                await _safe_write(_schema_task_to_proto(t))
                    except Exception as exc:
                        logger.warning("ScanStream result processing error", error=str(exc))

                    read_task = asyncio.create_task(context.read())

                now = loop.time()
                if now - last_poll >= 3.0:
                    last_poll = now
                    pending = await _poll_tasks()
                    for t in pending:
                        if t.task_id not in sent_task_ids:
                            sent_task_ids.add(t.task_id)
                            logger.info("Dispatching queued task",
                                        task_id=t.task_id, task_type=t.task_type)
                            await _safe_write(_schema_task_to_proto(t))

        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.warning("ScanStream loop error", error=str(exc))
        finally:
            if not read_task.done():
                read_task.cancel()
                try:
                    await read_task
                except (asyncio.CancelledError, Exception):
                    pass

        logger.info("ScanStream ended", probe_id=probe_id)

    def _build_heartbeat_response(self, tasks):
        if not _PROTO_AVAILABLE:
            return None
        return pb2.HeartbeatResponse(
            acknowledged=True,
            pending_tasks=[_schema_task_to_proto(t) for t in tasks],
            message="OK",
        )


# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------

def create_grpc_server(port: int):
    if not _PROTO_AVAILABLE:
        logger.warning("Skipping gRPC server — proto stubs missing.")
        return None
    try:
        import grpc.aio as aio
    except ImportError:
        logger.warning("grpcio not installed; gRPC server disabled.")
        return None

    server = aio.server(options=[
        ('grpc.keepalive_permit_without_calls', 1),
        ('grpc.keepalive_time_ms', 30000),
        ('grpc.keepalive_timeout_ms', 10000),
        ('grpc.http2.min_recv_ping_interval_without_data_ms', 5000),
        ('grpc.http2.min_ping_interval_without_data_ms', 5000),
    ])
    pb2_grpc.add_XarexServiceServicer_to_server(XarexServiceServicer(), server)
    server.add_insecure_port(f"[::]:{port}")
    logger.info("gRPC server configured", port=port)
    return server


async def serve_grpc(port: int) -> None:
    server = create_grpc_server(port)
    if server is None:
        return
    await server.start()
    logger.info("gRPC server started", port=port)
    await server.wait_for_termination()
