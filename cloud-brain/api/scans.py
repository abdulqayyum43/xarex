"""Scan management API routes including WebSocket stream."""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import get_org
from graph.engine import GraphEngine
from models.database import get_db
from models.schemas import (
    AttackPathRead,
    GraphResponse,
    MessageResponse,
    ScanCreate,
    ScanDetail,
    ScanRead,
)
from models.tables import AttackPath, Finding, GraphEdge, GraphNode, Org, Probe, Scan
from orchestrator.task_manager import TaskManager, _scan_graphs
from services.websocket_manager import ws_manager

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/scans", tags=["scans"])


# ---------------------------------------------------------------------------
# Create scan
# ---------------------------------------------------------------------------

@router.post("", response_model=ScanRead, status_code=status.HTTP_201_CREATED)
async def create_scan(
    body: ScanCreate,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
) -> ScanRead:
    """
    Create a new scan for the authenticated org.

    The scan is assigned to the specified probe and the first pipeline
    task (HOST_DISCOVERY) is immediately queued.
    """
    # A probe must have sent a heartbeat within this window to be usable.
    _ONLINE_THRESHOLD = timedelta(minutes=5)

    def _is_alive(probe: Probe) -> bool:
        if probe.last_seen is None:
            return False
        last_seen = probe.last_seen
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) - last_seen <= _ONLINE_THRESHOLD

    # Auto-select first truly-online probe if none specified
    probe_id = body.probe_id
    if not probe_id:
        result = await db.execute(
            select(Probe)
            .where(Probe.org_id == org.id, Probe.status == "online")
            .order_by(Probe.last_seen.desc())
        )
        probe = next(
            (p for p in result.scalars().all() if _is_alive(p)),
            None,
        )
        if not probe:
            raise HTTPException(
                status_code=400,
                detail="No online probe available. Start a probe first: sudo ./xarex-probe",
            )
        probe_id = probe.probe_id
    else:
        # Explicit probe_id provided — verify it exists and is alive
        result = await db.execute(
            select(Probe).where(Probe.probe_id == probe_id, Probe.org_id == org.id)
        )
        probe = result.scalar_one_or_none()
        if probe is None:
            raise HTTPException(status_code=400, detail=f"Probe '{probe_id}' not found")
        if not _is_alive(probe):
            raise HTTPException(
                status_code=400,
                detail=f"Probe '{probe_id}' is offline (last seen: {probe.last_seen}). Restart the probe.",
            )

    tm = TaskManager(db)
    scan = await tm.create_scan(
        org_id=org.id,
        probe_id=probe_id,
        config=body.config,
        name=body.name,
    )
    await db.commit()
    await db.refresh(scan)

    # Notify any WebSocket listeners that a new scan started
    await ws_manager.broadcast(
        scan.id,
        {"event": "scan_created", "scan_id": scan.id, "status": scan.status},
    )

    return ScanRead.model_validate(scan)


# ---------------------------------------------------------------------------
# List scans
# ---------------------------------------------------------------------------

@router.get("", response_model=list[ScanRead])
async def list_scans(
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
) -> list[ScanRead]:
    """Return all scans belonging to the authenticated org."""
    result = await db.execute(select(Scan).where(Scan.org_id == org.id))
    scans = result.scalars().all()
    return [ScanRead.model_validate(s) for s in scans]


# ---------------------------------------------------------------------------
# Scan detail
# ---------------------------------------------------------------------------

@router.get("/{scan_id}", response_model=ScanDetail)
async def get_scan(
    scan_id: str,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
) -> ScanDetail:
    """Return scan detail including all findings."""
    scan = await _get_scan_or_404(scan_id, org.id, db)

    findings_result = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id)
    )
    findings = findings_result.scalars().all()

    detail = ScanDetail.model_validate(scan)
    from models.schemas import FindingRead
    detail.findings = [FindingRead.model_validate(f) for f in findings]
    return detail


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------

@router.get("/{scan_id}/graph", response_model=GraphResponse)
async def get_scan_graph(
    scan_id: str,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
) -> GraphResponse:
    """
    Return the attack graph for a scan.

    If the scan is still running, returns the in-memory graph state.
    If completed, returns the persisted graph nodes/edges.
    """
    await _get_scan_or_404(scan_id, org.id, db)

    # Prefer the live in-memory engine (available while scan is running)
    engine: GraphEngine | None = _scan_graphs.get(scan_id)
    if engine is not None:
        return GraphResponse(**engine.to_dict())

    # Fall back to persisted graph nodes/edges
    nodes_result = await db.execute(
        select(GraphNode).where(GraphNode.scan_id == scan_id)
    )
    edges_result = await db.execute(
        select(GraphEdge).where(GraphEdge.scan_id == scan_id)
    )
    nodes = nodes_result.scalars().all()
    edges = edges_result.scalars().all()

    return GraphResponse(
        nodes=[
            {
                "id": n.id,
                "node_type": n.node_type,
                "identifier": n.identifier,
                "properties": n.properties,
            }
            for n in nodes
        ],
        edges=[
            {
                "source": e.source_node_id,
                "target": e.target_node_id,
                "edge_type": e.edge_type,
                "weight": e.weight,
            }
            for e in edges
        ],
    )


# ---------------------------------------------------------------------------
# Attack paths
# ---------------------------------------------------------------------------

@router.get("/{scan_id}/attack-paths", response_model=list[AttackPathRead])
async def get_attack_paths(
    scan_id: str,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
) -> list[AttackPathRead]:
    """Return all computed attack paths for a scan, sorted by risk score."""
    await _get_scan_or_404(scan_id, org.id, db)

    result = await db.execute(
        select(AttackPath)
        .where(AttackPath.scan_id == scan_id)
        .order_by(AttackPath.risk_score.desc())
    )
    paths = result.scalars().all()
    return [AttackPathRead.model_validate(p) for p in paths]


# ---------------------------------------------------------------------------
# WebSocket stream
# ---------------------------------------------------------------------------

@router.websocket("/{scan_id}/stream")
async def scan_stream(
    scan_id: str,
    websocket: WebSocket,
    db: AsyncSession = Depends(get_db),
) -> None:
    """
    Real-time WebSocket stream for scan events.

    Clients connect and receive JSON events as findings arrive and the
    scan progresses through pipeline stages.

    Authentication is handled by query-param `api_key` since browsers
    cannot set custom headers on WebSocket connections.
    """
    # Validate api_key from query parameter
    api_key = websocket.query_params.get("api_key")
    if not api_key:
        await websocket.close(code=1008)
        return

    from sqlalchemy import select as sa_select
    from models.tables import Org as OrgTable
    result = await db.execute(sa_select(OrgTable).where(OrgTable.api_key == api_key))
    org = result.scalar_one_or_none()
    if org is None:
        await websocket.close(code=1008)
        return

    # Verify the scan belongs to this org
    scan_result = await db.execute(
        sa_select(Scan).where(Scan.id == scan_id, Scan.org_id == org.id)
    )
    scan = scan_result.scalar_one_or_none()
    if scan is None:
        await websocket.close(code=1008)
        return

    await ws_manager.connect(scan_id, websocket)
    logger.info("WebSocket client subscribed to scan", scan_id=scan_id, org_id=org.id)

    try:
        # Keep connection alive; client can send pings or just listen
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                if data == "ping":
                    await websocket.send_text('{"event":"pong"}')
            except asyncio.TimeoutError:
                # Send keep-alive ping
                try:
                    await websocket.send_text('{"event":"keepalive"}')
                except Exception:
                    break
    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected", scan_id=scan_id)
    finally:
        await ws_manager.disconnect(scan_id, websocket)


# ---------------------------------------------------------------------------
# Stop a running scan
# ---------------------------------------------------------------------------

@router.post("/{scan_id}/stop", response_model=MessageResponse)
async def stop_scan(
    scan_id: str,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    """Cancel a running scan immediately."""
    scan = await _get_scan_or_404(scan_id, org.id, db)

    if scan.status not in ("running", "pending"):
        raise HTTPException(status_code=400, detail=f"Scan is already {scan.status}")

    from datetime import datetime, timezone
    from sqlalchemy import update
    await db.execute(
        update(Scan)
        .where(Scan.id == scan_id)
        .values(status="cancelled", completed_at=datetime.now(timezone.utc))
    )
    await db.commit()

    # Remove pending tasks for this scan from in-memory queues
    import queue as stdlib_queue
    from orchestrator.task_manager import _task_queues, _pending_tasks

    if scan_id in _pending_tasks:
        del _pending_tasks[scan_id]

    for probe_id, q in list(_task_queues.items()):
        kept = []
        while True:
            try:
                task = q.get_nowait()
                if task.scan_id != scan_id:
                    kept.append(task)
            except stdlib_queue.Empty:
                break
        new_q = stdlib_queue.SimpleQueue()
        for t in kept:
            new_q.put(t)
        _task_queues[probe_id] = new_q

    await ws_manager.broadcast(scan_id, {"type": "SCAN_STOPPED", "scan_id": scan_id})
    logger.info("Scan cancelled by user", scan_id=scan_id)
    return MessageResponse(message="Scan cancelled")


# ---------------------------------------------------------------------------
# Scan diff / comparison
# ---------------------------------------------------------------------------

@router.get("/{scan_id}/diff")
async def scan_diff(
    scan_id: str,
    baseline: str | None = None,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Compare scan_id (target) against a baseline scan.

    Returns findings categorised as:
    - new:        in target, not in baseline (regressions / newly found)
    - fixed:      in baseline, not in target (remediated)
    - persistent: in both scans (unresolved)

    Findings are matched by (host, port, title) fingerprint.
    If baseline is omitted, returns all target findings as 'new'.
    """
    target_scan = await _get_scan_or_404(scan_id, org.id, db)

    target_result = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
    target_findings = target_result.scalars().all()

    SEV_WEIGHT = {4: 2.5, 3: 1.2, 2: 0.4, 1: 0.1, 0: 0.0}
    SEV_LABEL_MAP = {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Info"}

    def _fmt(f: Finding) -> dict:
        return {
            "id": f.id,
            "scan_id": f.scan_id,
            "host": f.host,
            "port": f.port,
            "title": f.title,
            "severity": f.severity,
            "severity_label": SEV_LABEL_MAP.get(f.severity, "?"),
            "cve_id": f.cve_id,
            "service": f.service,
            "remediation_status": f.remediation_status or "new",
        }

    def _key(f: Finding) -> str:
        return f"{f.host}|{f.port or ''}|{f.title}"

    if not baseline:
        return {
            "target_scan_id": scan_id,
            "baseline_scan_id": None,
            "new": [_fmt(f) for f in sorted(target_findings, key=lambda f: f.severity, reverse=True)],
            "fixed": [],
            "persistent": [],
            "risk_delta": round(sum(SEV_WEIGHT.get(f.severity, 0) for f in target_findings), 2),
            "summary": {
                "new_count": len(target_findings),
                "fixed_count": 0,
                "persistent_count": 0,
            },
        }

    baseline_scan = await _get_scan_or_404(baseline, org.id, db)
    baseline_result = await db.execute(select(Finding).where(Finding.scan_id == baseline))
    baseline_findings = baseline_result.scalars().all()

    map_baseline = {_key(f): f for f in baseline_findings}
    map_target   = {_key(f): f for f in target_findings}

    new_findings        = [f for f in target_findings  if _key(f) not in map_baseline]
    fixed_findings      = [f for f in baseline_findings if _key(f) not in map_target]
    persistent_findings = [f for f in target_findings  if _key(f) in map_baseline]

    risk_baseline = sum(SEV_WEIGHT.get(f.severity, 0) for f in baseline_findings)
    risk_target   = sum(SEV_WEIGHT.get(f.severity, 0) for f in target_findings)
    risk_delta    = round(risk_target - risk_baseline, 2)

    def _srt(lst): return sorted(lst, key=lambda f: f.severity, reverse=True)

    return {
        "target_scan_id":   scan_id,
        "baseline_scan_id": baseline,
        "new":         [_fmt(f) for f in _srt(new_findings)],
        "fixed":       [_fmt(f) for f in _srt(fixed_findings)],
        "persistent":  [_fmt(f) for f in _srt(persistent_findings)],
        "risk_delta":  risk_delta,
        "summary": {
            "new_count":        len(new_findings),
            "fixed_count":      len(fixed_findings),
            "persistent_count": len(persistent_findings),
            "risk_baseline":    round(risk_baseline, 2),
            "risk_target":      round(risk_target, 2),
        },
    }


# ---------------------------------------------------------------------------
# Rebuild attack paths for an existing completed scan
# ---------------------------------------------------------------------------

@router.post("/{scan_id}/attack-paths/rebuild")
async def rebuild_attack_paths(
    scan_id: str,
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Re-run attack-path computation on an already-completed scan using its
    persisted findings. Useful when the thresholds or graph logic have changed.
    """
    await _get_scan_or_404(scan_id, org.id, db)

    # Load all findings for this scan
    findings_result = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
    findings = findings_result.scalars().all()

    if not findings:
        return {"message": "No findings to build paths from", "attack_paths": 0}

    # Build a fresh in-memory graph from findings
    from graph.engine import FindingInput, GraphEngine
    engine = GraphEngine(scan_id=scan_id)
    for f in findings:
        engine.add_finding(FindingInput(
            id=f.id,
            scan_id=f.scan_id,
            host=f.host,
            port=f.port,
            protocol=f.protocol,
            service=f.service,
            severity=f.severity,
            cve_id=f.cve_id,
            title=f.title,
            description=f.description or "",
            evidence=f.evidence or "",
            remediation=f.remediation or "",
        ))

    attack_paths = engine.build_attack_paths()

    # Delete old attack paths for this scan then insert new ones
    from sqlalchemy import delete as sa_delete
    await db.execute(sa_delete(AttackPath).where(AttackPath.scan_id == scan_id))

    import uuid as _uuid
    for ap in attack_paths:
        db_ap = AttackPath(
            id=str(_uuid.uuid4()),
            scan_id=scan_id,
            nodes=ap.nodes,
            risk_score=ap.risk_score,
            impact=ap.impact,
            entry_point=ap.entry_point,
            target=ap.target,
        )
        db.add(db_ap)

    await db.commit()
    return {"message": "Attack paths rebuilt", "attack_paths": len(attack_paths)}


# ---------------------------------------------------------------------------
# Shared helper
# ---------------------------------------------------------------------------

async def _get_scan_or_404(scan_id: str, org_id: str, db: AsyncSession) -> Scan:
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.org_id == org_id)
    )
    scan = result.scalar_one_or_none()
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan '{scan_id}' not found",
        )
    return scan
