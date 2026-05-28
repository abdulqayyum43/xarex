"""Security scan endpoints — launch, poll, cancel, download report."""
import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel
from sqlalchemy.orm import Session
from core.database import AgentRun, get_db
from core.auth import get_current_org

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])


class LaunchScanRequest(BaseModel):
    target_subnet: str
    probe_id: str | None = None
    scan_type: str = "full"
    notify_slack: str | None = None
    notify_email: str | None = None


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    target_subnet: str
    created_at: datetime


@router.post("", response_model=ScanResponse)
async def launch_scan(
    req: LaunchScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    org=Depends(get_current_org),
):
    run = AgentRun(
        id=uuid.uuid4(),
        org_id=org.id,
        agent_type="security",
        status="pending",
        input={
            "target_subnet": req.target_subnet,
            "scan_type": req.scan_type,
            "probe_id": req.probe_id,
            "notify_slack": req.notify_slack,
            "notify_email": req.notify_email,
        },
    )
    db.add(run)
    db.commit()

    background_tasks.add_task(_run_scan_async, str(run.id), req.target_subnet, req.scan_type)

    return ScanResponse(
        scan_id=str(run.id),
        status="pending",
        target_subnet=req.target_subnet,
        created_at=run.created_at,
    )


@router.get("")
def list_scans(db: Session = Depends(get_db), org=Depends(get_current_org)):
    runs = (
        db.query(AgentRun)
        .filter(AgentRun.org_id == org.id, AgentRun.agent_type == "security")
        .order_by(AgentRun.created_at.desc())
        .limit(50)
        .all()
    )
    return [
        {
            "scan_id": str(r.id),
            "status": r.status,
            "target_subnet": r.input.get("target_subnet") if r.input else None,
            "created_at": r.created_at,
        }
        for r in runs
    ]


@router.get("/{scan_id}")
def get_scan(scan_id: str, db: Session = Depends(get_db), org=Depends(get_current_org)):
    run = _get_run_or_404(db, org.id, scan_id)
    return {
        "scan_id": str(run.id),
        "status": run.status,
        "input": run.input,
        "output": run.output,
        "tokens_used": run.tokens_used,
        "created_at": run.created_at,
        "updated_at": run.updated_at,
    }


@router.get("/{scan_id}/report")
def get_report(scan_id: str, db: Session = Depends(get_db), org=Depends(get_current_org)):
    run = _get_run_or_404(db, org.id, scan_id)
    if run.status != "complete":
        raise HTTPException(status_code=202, detail="Report not ready yet")
    if not run.output or not run.output.get("report_html"):
        raise HTTPException(status_code=404, detail="Report not found")
    from fastapi.responses import HTMLResponse
    return HTMLResponse(content=run.output["report_html"])


@router.get("/{scan_id}/attack-paths")
def get_attack_paths(scan_id: str, db: Session = Depends(get_db), org=Depends(get_current_org)):
    run = _get_run_or_404(db, org.id, scan_id)
    if not run.output:
        return {"paths": []}
    return {"paths": run.output.get("attack_paths", [])}


@router.post("/{scan_id}/cancel")
def cancel_scan(scan_id: str, db: Session = Depends(get_db), org=Depends(get_current_org)):
    run = _get_run_or_404(db, org.id, scan_id)
    if run.status in ("complete", "failed", "cancelled"):
        raise HTTPException(status_code=400, detail=f"Scan already in terminal state: {run.status}")
    run.status = "cancelled"
    db.commit()
    return {"scan_id": scan_id, "status": "cancelled"}


def _get_run_or_404(db: Session, org_id, scan_id: str) -> AgentRun:
    run = (
        db.query(AgentRun)
        .filter(AgentRun.id == scan_id, AgentRun.org_id == org_id, AgentRun.agent_type == "security")
        .first()
    )
    if not run:
        raise HTTPException(status_code=404, detail="Scan not found")
    return run


def _run_scan_async(scan_id: str, target_subnet: str, scan_type: str):
    """Background task — runs the full scan pipeline."""
    from core.database import SessionLocal
    from agents.security.brain.orchestrator import run_security_analysis

    db = SessionLocal()
    try:
        run = db.query(AgentRun).filter(AgentRun.id == scan_id).first()
        if not run:
            return
        run.status = "running"
        db.commit()

        probe_data = {
            "hosts": [],
            "scan_type": scan_type,
            "note": "In production, probe results stream in via gRPC. This is a stub for direct API mode.",
        }

        result = run_security_analysis(scan_id, target_subnet, probe_data)

        run.status = "complete"
        run.output = {
            "report_html": result.report_html,
            "attack_paths": result.attack_paths,
            "hosts": result.hosts,
        }
        run.tokens_used = result.total_tokens
        db.commit()
    except Exception as e:
        run = db.query(AgentRun).filter(AgentRun.id == scan_id).first()
        if run:
            run.status = "failed"
            run.output = {"error": str(e)}
            db.commit()
    finally:
        db.close()
