"""Xarex Cloud Brain – FastAPI application entry point."""
from __future__ import annotations

import asyncio
import threading
from contextlib import asynccontextmanager
from pathlib import Path

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from api.admin import router as admin_router
from api.assistant import router as assistant_router
from api.billing import router as billing_router
from api.leads import router as leads_router
from api.compliance import router as compliance_router
from api.findings import router as findings_router
from api.integrations import router as integrations_router
from api.phishing import router as phishing_router
from api.threat_intel import router as threat_intel_router
from api.probes import router as probes_router
from api.reports import router as reports_router
from api.scans import router as scans_router
from api.schedules import router as schedules_router
from api.templates import router as templates_router
from api.breach_monitor import router as breach_monitor_router
from api.analyzer import router as analyzer_router
from api.security_score import router as security_score_router
from api.footprint import router as footprint_router
from api.guardian import router as guardian_router
from api.domain_monitor import router as domain_monitor_router
from api.privacy_check import router as privacy_router
from api.notifications import router as notifications_router
from api.me import router as me_router
from api.recon import router as recon_router
from api.secrets import router as secrets_router
from config import settings
from limiter import limiter
from models.database import Base, engine
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# gRPC background thread
# ---------------------------------------------------------------------------

def _start_grpc_thread(port: int) -> None:
    """Run the gRPC server in a dedicated OS thread with its own event loop."""
    from services.grpc_server import serve_grpc

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(serve_grpc(port))
    except Exception as exc:  # noqa: BLE001
        logger.error("gRPC server error", error=str(exc))
    finally:
        loop.close()


# ---------------------------------------------------------------------------
# Startup recovery
# ---------------------------------------------------------------------------

async def _recover_stuck_scans() -> None:
    """Re-enqueue HOST_DISCOVERY for any scans left in 'running' state.

    When the cloud-brain restarts, in-memory task queues are cleared.
    Any scan that was still running has no tasks queued for it, so the
    probe will never receive them again. This function fixes that by
    re-issuing the initial HOST_DISCOVERY task for every stuck scan.
    Scans that genuinely completed (finding_count > 0 or counter intact)
    are skipped — only scans with 0 findings get recovered.
    """
    from models.database import AsyncSessionLocal
    from models.tables import Probe, Scan
    from orchestrator.task_manager import TaskManager, _pending_tasks
    from sqlalchemy import select

    async with AsyncSessionLocal() as db:
        # Find all probes that were online (use the most-recently-seen one).
        probe_result = await db.execute(
            select(Probe)
            .where(Probe.status == "online")
            .order_by(Probe.last_seen.desc())
            .limit(1)
        )
        probe = probe_result.scalar_one_or_none()
        if probe is None:
            logger.info("No online probe found — skipping stuck-scan recovery")
            return

        # Find scans that are "running" but have 0 findings (genuinely stuck).
        stuck_result = await db.execute(
            select(Scan)
            .where(Scan.status == "running", Scan.finding_count == 0)
        )
        stuck_scans = stuck_result.scalars().all()

        if not stuck_scans:
            return

        tm = TaskManager(db)
        for scan in stuck_scans:
            target = (scan.config or {}).get("target", "")
            if not target:
                # Can't recover without a target — mark failed
                scan.status = "failed"
                logger.warning("Stuck scan has no target in config; marked failed", scan_id=str(scan.id))
                continue

            await tm._enqueue_task(
                probe_id=probe.probe_id,
                scan_id=str(scan.id),
                task_type="HOST_DISCOVERY",
                target=target,
                options=scan.config or {},
            )
            logger.info(
                "Re-enqueued HOST_DISCOVERY for stuck scan",
                scan_id=str(scan.id),
                name=scan.name,
                target=target,
                probe_id=probe.probe_id,
            )

            # Mark this scan as recovered so the Register handler doesn't
            # enqueue it a second time when the probe reconnects.
            try:
                from services.grpc_server import _recovered_this_session
                _recovered_this_session.add(str(scan.id))
            except Exception:
                pass  # grpc_server may not be imported yet; harmless

        await db.commit()


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- startup ---
    logger.info("Xarex Cloud Brain starting", grpc_port=settings.GRPC_PORT, http_port=settings.WS_PORT)

    # Create all tables (idempotent in dev; use Alembic in production)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Add columns that may be missing from older DB schemas
        from sqlalchemy import text
        await conn.execute(text("ALTER TABLE scans ADD COLUMN IF NOT EXISTS finding_count INTEGER NOT NULL DEFAULT 0"))
        await conn.execute(text("ALTER TABLE scans ADD COLUMN IF NOT EXISTS critical_count INTEGER NOT NULL DEFAULT 0"))
        # Backfill finding counts for existing scans
        await conn.execute(text("UPDATE scans SET finding_count = (SELECT COUNT(*) FROM findings WHERE findings.scan_id = scans.id) WHERE finding_count = 0"))
        await conn.execute(text("UPDATE scans SET critical_count = (SELECT COUNT(*) FROM findings WHERE findings.scan_id = scans.id AND findings.severity = 4) WHERE critical_count = 0"))
        # Remediation tracking columns
        await conn.execute(text("ALTER TABLE findings ADD COLUMN IF NOT EXISTS remediation_status VARCHAR(32) NOT NULL DEFAULT 'new'"))
        await conn.execute(text("ALTER TABLE findings ADD COLUMN IF NOT EXISTS remediation_note TEXT"))
        await conn.execute(text("ALTER TABLE findings ADD COLUMN IF NOT EXISTS remediation_updated_at TIMESTAMPTZ"))
        # Performance indexes
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_findings_severity ON findings(severity)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_findings_host ON findings(host)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_findings_scan_sev ON findings(scan_id, severity)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_scans_status ON scans(status)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_scans_started ON scans(org_id, started_at DESC)"))
        # Threat Intelligence tables
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS ioc_watch (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
                ioc_type VARCHAR(16) NOT NULL,
                value VARCHAR(512) NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                severity VARCHAR(16) NOT NULL DEFAULT 'medium',
                active BOOLEAN NOT NULL DEFAULT TRUE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
        """))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_ioc_watch_org ON ioc_watch(org_id)"))
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS threat_intel_cache (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                lookup_key VARCHAR(512) NOT NULL UNIQUE,
                result JSONB NOT NULL DEFAULT '{}',
                fetched_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                expires_at TIMESTAMPTZ NOT NULL
            )
        """))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_threat_intel_key ON threat_intel_cache(lookup_key)"))
        # Domain Guardian table
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS domain_monitors (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
                domain VARCHAR(253) NOT NULL,
                label VARCHAR(128) NOT NULL DEFAULT '',
                status VARCHAR(32) NOT NULL DEFAULT 'pending',
                health_score INTEGER NOT NULL DEFAULT 100,
                ssl_valid BOOLEAN NOT NULL DEFAULT TRUE,
                ssl_expires_at TIMESTAMPTZ,
                ssl_days_remaining INTEGER,
                ssl_issuer VARCHAR(256),
                spf_valid BOOLEAN NOT NULL DEFAULT FALSE,
                dmarc_valid BOOLEAN NOT NULL DEFAULT FALSE,
                dkim_valid BOOLEAN NOT NULL DEFAULT FALSE,
                dmarc_policy VARCHAR(32),
                mx_records JSONB NOT NULL DEFAULT '[]',
                ns_records JSONB NOT NULL DEFAULT '[]',
                whois_expires_at TIMESTAMPTZ,
                whois_days_remaining INTEGER,
                registrar VARCHAR(256),
                lookalike_count INTEGER NOT NULL DEFAULT 0,
                lookalikes JSONB NOT NULL DEFAULT '[]',
                issues JSONB NOT NULL DEFAULT '[]',
                last_result JSONB NOT NULL DEFAULT '{}',
                last_checked TIMESTAMPTZ,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
        """))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_domain_monitors_org ON domain_monitors(org_id)"))
        # Notification Center table
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS notifications (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
                kind VARCHAR(64) NOT NULL,
                severity VARCHAR(16) NOT NULL DEFAULT 'info',
                title VARCHAR(512) NOT NULL,
                body TEXT NOT NULL DEFAULT '',
                action_url VARCHAR(512),
                action_label VARCHAR(64),
                meta JSONB NOT NULL DEFAULT '{}',
                read BOOLEAN NOT NULL DEFAULT FALSE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
        """))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_notifications_org_unread ON notifications(org_id, read, created_at DESC)"))
        # Billing — webhook idempotency unique constraint.
        # P0-5 (security-review): force the DB to dedupe duplicate Stripe
        # webhook deliveries. Wrapped in a try/except: re-running with a
        # duplicate provider_event_id (unlikely in dev, possible in older
        # deployments) would otherwise fail the constraint creation; we log
        # and continue so the rest of startup is unaffected.
        try:
            await conn.execute(text(
                "ALTER TABLE billing_events "
                "ADD CONSTRAINT ux_billing_events_provider_event_id "
                "UNIQUE (provider_event_id)"
            ))
        except Exception as _exc:  # noqa: BLE001
            logger.info(
                "billing_events unique constraint already present or could not be added",
                error=str(_exc),
            )
    logger.info("Database schema ready")

    # Recover any scans that were left "running" when the server last stopped.
    # Their in-memory task queues were wiped on restart, so we re-enqueue the
    # initial HOST_DISCOVERY task for each one so the probe can pick it up.
    await _recover_stuck_scans()
    logger.info("Startup recovery check complete")

    # Register the main event loop with ws_manager so gRPC thread can broadcast
    from services.websocket_manager import ws_manager as _ws_manager
    _ws_manager.set_main_loop(asyncio.get_event_loop())
    logger.info("WebSocket manager initialised")

    # Start gRPC server in a background daemon thread
    grpc_thread = threading.Thread(
        target=_start_grpc_thread,
        args=(settings.GRPC_PORT,),
        daemon=True,
        name="grpc-server",
    )
    grpc_thread.start()
    logger.info("gRPC background thread started", port=settings.GRPC_PORT)

    # Start autonomous scheduler
    from services.scheduler import start_scheduler, stop_scheduler
    await start_scheduler()
    logger.info("Autonomous scheduler started")

    yield

    # --- shutdown ---
    await stop_scheduler()
    logger.info("Xarex Cloud Brain shutting down")
    await engine.dispose()


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Xarex Cloud Brain",
    description=(
        "Autonomous penetration testing orchestration platform. "
        "Manages probes, scan pipelines, attack-path graphs, and real-time findings."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── Rate limiting (slowapi) ──────────────────────────────────────────────
# Routes opt in via `@limiter.limit("N/period")` decorators (see
# `api/leads.py`). RateLimitExceeded is translated into 429 by slowapi's
# stock handler. The middleware is what actually evaluates the decorators.
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

# CORS — explicit allowlist sourced from CORS_ORIGINS env var. Credentials
# are disabled because all authenticated routes carry the API key in an
# `X-API-Key` header (not a cookie), so we don't need browser credential
# semantics. A bare "*" entry is honored as an emergency open-everything
# escape hatch (NOT recommended). See config.py::CORS_ORIGINS for defaults.
_cors_origins = settings.cors_origins_list or ["*"]
_cors_open = _cors_origins == ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=False,  # token in header, not cookie
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-Admin-Secret"],
    expose_headers=["X-Request-Id"],
    max_age=600,
)
if _cors_open:
    import structlog as _slog
    _slog.get_logger(__name__).warning(
        "CORS allowlist is wide open (*). Set CORS_ORIGINS in env for production.",
    )

try:
    from fastapi.middleware.gzip import GZipMiddleware
    app.add_middleware(GZipMiddleware, minimum_size=512)
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------

app.include_router(scans_router, prefix="/api/v1")
app.include_router(probes_router, prefix="/api/v1")
app.include_router(admin_router, prefix="/api/v1")
app.include_router(findings_router, prefix="/api/v1")
app.include_router(reports_router, prefix="/api/v1")
app.include_router(schedules_router, prefix="/api/v1")
app.include_router(templates_router, prefix="/api/v1")
app.include_router(compliance_router, prefix="/api/v1")
app.include_router(integrations_router, prefix="/api/v1")
app.include_router(phishing_router, prefix="/api/v1")
app.include_router(threat_intel_router, prefix="/api/v1")
app.include_router(breach_monitor_router, prefix="/api/v1")
app.include_router(analyzer_router,       prefix="/api/v1")
app.include_router(security_score_router, prefix="/api/v1")
app.include_router(footprint_router,      prefix="/api/v1")
app.include_router(guardian_router,       prefix="/api/v1")
app.include_router(domain_monitor_router, prefix="/api/v1")
app.include_router(privacy_router,        prefix="/api/v1")
app.include_router(notifications_router,  prefix="/api/v1")
app.include_router(me_router,             prefix="/api/v1")
app.include_router(recon_router,           prefix="/api/v1")
app.include_router(secrets_router,         prefix="/api/v1")
app.include_router(assistant_router)
app.include_router(billing_router)
app.include_router(leads_router, prefix="/api/v1", tags=["leads"])

# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/health", tags=["system"])
async def health_check() -> JSONResponse:
    """Liveness probe endpoint."""
    return JSONResponse(
        content={
            "status": "ok",
            "service": "xarex-cloud-brain",
            "version": "1.0.0",
        }
    )


# ---------------------------------------------------------------------------
# Static files (frontend)
# ---------------------------------------------------------------------------

# Wrap StaticFiles so that index.html / app.js / style.css always revalidate
# with the server (cheap ETag-based 304s) instead of being served from the
# browser's disk cache for hours. Without this, customers / devs need to do
# Ctrl-Shift-R after every dashboard deploy or they get the previous version's
# JS and bail with mysterious "function not defined" errors.
class _RevalidatingStatic(StaticFiles):
    async def get_response(self, path, scope):
        response = await super().get_response(path, scope)
        ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
        if ext in {"html", "js", "css"} or path in {"", "/"}:
            # `no-cache` = browser MUST revalidate via ETag / If-Modified-Since.
            # `must-revalidate` blocks stale-while-revalidate proxies.
            response.headers["Cache-Control"] = "no-cache, must-revalidate"
        return response


# Static mounts — order matters: more-specific paths first, root last.
#
# /app/*  → dashboard SPA  (frontend/)
# /signup → dashboard SPA  (so the marketing "Start free trial" CTAs work)
# /       → marketing site (website/)
#
# Anything that's an API route (e.g. /api/v1/*, /health) is handled by the
# FastAPI routers above BEFORE these mounts, so the static catch-all at /
# never intercepts API traffic.

from fastapi.responses import RedirectResponse

_repo_root      = Path(__file__).parent.parent
_frontend_dir   = _repo_root / "frontend"   # the authenticated dashboard SPA
_website_dir    = _repo_root / "website"    # the public marketing site


@app.get("/signup", include_in_schema=False)
async def _signup_redirect():
    """Marketing-site CTAs link to /signup — bounce them into the dashboard.

    The dashboard's connect modal handles new-user signup via the existing
    Stripe checkout flow. Keeping this as a redirect lets us change the
    target later (e.g. a dedicated /signup page) without re-deploying the
    marketing site.
    """
    return RedirectResponse(url="/app/", status_code=302)


@app.get("/demo", include_in_schema=False)
async def _demo_redirect():
    """Pretty URL for the demo page — bounces /demo to /demo.html."""
    return RedirectResponse(url="/demo.html", status_code=302)


if _frontend_dir.exists() and _frontend_dir.is_dir():
    app.mount("/app", _RevalidatingStatic(directory=str(_frontend_dir), html=True), name="dashboard")
    logger.info("Dashboard mounted at /app", path=str(_frontend_dir))
else:
    logger.info(
        "Frontend directory not found – skipping dashboard mount",
        expected_path=str(_frontend_dir),
    )

if _website_dir.exists() and _website_dir.is_dir():
    app.mount("/", _RevalidatingStatic(directory=str(_website_dir), html=True), name="marketing")
    logger.info("Marketing site mounted at /", path=str(_website_dir))
else:
    logger.warning(
        "Marketing site directory not found – root will 404",
        expected_path=str(_website_dir),
    )


# ---------------------------------------------------------------------------
# Entry point (for direct execution / development)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=settings.WS_PORT,
        reload=True,
        log_level="info",
    )
