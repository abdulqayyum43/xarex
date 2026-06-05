"""Xarex — billing API endpoints.

Endpoints:
  POST /api/billing/signup/free            Provision free-tier license (no payment)
  POST /api/billing/checkout/stripe        Create Stripe Checkout session
  POST /api/billing/checkout/toyyibpay     Create ToyyibPay bill
  POST /api/billing/webhook/stripe         Stripe webhook receiver
  POST /api/billing/callback/toyyibpay     ToyyibPay payment callback
  GET  /api/billing/success                Post-payment success page
  GET  /api/billing/session-status         Poll Checkout Session + License readiness
  GET  /api/billing/subscription           Check subscription status by email
  GET  /api/billing/download/{token}       Download Cloud Brain package
  GET  /api/billing/probe/linux/{token}    Download Linux probe binary
  GET  /api/billing/probe/windows/{token}  Download Windows probe binary

Security notes (api-security-reviewer remediation):
  - /session-status requires a `t=<reveal_token>` query param OR an
    HttpOnly cookie set at checkout time. The Stripe session_id ALONE is
    insufficient: it appears in browser history, referrers, dashboard
    exports, etc. (P0-1/P0-2).
  - Every missing/invalid/expired/already-consumed reveal_token returns
    a generic 404 — no oracle that distinguishes "wrong token" from
    "no token at all" (P0-1).
  - /checkout/stripe and /session-status are rate-limited per IP via
    slowapi (H-7).
  - /success rejects any session_id that doesn't match Stripe's regex
    BEFORE injecting into the HTML (H-6).

Note on `from __future__ import annotations`: deliberately NOT used here.
slowapi's `@limiter.limit(...)` decorator wraps the endpoint so FastAPI's
dependency-injection introspection resolves type hints against slowapi's
module globals. With PEP 563 deferred annotations the request-body class
name fails to resolve and Pydantic raises `PydanticUndefinedAnnotation`
at app start. See api/leads.py for the matching note.
"""
import json
import mimetypes
from pathlib import Path
from typing import Literal

import stripe as stripe_lib
import structlog
from fastapi import APIRouter, Depends, Form, Header, HTTPException, Query, Request, Response, status
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from limiter import limiter
from models.database import get_db
from models.tables import Customer, License, Subscription
from services.billing import (
    StripeSignatureError,
    cached_stripe_session_retrieve,
    create_stripe_checkout,
    create_toyyibpay_bill,
    get_license_by_email,
    get_license_by_token,
    handle_stripe_event,
    handle_toyyibpay_callback,
    is_valid_stripe_session_id,
    provision_free_license,
    validate_and_consume_reveal_token,
)
from services.pii import email_hash as _email_hash

log = structlog.get_logger(__name__)

router = APIRouter(prefix="/api/billing", tags=["billing"])


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

_REVEAL_COOKIE_NAME = "xrx_reveal"
_REVEAL_COOKIE_MAX_AGE = 600  # seconds — matches services/billing._REVEAL_TTL_SECONDS


# ─────────────────────────────────────────────────────────────────────────────
# Request / Response models
# ─────────────────────────────────────────────────────────────────────────────

class CheckoutRequest(BaseModel):
    """Used by free signup and the (legacy) ToyyibPay checkout."""
    email: EmailStr
    name: str


class StripeCheckoutRequest(BaseModel):
    """Stripe Checkout body — tier + cadence pick the right Price ID.

    `name` is optional: the marketing-site dialog only collects an email to
    keep friction low. services/billing.py falls back to the local-part of
    the email (`alice@x.com` → `alice`) when name is empty. Users can update
    their Stripe Customer name later via the dashboard / receipts.
    """
    email: EmailStr
    name: str = Field(default="", max_length=200)
    tier: Literal["starter", "pro"]
    cadence: Literal["monthly", "annual"]


class SessionStatusResponse(BaseModel):
    """Response for GET /session-status, polled by the success page.

    - ``pending``: Checkout Session not yet `complete` OR webhook hasn't
      provisioned the License row yet.
    - ``ready``: session complete AND License row exists for the customer.
    - ``failed``: Stripe reports the session as `expired` or `unpaid`.
    - ``error``: Stripe API call itself failed — the FE should stop polling
      and surface the email-credentials fallback (H-10).
    """
    status: Literal["pending", "ready", "failed", "error"]
    license: dict | None = None


class SubscriptionStatus(BaseModel):
    """Public, unauthenticated subscription-state probe.

    Security: this endpoint accepts an email query param with NO auth, so it
    must NEVER return secrets (api_key, download_token, org_id). A customer who
    has lost their credentials must request re-issuance via support, not pull
    them back via an unauth GET keyed only on an easily-guessable email.

    Safe fields only — see Issue 2 (api-security-reviewer SHIP-WITH-CHANGES).
    """
    email: str
    has_license: bool
    plan: str | None = None
    status: str | None = None
    current_period_end: str | None = None
    support_contact: str = "support@xarexsec.io"


class FreeSignupResponse(BaseModel):
    org_id: str
    api_key: str
    download_token: str
    scan_limit: int


# ─────────────────────────────────────────────────────────────────────────────
# Free plan signup
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/signup/free", response_model=FreeSignupResponse)
async def free_signup(body: CheckoutRequest, db: AsyncSession = Depends(get_db)) -> FreeSignupResponse:
    """Provision a free-tier license — no payment required."""
    if not settings.FREE_PLAN_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Free plan is not available at this time",
        )
    try:
        lic = await provision_free_license(db=db, email=body.email, name=body.name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        log.error("Free signup failed", error=str(exc), email=body.email)
        raise HTTPException(status_code=500, detail="Signup failed — please try again") from exc

    return FreeSignupResponse(
        org_id=lic.org_id,
        api_key=lic.api_key,
        download_token=lic.download_token,
        scan_limit=lic.scan_limit or settings.FREE_PLAN_SCAN_LIMIT,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Stripe checkout
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/checkout/stripe")
# H-7: per-IP rate limit. Mirrors `5/minute` on /leads but a bit higher to
# accommodate the dialog's email → checkout → back → re-submit retry flow.
@limiter.limit("10/minute")
async def stripe_checkout(
    request: Request,
    body: StripeCheckoutRequest,
) -> JSONResponse:
    """Create a Stripe Checkout Session.

    Response shape (P0-1/P0-2):
        {
          "checkout_url": "https://checkout.stripe.com/...",
          "url":          "<same as checkout_url, retained for back-compat>",
          "reveal_token": "<32B urlsafe — read on /success>"
        }

    The `reveal_token` is ALSO set as an HttpOnly, Secure, SameSite=Lax
    cookie so the /success page works even when an enterprise proxy strips
    unknown query parameters from the Stripe redirect.
    """
    if not settings.STRIPE_SECRET_KEY:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Stripe is not configured on this server",
        )
    try:
        result = await create_stripe_checkout(
            email=body.email,
            name=body.name,
            tier=body.tier,
            cadence=body.cadence,
        )
        checkout_url = result["checkout_url"]
        reveal_token = result["reveal_token"]
    except ValueError as exc:
        log.info(
            "Stripe checkout rejected — pricing not configured",
            tier=body.tier,
            cadence=body.cadence,
            error=str(exc),
        )
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        log.error("Stripe checkout creation failed", error=str(exc), email=body.email)
        raise HTTPException(status_code=500, detail="Failed to create checkout session") from exc

    response = JSONResponse({
        "checkout_url": checkout_url,
        # Retained for back-compat with any caller that still reads `url`.
        "url": checkout_url,
        "reveal_token": reveal_token,
    })
    # HttpOnly cookie fallback for when the success_url's `t=` is stripped
    # by an aggressive enterprise proxy. Scoped to /api/billing/ so it's
    # never sent to unrelated endpoints. `secure` follows the public URL —
    # http://localhost during dev must NOT set Secure or Chrome rejects.
    is_https = settings.PUBLIC_URL.startswith("https://")
    response.set_cookie(
        key=_REVEAL_COOKIE_NAME,
        value=reveal_token,
        max_age=_REVEAL_COOKIE_MAX_AGE,
        path="/api/billing/",
        httponly=True,
        secure=is_https,
        samesite="lax",
    )
    return response


# ─────────────────────────────────────────────────────────────────────────────
# ToyyibPay checkout
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/checkout/toyyibpay")
async def toyyibpay_checkout(body: CheckoutRequest) -> JSONResponse:
    """Create a ToyyibPay bill and return the payment URL."""
    if not settings.TOYYIBPAY_SECRET_KEY or not settings.TOYYIBPAY_CATEGORY_CODE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ToyyibPay is not configured on this server",
        )
    try:
        url = await create_toyyibpay_bill(email=body.email, name=body.name)
        return JSONResponse({"url": url})
    except Exception as exc:
        log.error("ToyyibPay bill creation failed", error=str(exc), email=body.email)
        raise HTTPException(status_code=500, detail="Failed to create payment bill") from exc


# ─────────────────────────────────────────────────────────────────────────────
# Stripe webhook
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/webhook/stripe", include_in_schema=False)
async def stripe_webhook(
    request: Request,
    stripe_signature: str = Header(alias="stripe-signature", default=""),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """Receive and process Stripe webhook events.

    P0-4: ONLY catch signature failures (→ 400). Every other exception
    propagates to FastAPI's default 500 handler so Stripe retries with
    exponential backoff (up to 3 days). A 200-on-everything response would
    permanently lose events on transient DB failures.
    """
    payload = await request.body()
    try:
        await handle_stripe_event(db=db, payload=payload, sig_header=stripe_signature)
    except StripeSignatureError as exc:
        # Signature verification or construct_event failure. These are NOT
        # transient — Stripe should not retry. 400 ends the redelivery loop.
        # Use a narrow custom exception (not ValueError) so processing errors
        # from inside handle_stripe_event (e.g. unknown price_id) still
        # propagate to 500 and trigger Stripe retries (P0-4).
        raise HTTPException(status_code=400, detail="invalid signature") from exc
    except Exception as exc:
        # Log full context so ops can pinpoint the failure, then re-raise so
        # FastAPI returns a 500 and Stripe retries. Crucially we do NOT
        # swallow this to a 200 anymore.
        log.error(
            "Stripe webhook processing error — bubbling to 500 for Stripe retry",
            error_class=type(exc).__name__,
            error=str(exc),
        )
        raise
    return JSONResponse({"received": True})


# ─────────────────────────────────────────────────────────────────────────────
# ToyyibPay callback
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/callback/toyyibpay", include_in_schema=False)
async def toyyibpay_callback(
    refno:   str = Form(default=""),
    status:  str = Form(default=""),
    reason:  str = Form(default=""),
    billcode: str = Form(default=""),
    order_id: str = Form(alias="order_id", default=""),
    amount:   str = Form(default=""),
    name:     str = Form(default=""),
    email:    str = Form(default=""),
    phone:    str = Form(default=""),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """Receive ToyyibPay payment result callback."""
    try:
        await handle_toyyibpay_callback(
            db=db,
            ref_no=refno,
            status=status,
            reason=reason,
            bill_code=billcode,
            order_id=order_id,
            amount=amount,
            name=name,
            email=email,
            phone=phone,
        )
        return JSONResponse({"ok": True})
    except Exception as exc:
        log.error("ToyyibPay callback processing error", error=str(exc), email=email)
        return JSONResponse({"ok": True})  # always 200 to ToyyibPay


# ─────────────────────────────────────────────────────────────────────────────
# Post-payment success page
# ─────────────────────────────────────────────────────────────────────────────

_SUCCESS_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Setting up your account — Xarex</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800;900&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet"/>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#060810;font-family:'Inter',sans-serif;color:#e8eaf6;min-height:100vh;
      display:flex;flex-direction:column;align-items:center;justify-content:center;padding:24px}}
.logo{{display:flex;align-items:center;gap:10px;margin-bottom:32px}}
.logo-mark{{width:36px;height:36px;background:#7c6af7;border-radius:8px;display:flex;align-items:center;
             justify-content:center;flex-shrink:0}}
.logo-mark svg{{display:block}}
.logo-name{{font-size:20px;font-weight:900;color:#f0ecff;letter-spacing:-.02em}}
.card{{background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.09);
       border-radius:20px;padding:44px 40px;width:100%;max-width:560px}}
#state-pending,#state-ready,#state-failed,#state-timeout{{display:none}}
#state-pending.active,#state-ready.active,#state-failed.active,#state-timeout.active{{display:block}}
.spinner-ring{{width:52px;height:52px;border:4px solid rgba(124,106,247,0.15);
               border-top-color:#7c6af7;border-radius:50%;animation:spin 1s linear infinite;
               margin:0 auto 24px}}
@keyframes spin{{to{{transform:rotate(360deg)}}}}
.state-title{{font-size:24px;font-weight:800;color:#f0ecff;margin-bottom:8px;text-align:center}}
.state-sub{{font-size:15px;color:#b8aed4;line-height:1.6;text-align:center;margin-bottom:0}}
.poll-status{{font-size:13px;color:#6b6080;text-align:center;margin-top:12px}}
.check-icon{{width:52px;height:52px;background:rgba(16,185,129,0.15);border:2px solid rgba(16,185,129,0.4);
             border-radius:50%;display:flex;align-items:center;justify-content:center;
             margin:0 auto 20px;font-size:24px}}
.plan-badge{{display:inline-flex;align-items:center;gap:6px;background:rgba(124,106,247,0.12);
             border:1px solid rgba(124,106,247,0.35);border-radius:8px;padding:5px 14px;
             font-size:13px;color:#a89df5;font-weight:700;margin-bottom:24px}}
.cred-section{{margin-bottom:20px}}
.cred-label{{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;
             color:#6b6080;margin-bottom:6px}}
.cred-row{{display:flex;align-items:center;gap:8px;background:rgba(0,0,0,0.3);
           border:1px solid rgba(255,255,255,0.08);border-radius:10px;padding:12px 14px}}
.cred-value{{font-family:'JetBrains Mono',monospace;font-size:13px;color:#c8c0f0;
             flex:1;word-break:break-all;line-height:1.4}}
.copy-btn{{flex-shrink:0;background:rgba(124,106,247,0.15);border:1px solid rgba(124,106,247,0.3);
           color:#a89df5;border-radius:7px;padding:5px 12px;font-size:12px;font-weight:700;
           cursor:pointer;transition:background .15s;white-space:nowrap}}
.copy-btn:hover{{background:rgba(124,106,247,0.3)}}
.copy-btn.copied{{background:rgba(16,185,129,0.2);border-color:rgba(16,185,129,0.4);color:#34d399}}
.dl-grid{{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:20px}}
.dl-btn{{flex:1;min-width:140px;display:flex;align-items:center;justify-content:center;gap:8px;
         background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.1);
         border-radius:10px;padding:12px 16px;font-size:13px;font-weight:700;color:#b8aed4;
         text-decoration:none;transition:border-color .15s,color .15s}}
.dl-btn:hover{{border-color:rgba(124,106,247,0.5);color:#f0ecff}}
.qs-title{{font-size:14px;font-weight:800;color:#f0ecff;margin-bottom:12px}}
.qs-step{{display:flex;gap:12px;margin-bottom:14px;align-items:flex-start}}
.qs-num{{flex-shrink:0;width:22px;height:22px;background:rgba(124,106,247,0.2);
         border-radius:50%;display:flex;align-items:center;justify-content:center;
         font-size:11px;font-weight:800;color:#a89df5;margin-top:1px}}
.qs-body{{flex:1}}
.qs-desc{{font-size:13px;color:#b8aed4;margin-bottom:6px}}
.code-block{{display:flex;align-items:center;gap:8px;background:rgba(0,0,0,0.4);
             border:1px solid rgba(255,255,255,0.07);border-radius:8px;padding:9px 12px}}
.code-block code{{font-family:'JetBrains Mono',monospace;font-size:12px;color:#7c6af7;
                  flex:1;line-height:1.4;word-break:break-all}}
.warn-banner{{display:flex;align-items:flex-start;gap:10px;background:rgba(245,158,11,0.08);
              border:1px solid rgba(245,158,11,0.25);border-radius:10px;
              padding:12px 16px;margin-top:20px;font-size:13px;color:#fbbf24;line-height:1.5}}
.fail-icon{{width:52px;height:52px;background:rgba(239,68,68,0.12);border:2px solid rgba(239,68,68,0.35);
            border-radius:50%;display:flex;align-items:center;justify-content:center;
            margin:0 auto 20px;font-size:24px}}
.action-link{{color:#7c6af7;text-decoration:none;font-weight:700}}
.action-link:hover{{text-decoration:underline}}
.page-footer{{margin-top:24px;font-size:12px;color:#4b4568;text-align:center;line-height:1.8}}
.page-footer a{{color:#6b6080;text-decoration:none}}
.page-footer a:hover{{color:#b8aed4}}
.divider{{border:none;border-top:1px solid rgba(255,255,255,0.07);margin:20px 0}}
@media(max-width:440px){{
  .card{{padding:28px 20px}}
  .dl-grid{{flex-direction:column}}
}}
</style>
</head>
<body>

<div class="logo">
  <div class="logo-mark">
    <svg width="22" height="22" viewBox="0 0 22 22" fill="none">
      <path d="M4 4L11 11M11 11L18 4M11 11L4 18M11 11L18 18" stroke="white" stroke-width="2.5" stroke-linecap="round"/>
    </svg>
  </div>
  <span class="logo-name">Xarex</span>
</div>

<div class="card">

  <div id="state-pending" class="{pending_class}">
    <div class="spinner-ring"></div>
    <h1 class="state-title">Setting up your account&hellip;</h1>
    <p class="state-sub">We're provisioning your license. This usually takes less than 10 seconds.</p>
    <p class="poll-status" id="poll-status" aria-live="polite">Checking payment status&hellip;</p>
  </div>

  <div id="state-ready">
    <div class="check-icon">&#10003;</div>
    <h1 class="state-title" style="margin-bottom:6px">You're in.</h1>
    <div style="text-align:center;margin-bottom:24px">
      <span class="plan-badge" id="plan-badge">Xarex Pro</span>
    </div>

    <div class="cred-section">
      <div class="cred-label">API Key</div>
      <div class="cred-row">
        <span class="cred-value" id="cred-api-key">&mdash;</span>
        <button class="copy-btn" onclick="copyField('cred-api-key',this)">Copy</button>
      </div>
    </div>

    <div class="cred-section">
      <div class="cred-label">Org ID</div>
      <div class="cred-row">
        <span class="cred-value" id="cred-org-id">&mdash;</span>
        <button class="copy-btn" onclick="copyField('cred-org-id',this)">Copy</button>
      </div>
    </div>

    <hr class="divider"/>

    <div class="cred-label" style="margin-bottom:10px">Downloads</div>
    <div class="dl-grid" id="dl-grid"></div>

    <hr class="divider"/>

    <div class="qs-title">What to do next</div>

    <div class="qs-step">
      <div class="qs-num">1</div>
      <div class="qs-body">
        <div class="qs-desc">Extract the Cloud Brain package and start it:</div>
        <div class="code-block">
          <code>docker compose up -d</code>
          <button class="copy-btn" onclick="copyText('docker compose up -d',this)">Copy</button>
        </div>
      </div>
    </div>

    <div class="qs-step">
      <div class="qs-num">2</div>
      <div class="qs-body">
        <div class="qs-desc">Run your first scan (replace with your target):</div>
        <div class="code-block">
          <code id="qs-scan-cmd">curl -X POST http://localhost:8005/api/v1/scans/quick -H "X-API-Key: &lt;key&gt;" -H "Content-Type: application/json" -d '{{"target":"192.168.1.0/24"}}'</code>
          <button class="copy-btn" onclick="copyText(document.getElementById('qs-raw-scan').value,this)">Copy</button>
          <input type="hidden" id="qs-raw-scan"/>
        </div>
      </div>
    </div>

    <div class="qs-step">
      <div class="qs-num">3</div>
      <div class="qs-body">
        <div class="qs-desc">Open the dashboard in your browser:</div>
        <div class="code-block">
          <code>http://localhost:8005</code>
          <button class="copy-btn" onclick="copyText('http://localhost:8005',this)">Copy</button>
        </div>
      </div>
    </div>

    <div class="warn-banner">
      <span>&#9888;</span>
      <div>Keep this page open &mdash; your credentials won't be shown again after you navigate away.
           Treat your API key like a password. Never commit it to git.</div>
    </div>
  </div>

  <div id="state-failed" class="{failed_class}">
    <div class="fail-icon">&#10007;</div>
    <h1 class="state-title" style="margin-bottom:8px">Payment could not be completed.</h1>
    <p class="state-sub" style="margin-bottom:20px">
      Your session expired or the payment was cancelled. No charge was made.
    </p>
    <p style="text-align:center;font-size:14px;color:#b8aed4">
      <a href="/#lp-pricing" class="action-link">Try again</a> &nbsp;&middot;&nbsp;
      <a href="mailto:support@xarexsec.io" class="action-link">Contact support</a>
    </p>
  </div>

  <div id="state-timeout">
    <div class="fail-icon">&#9202;</div>
    <h1 class="state-title" style="margin-bottom:8px">Provisioning is taking longer than usual.</h1>
    <p class="state-sub" style="margin-bottom:20px">
      We've sent your credentials to your email address. Check your inbox (and spam folder) &mdash;
      you should have them within a few minutes.
    </p>
    <p style="text-align:center;font-size:14px;color:#b8aed4">
      Questions? Email us at
      <a href="mailto:support@xarexsec.io" class="action-link">support@xarexsec.io</a>
    </p>
  </div>

</div>

<div class="page-footer">
  <a href="https://xarexsec.io/docs">Docs</a> &nbsp;&middot;&nbsp;
  <a href="mailto:support@xarexsec.io">support@xarexsec.io</a>
  <br/>
  These credentials grant full access to your account. Treat like a password. Never commit to git.
</div>

<script>
(function () {{
  // Both values are read from URLSearchParams at runtime, NOT injected
  // server-side, so the HTML carries no user input (H-6). The server already
  // rejected invalid session IDs by rendering the failed state directly.
  var params = new URLSearchParams(window.location.search);
  var SESSION_ID = params.get('session_id');
  var REVEAL_T = params.get('t');
  var SESSION_ID_VALID = {session_id_valid_js};

  var MAX_ATTEMPTS = 30;
  var POLL_INTERVAL = 2000;
  var attempt = 0;
  var timer = null;

  function setState(name) {{
    ['pending','ready','failed','timeout'].forEach(function(s) {{
      var el = document.getElementById('state-' + s);
      if (el) el.className = s === name ? 'active' : '';
    }});
  }}

  function setStatus(msg) {{
    var el = document.getElementById('poll-status');
    if (el) el.textContent = msg;
  }}

  function copyField(fieldId, btn) {{
    var el = document.getElementById(fieldId);
    if (!el) return;
    copyText(el.textContent.trim(), btn);
  }}

  function copyText(text, btn) {{
    if (!text) return;
    navigator.clipboard.writeText(text).then(function() {{
      if (!btn) return;
      var orig = btn.textContent;
      btn.textContent = 'Copied!';
      btn.classList.add('copied');
      setTimeout(function() {{ btn.textContent = orig; btn.classList.remove('copied'); }}, 1500);
    }}).catch(function() {{}});
  }}

  window.copyField = copyField;
  window.copyText  = copyText;

  function showReady(license) {{
    setState('ready');

    var plan = (license.plan || 'xarex_pro').replace(/_/g,' ');
    plan = plan.replace(/\\b\\w/g, function(c) {{ return c.toUpperCase(); }});
    var badge = document.getElementById('plan-badge');
    if (badge) badge.textContent = plan;

    var apiEl = document.getElementById('cred-api-key');
    var orgEl = document.getElementById('cred-org-id');
    if (apiEl) apiEl.textContent = license.api_key || '';
    if (orgEl) orgEl.textContent = license.org_id  || '';

    var rawScanEl = document.getElementById('qs-raw-scan');
    var scanCmdEl = document.getElementById('qs-scan-cmd');
    if (rawScanEl && license.api_key) {{
      var cmd = 'curl -X POST http://localhost:8005/api/v1/scans/quick -H "X-API-Key: ' + license.api_key + '" -H "Content-Type: application/json" -d \\'{{\\"target\\":\\"192.168.1.0/24\\"}}\\'';
      rawScanEl.value = cmd;
      if (scanCmdEl) scanCmdEl.textContent = cmd;
    }}

    var token = license.download_token || '';
    var dlGrid = document.getElementById('dl-grid');
    if (dlGrid && token) {{
      dlGrid.innerHTML =
        '<a class="dl-btn" href="/api/billing/probe/linux/' + token + '">Linux probe</a>' +
        '<a class="dl-btn" href="/api/billing/probe/windows/' + token + '">Windows probe</a>' +
        '<a class="dl-btn" href="/api/billing/download/' + token + '">Cloud Brain ZIP</a>';
    }} else if (dlGrid) {{
      dlGrid.innerHTML = '<p style="font-size:13px;color:#6b6080">Download links will appear in your confirmation email.</p>';
    }}
  }}

  function poll() {{
    if (!SESSION_ID_VALID || !SESSION_ID) {{
      setState('failed');
      return;
    }}
    attempt++;
    setStatus('Checking payment status (' + attempt + '/' + MAX_ATTEMPTS + ')…');

    var url = '/api/billing/session-status?session_id=' + encodeURIComponent(SESSION_ID);
    if (REVEAL_T) {{ url += '&t=' + encodeURIComponent(REVEAL_T); }}

    fetch(url, {{ credentials: 'same-origin' }})
      .then(function(r) {{
        if (r.status === 404) {{
          // Generic-404 path: token missing / wrong / expired / consumed.
          // Stop polling and show the timeout state with the email-fallback
          // copy — credentials will arrive via the welcome email.
          setState('timeout');
          return null;
        }}
        return r.json();
      }})
      .then(function(data) {{
        if (!data) return;
        if (data.status === 'ready') {{
          showReady(data.license || {{}});
        }} else if (data.status === 'failed' || data.status === 'error') {{
          setState('failed');
        }} else {{
          if (attempt >= MAX_ATTEMPTS) {{
            setState('timeout');
          }} else {{
            timer = setTimeout(poll, POLL_INTERVAL);
          }}
        }}
      }})
      .catch(function() {{
        if (attempt >= MAX_ATTEMPTS) {{
          setState('timeout');
        }} else {{
          timer = setTimeout(poll, POLL_INTERVAL);
        }}
      }});
  }}

  if (SESSION_ID_VALID) {{ poll(); }}
}})();
</script>
</body>
</html>"""


@router.get("/success", response_class=HTMLResponse, include_in_schema=False)
async def payment_success(provider: str = "stripe", session_id: str = "") -> HTMLResponse:
    """Landing page after a successful payment redirect.

    H-6: validate `session_id` against the Stripe regex BEFORE rendering.
    Invalid IDs render the failed state directly — we never inject the user-
    supplied value into the JS source. The JS itself reads session_id from
    URLSearchParams so even when valid the value never crosses the HTML
    boundary on the server side.
    """
    session_id_valid = bool(session_id) and is_valid_stripe_session_id(session_id)
    if session_id_valid:
        pending_class = "active"
        failed_class = ""
    else:
        # Missing or invalid session_id → render failed immediately.
        pending_class = ""
        failed_class = "active"

    # Issue 4 (defence-in-depth): use json.dumps to render the JS boolean
    # literal. Today only "true"/"false" reach this slot, but a future
    # maintainer who introduces a third branch could inadvertently inject
    # arbitrary JS — json.dumps on a bool always produces exactly "true"
    # or "false", regardless of what value reaches it.
    sid_valid_js = json.dumps(bool(session_id_valid))

    html = _SUCCESS_HTML.format(
        pending_class=pending_class,
        failed_class=failed_class,
        session_id_valid_js=sid_valid_js,
    )
    return HTMLResponse(html)


# ─────────────────────────────────────────────────────────────────────────────
# Subscription status check
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/session-status", response_model=SessionStatusResponse)
# H-7: per-IP rate limit. /success polls every 2s for up to 60s = 30 hits;
# 30/minute covers a single user's normal flow and blocks bot enumeration.
@limiter.limit("30/minute")
async def session_status(
    request: Request,
    session_id: str = Query(...),
    t: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
) -> SessionStatusResponse:
    """Poll a Checkout Session + License pair after redirect from Stripe.

    Requires either:
      - `t=<reveal_token>` query param matching the token issued at checkout, OR
      - `xrx_reveal` HttpOnly cookie set by the /checkout/stripe response.

    Any miss (missing param/cookie, wrong token, expired, already-consumed,
    invalid session_id shape) returns a generic 404 — no oracle that
    distinguishes which check failed. After a successful `ready` response
    the token is burned (one-time-use) so a follow-up poll returns 404.
    """
    # H-6: reject anything that doesn't match Stripe's session-id shape.
    if not is_valid_stripe_session_id(session_id):
        raise HTTPException(status_code=404, detail="Not found")

    if not settings.STRIPE_SECRET_KEY:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Stripe is not configured on this server",
        )

    # ── Reveal-token check (P0-1) ─────────────────────────────────────────
    # Prefer the explicit query param; fall back to the HttpOnly cookie set
    # by /checkout/stripe (covers enterprise proxies that strip `t=`).
    #
    # Issue 1 (timing oracle): we deliberately do NOT short-circuit here on
    # "no token stored for this session_id" via peek_reveal_token_exists().
    # That peek was a sub-millisecond fast-path on the no-token branch and
    # several-tens-of-ms on the wrong-token branch (the latter hits the
    # Stripe retrieve path) — that gap let an attacker probe whether a given
    # session_id had ever been issued in our system, just by latency.
    # Instead, every request that gets past the regex check runs the SAME
    # downstream code path: Stripe retrieve (3s cache) → email lookup →
    # validate_and_consume. All 404 returns now share that path-length;
    # the only remaining variance is cache hit vs miss inside a 3s window,
    # and that variance is not session-existence-dependent.
    token = t or request.cookies.get(_REVEAL_COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=404, detail="Not found")

    # 1. Retrieve the Session from Stripe (short server-side cache).
    try:
        session_obj = cached_stripe_session_retrieve(session_id)
    except Exception as exc:
        # H-10: distinguish "Stripe API failed" from "still pending" so the
        # FE can stop polling and fall back to the email-credentials copy.
        log.warning("Stripe session retrieve failed", session_id=session_id, error=str(exc))
        return SessionStatusResponse(status="error", license=None)

    payment_status = getattr(session_obj, "payment_status", None) or session_obj.get("payment_status", "")
    sess_status = getattr(session_obj, "status", None) or session_obj.get("status", "")
    if sess_status == "expired" or payment_status == "unpaid":
        return SessionStatusResponse(status="failed", license=None)

    if sess_status != "complete":
        return SessionStatusResponse(status="pending", license=None)

    # 2. Session is complete on Stripe's side. Has our webhook landed yet?
    details = getattr(session_obj, "customer_details", None) or session_obj.get("customer_details", {})
    email = (details or {}).get("email") if isinstance(details, dict) else getattr(details, "email", None)
    if not email:
        email = session_obj.get("customer_email", "") if isinstance(session_obj, dict) else getattr(session_obj, "customer_email", "")
    if not email:
        return SessionStatusResponse(status="pending", license=None)

    lic = await get_license_by_email(db=db, email=email)
    if not lic or lic.status != "active":
        return SessionStatusResponse(status="pending", license=None)

    # All conditions met — NOW validate-and-consume the token. This is the
    # one branch that reveals credentials, so this is the right place to
    # burn the one-time-use token (P0-1).
    if not validate_and_consume_reveal_token(session_id, token):
        # Wrong / expired / already consumed. Same 404 shape as the other
        # paths — no oracle.
        raise HTTPException(status_code=404, detail="Not found")

    log.info(
        "Checkout complete — credentials revealed",
        email_hash=_email_hash(email),
        session_id=session_id,
    )

    return SessionStatusResponse(
        status="ready",
        license={
            "org_id": lic.org_id,
            "api_key": lic.api_key,
            "plan": lic.plan,
            "download_token": lic.download_token,
        },
    )


@router.get("/subscription", response_model=SubscriptionStatus)
async def check_subscription(email: str, db: AsyncSession = Depends(get_db)) -> SubscriptionStatus:
    """Look up subscription state by email — SAFE FIELDS ONLY.

    Issue 2 (api-security-reviewer SHIP-WITH-CHANGES): this endpoint is
    unauthenticated and keyed only on email — knowing or guessing a customer's
    email must NOT yield credentials. We strip api_key, download_token, and
    org_id from the response. Customers who lost their credentials must use
    a credentialed recovery flow (re-issue via /session-status with a fresh
    reveal_token, or email-based reset) — never this endpoint.
    """
    license_ = await get_license_by_email(db=db, email=email)
    if not license_ or license_.status != "active":
        return SubscriptionStatus(email=email, has_license=False)

    result = await db.execute(
        select(Subscription).where(Subscription.customer_id == license_.customer_id)
    )
    sub = result.scalar_one_or_none()

    # current_period_end may be absent on free plans / very fresh rows; emit
    # ISO-8601 when present so clients can format it client-side.
    cpe = getattr(sub, "current_period_end", None) if sub else None
    cpe_iso = cpe.isoformat() if cpe is not None else None

    return SubscriptionStatus(
        email=email,
        has_license=True,
        plan=license_.plan,
        status=sub.status if sub else "active",
        current_period_end=cpe_iso,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Download endpoints (token-gated)
# ─────────────────────────────────────────────────────────────────────────────

_DIST_DIR = Path(__file__).parent.parent.parent / "dist"


def _require_active_license(license_: License | None) -> None:
    if not license_ or license_.status != "active":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or inactive license",
        )


@router.get("/download/{token}", include_in_schema=False)
async def download_cloud_brain(token: str, db: AsyncSession = Depends(get_db)) -> FileResponse:
    """Return the Cloud Brain Docker Compose ZIP for a valid download token."""
    license_ = await get_license_by_token(db=db, token=token)
    _require_active_license(license_)

    zip_path = _DIST_DIR / "xarex-cloud-brain.zip"
    if not zip_path.exists():
        raise HTTPException(status_code=404, detail="Distribution package not yet available — contact support")

    return FileResponse(
        path=str(zip_path),
        media_type="application/zip",
        filename="xarex-cloud-brain.zip",
    )


@router.get("/probe/linux/{token}", include_in_schema=False)
async def download_probe_linux(token: str, db: AsyncSession = Depends(get_db)) -> FileResponse:
    """Return the Linux probe binary for a valid download token."""
    license_ = await get_license_by_token(db=db, token=token)
    _require_active_license(license_)

    bin_path = _DIST_DIR / "xarex-probe-linux"
    if not bin_path.exists():
        raise HTTPException(status_code=404, detail="Linux probe binary not yet available — contact support")

    return FileResponse(
        path=str(bin_path),
        media_type="application/octet-stream",
        filename="xarex-probe",
    )


@router.get("/probe/windows/{token}", include_in_schema=False)
async def download_probe_windows(token: str, db: AsyncSession = Depends(get_db)) -> FileResponse:
    """Return the Windows probe binary for a valid download token."""
    license_ = await get_license_by_token(db=db, token=token)
    _require_active_license(license_)

    bin_path = _DIST_DIR / "xarex-probe-windows.exe"
    if not bin_path.exists():
        raise HTTPException(status_code=404, detail="Windows probe binary not yet available — contact support")

    return FileResponse(
        path=str(bin_path),
        media_type="application/octet-stream",
        filename="xarex-probe.exe",
    )
