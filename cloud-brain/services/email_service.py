"""Xarex — transactional email delivery.

Supports two backends (checked in order):
  1. Resend API  — set RESEND_API_KEY in .env
  2. SMTP        — set SMTP_HOST / SMTP_USER / SMTP_PASSWORD in .env
"""
from __future__ import annotations

import smtplib
import textwrap
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import httpx
import structlog

from config import settings

log = structlog.get_logger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Core send function
# ─────────────────────────────────────────────────────────────────────────────

async def send_email(*, to: str, subject: str, html: str, text: str = "") -> bool:
    """Send a transactional email.  Returns True on success."""
    if settings.RESEND_API_KEY:
        return await _send_via_resend(to=to, subject=subject, html=html, text=text)
    if settings.SMTP_USER and settings.SMTP_PASSWORD:
        return _send_via_smtp(to=to, subject=subject, html=html, text=text)
    log.warning("No email provider configured — skipping send", to=to, subject=subject)
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Resend backend
# ─────────────────────────────────────────────────────────────────────────────

async def _send_via_resend(*, to: str, subject: str, html: str, text: str) -> bool:
    payload = {
        "from": f"{settings.EMAIL_FROM_NAME} <{settings.EMAIL_FROM}>",
        "to": [to],
        "subject": subject,
        "html": html,
    }
    if text:
        payload["text"] = text
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                "https://api.resend.com/emails",
                json=payload,
                headers={"Authorization": f"Bearer {settings.RESEND_API_KEY}"},
            )
        resp.raise_for_status()
        log.info("Email sent via Resend", to=to, subject=subject)
        return True
    except Exception as exc:
        log.error("Resend send failed", to=to, error=str(exc))
        return False


# ─────────────────────────────────────────────────────────────────────────────
# SMTP backend
# ─────────────────────────────────────────────────────────────────────────────

def _send_via_smtp(*, to: str, subject: str, html: str, text: str) -> bool:
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = f"{settings.EMAIL_FROM_NAME} <{settings.EMAIL_FROM}>"
    msg["To"]      = to
    if text:
        msg.attach(MIMEText(text, "plain"))
    msg.attach(MIMEText(html, "html"))
    try:
        if settings.SMTP_TLS:
            server = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT)
            server.starttls()
        else:
            server = smtplib.SMTP_SSL(settings.SMTP_HOST, settings.SMTP_PORT)
        server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
        server.sendmail(settings.EMAIL_FROM, [to], msg.as_string())
        server.quit()
        log.info("Email sent via SMTP", to=to, subject=subject)
        return True
    except Exception as exc:
        log.error("SMTP send failed", to=to, error=str(exc))
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Email templates
# ─────────────────────────────────────────────────────────────────────────────

def _base_html(content: str) -> str:
    """Wrap content in the Xarex branded email shell."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Xarex Security</title>
<style>
  body{{margin:0;padding:0;background:#05030f;font-family:'Helvetica Neue',Arial,sans-serif;color:#e8eaf6}}
  .wrap{{max-width:580px;margin:0 auto;padding:40px 20px}}
  .logo{{display:flex;align-items:center;gap:10px;margin-bottom:32px}}
  .logo-mark{{width:36px;height:36px;border-radius:9px;background:linear-gradient(135deg,#7c6af7,#c354e8);
              display:flex;align-items:center;justify-content:center;font-size:18px;color:#fff;font-weight:900}}
  .logo-text{{font-size:20px;font-weight:900;color:#f0ecff;letter-spacing:-0.5px}}
  .card{{background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.09);
         border-radius:16px;padding:32px;margin-bottom:24px}}
  h1{{font-size:26px;font-weight:900;color:#f0ecff;margin:0 0 12px;letter-spacing:-0.5px}}
  p{{font-size:15px;color:#b8aed4;line-height:1.65;margin:0 0 16px}}
  .cred-box{{background:rgba(0,0,0,0.35);border:1px solid rgba(255,255,255,0.1);
             border-radius:10px;padding:16px 20px;margin:16px 0;font-family:monospace}}
  .cred-label{{font-size:11px;font-weight:700;color:#7c6af7;text-transform:uppercase;
               letter-spacing:0.1em;margin-bottom:4px}}
  .cred-value{{font-size:14px;color:#f0ecff;word-break:break-all}}
  .btn{{display:inline-block;padding:14px 28px;border-radius:12px;font-size:15px;font-weight:700;
        background:linear-gradient(135deg,#7c6af7,#c354e8);color:#fff;text-decoration:none;
        margin:8px 0}}
  .step{{display:flex;gap:14px;align-items:flex-start;margin-bottom:16px}}
  .step-num{{width:26px;height:26px;border-radius:50%;background:rgba(124,106,247,0.2);
             border:1px solid rgba(124,106,247,0.4);color:#7c6af7;font-size:13px;font-weight:800;
             display:flex;align-items:center;justify-content:center;flex-shrink:0;margin-top:1px}}
  .step-text{{font-size:14px;color:#b8aed4;line-height:1.6}}
  .step-text strong{{color:#f0ecff}}
  .divider{{height:1px;background:rgba(255,255,255,0.08);margin:24px 0}}
  .footer{{text-align:center;font-size:12px;color:#4a4060;line-height:1.6;margin-top:32px}}
  .footer a{{color:#7c6af7;text-decoration:none}}
  .highlight{{color:#f0ecff;font-weight:700}}
  .warn-box{{background:rgba(240,133,58,0.07);border:1px solid rgba(240,133,58,0.2);
             border-radius:10px;padding:14px 18px;font-size:13px;color:#d4b078;margin:16px 0}}
</style>
</head>
<body>
<div class="wrap">
  <div class="logo">
    <div class="logo-mark">⬡</div>
    <span class="logo-text">XAREX</span>
  </div>
  {content}
  <div class="footer">
    <p>Xarex Security · <a href="{settings.PUBLIC_URL}">xarexsec.io</a><br>
    You received this because you subscribed to Xarex Pro.<br>
    Questions? Reply to this email — we respond within 4 hours.</p>
  </div>
</div>
</body>
</html>"""


async def send_welcome_email(
    *,
    to: str,
    customer_name: str,
    org_id: str,
    api_key: str,
    download_token: str,
    trial_days: int = 14,
    plan: str = "xarex_pro",
    scan_limit: int | None = None,
) -> bool:
    """Send the post-signup welcome email.

    Routes to free-plan or paid-plan template based on `plan`.
    """
    if plan == "free":
        return await _send_free_welcome_email(
            to=to, customer_name=customer_name,
            org_id=org_id, api_key=api_key,
            scan_limit=scan_limit or 3,
        )
    return await _send_pro_welcome_email(
        to=to, customer_name=customer_name,
        org_id=org_id, api_key=api_key,
        download_token=download_token, trial_days=trial_days,
    )


async def _send_free_welcome_email(
    *,
    to: str,
    customer_name: str,
    org_id: str,
    api_key: str,
    scan_limit: int,
) -> bool:
    """Lightweight welcome for free-tier signups — no download links."""
    content = f"""
    <div class="card">
      <h1>Welcome to Xarex — Free Plan</h1>
      <p>Hi <span class="highlight">{customer_name}</span>, your free account is active.
      You have <span class="highlight">{scan_limit} scans</span> to explore the platform —
      no time limit, no credit card required.</p>

      <div class="cred-box">
        <div class="cred-label">Org ID</div>
        <div class="cred-value">{org_id}</div>
      </div>
      <div class="cred-box">
        <div class="cred-label">API Key</div>
        <div class="cred-value">{api_key}</div>
      </div>

      <div class="warn-box">
        ⚠ Keep your API key private — treat it like a password.
      </div>
    </div>

    <div class="card">
      <h1 style="font-size:20px">Connect in 2 steps</h1>

      <div class="step">
        <div class="step-num">1</div>
        <div class="step-text">
          <strong>Open the Xarex dashboard</strong><br>
          Go to <a href="{settings.PUBLIC_URL}" style="color:#7c6af7">{settings.PUBLIC_URL}</a>,
          click <strong>Sign In</strong>, enter your API key above and the Cloud Brain URL.
        </div>
      </div>

      <div class="step">
        <div class="step-num">2</div>
        <div class="step-text">
          <strong>Run your first scan</strong><br>
          Click <strong>Quick Scan</strong>, enter a subnet (e.g. <code>192.168.1.0/24</code>)
          and hit Launch. Results appear live within 5 minutes.
        </div>
      </div>

      <div class="divider"></div>
      <a href="{settings.PUBLIC_URL}" class="btn">Open Xarex Dashboard →</a>
    </div>

    <div class="card" style="opacity:0.85">
      <p style="font-size:14px;margin:0">
        <strong style="color:#f0ecff">Want unlimited scans?</strong>
        Upgrade to Xarex Pro (RM 99/month) for unlimited scans, scheduled scanning,
        AI-powered reports, and attack path analysis.<br>
        <a href="{settings.PUBLIC_URL}/#lp-pricing" style="color:#7c6af7">View Pro plan →</a>
      </p>
    </div>
    """
    html = _base_html(content)
    text = textwrap.dedent(f"""
        Welcome to Xarex (Free Plan), {customer_name}!

        Your credentials:
          Org ID:  {org_id}
          API Key: {api_key}

        You have {scan_limit} scans on the free plan.

        Open the dashboard: {settings.PUBLIC_URL}
        Sign in with your API key above.

        Upgrade to Pro (unlimited): {settings.PUBLIC_URL}/#lp-pricing

        Questions? Reply to this email.
    """).strip()
    return await send_email(
        to=to,
        subject="Your Xarex free account is ready",
        html=html,
        text=text,
    )


async def _send_pro_welcome_email(
    *,
    to: str,
    customer_name: str,
    org_id: str,
    api_key: str,
    download_token: str,
    trial_days: int,
) -> bool:
    """Full onboarding email for paid/trial subscribers."""
    download_url  = f"{settings.PUBLIC_URL}/api/billing/download/{download_token}"
    probe_linux   = f"{settings.PUBLIC_URL}/api/billing/probe/linux/{download_token}"
    probe_windows = f"{settings.PUBLIC_URL}/api/billing/probe/windows/{download_token}"

    content = f"""
    <div class="card">
      <h1>Welcome to Xarex Pro 👋</h1>
      <p>Hi <span class="highlight">{customer_name}</span>, your
      {'<span class="highlight">' + str(trial_days) + '-day free trial</span> has started' if trial_days else 'Xarex Pro subscription is active'}.
      Here are your credentials — keep them safe.</p>

      <div class="cred-box">
        <div class="cred-label">Org ID</div>
        <div class="cred-value">{org_id}</div>
      </div>
      <div class="cred-box">
        <div class="cred-label">API Key</div>
        <div class="cred-value">{api_key}</div>
      </div>

      <div class="warn-box">
        ⚠ Your API key is like a password — never commit it to Git or share it publicly.
        Store it in <code>/etc/xarex/probe.conf</code> with permissions <code>600</code>.
      </div>
    </div>

    <div class="card">
      <h1 style="font-size:20px">Get running in 3 steps</h1>

      <div class="step">
        <div class="step-num">1</div>
        <div class="step-text">
          <strong>Download and start the Cloud Brain</strong><br>
          Run this on any Linux server (VPS, cloud VM, or your workstation):
          <div class="cred-box" style="margin-top:8px;font-size:13px">
            curl -sSL {download_url} -o xarex-cloud-brain.zip<br>
            unzip xarex-cloud-brain.zip &amp;&amp; cd xarex<br>
            echo "LICENSE_KEY={api_key}" &gt; .env<br>
            docker compose up -d
          </div>
          Then open <strong>http://your-server-ip:8005</strong> in your browser.
        </div>
      </div>

      <div class="step">
        <div class="step-num">2</div>
        <div class="step-text">
          <strong>Deploy a probe inside your network</strong><br>
          Download for <a href="{probe_linux}" style="color:#7c6af7">Linux</a> or
          <a href="{probe_windows}" style="color:#7c6af7">Windows</a>.
          Run it with your credentials:<br>
          <div class="cred-box" style="margin-top:8px;font-size:13px">
            sudo ./xarex-probe --org-id {org_id} --key {api_key} --brain your-server-ip:50051
          </div>
          The probe appears in your dashboard within 30 seconds.
        </div>
      </div>

      <div class="step">
        <div class="step-num">3</div>
        <div class="step-text">
          <strong>Launch your first scan</strong><br>
          In the dashboard click <strong>Quick Scan</strong>, enter a subnet
          (e.g. <code>192.168.1.0/24</code>), and hit Launch.
          Results appear live in under 5 minutes.
        </div>
      </div>

      <div class="divider"></div>
      <a href="{settings.PUBLIC_URL}" class="btn">Open Xarex Dashboard →</a>
    </div>

    <div class="card" style="opacity:0.8">
      <p style="font-size:14px;margin:0">
        <strong style="color:#f0ecff">Need help?</strong> Reply to this email — we respond fast.<br>
        <strong style="color:#f0ecff">Full documentation</strong> is in the Guide panel inside the app (? button, top right).<br>
        <strong style="color:#f0ecff">Community</strong> Discord: <a href="#" style="color:#7c6af7">discord.gg/xarex-security</a>
      </p>
    </div>
    """
    html = _base_html(content)
    text = textwrap.dedent(f"""
        Welcome to Xarex Pro, {customer_name}!

        Your credentials:
          Org ID:  {org_id}
          API Key: {api_key}

        Download Cloud Brain: {download_url}
        Linux probe:   {probe_linux}
        Windows probe: {probe_windows}

        Questions? Reply to this email.
    """).strip()
    return await send_email(
        to=to,
        subject="Your Xarex Pro credentials — get started in 3 steps",
        html=html,
        text=text,
    )


async def send_upgrade_email(
    *,
    to: str,
    customer_name: str,
    org_id: str,
    api_key: str,
    download_token: str,
) -> bool:
    """Notify a free-plan user that their account has been upgraded to Pro."""
    download_url = f"{settings.PUBLIC_URL}/api/billing/download/{download_token}"
    content = f"""
    <div class="card">
      <h1>You're now on Xarex Pro ✦</h1>
      <p>Hi <span class="highlight">{customer_name}</span>, your account has been upgraded.
      Unlimited scans, AI reports, scheduled scanning — everything is unlocked.</p>

      <div class="cred-box">
        <div class="cred-label">Org ID</div>
        <div class="cred-value">{org_id}</div>
      </div>
      <div class="cred-box">
        <div class="cred-label">API Key (unchanged)</div>
        <div class="cred-value">{api_key}</div>
      </div>

      <div style="margin-top:16px">
        <a href="{download_url}" class="btn">Download Cloud Brain Package →</a>
      </div>
    </div>

    <div class="card" style="opacity:0.85">
      <p style="font-size:14px;margin:0">
        <strong style="color:#f0ecff">Your existing setup still works</strong> — same Org ID and
        API key, no reconfiguration needed. The scan limit has been removed automatically.
      </p>
    </div>
    """
    return await send_email(
        to=to,
        subject="Xarex Pro is now active on your account",
        html=_base_html(content),
        text=textwrap.dedent(f"""
            Hi {customer_name}, your account has been upgraded to Xarex Pro!

            Org ID:  {org_id}
            API Key: {api_key} (unchanged)

            Download Cloud Brain: {download_url}

            Same credentials, no reconfiguration needed.
        """).strip(),
    )


async def send_payment_failed_email(*, to: str, customer_name: str, amount: str, retry_url: str) -> bool:
    content = f"""
    <div class="card">
      <h1>Payment failed ⚠</h1>
      <p>Hi <span class="highlight">{customer_name}</span>, we couldn't collect your payment of
      <span class="highlight">{amount}</span> for Xarex Pro.</p>
      <p>Your access remains active for 3 days while we retry. Please update your payment method
      to avoid interruption.</p>
      <a href="{retry_url}" class="btn">Update Payment Method →</a>
    </div>
    """
    return await send_email(
        to=to,
        subject="Action required: Xarex payment failed",
        html=_base_html(content),
    )


async def send_subscription_cancelled_email(*, to: str, customer_name: str, ends_at: str) -> bool:
    content = f"""
    <div class="card">
      <h1>Subscription cancelled</h1>
      <p>Hi <span class="highlight">{customer_name}</span>, your Xarex Pro subscription
      has been cancelled.</p>
      <p>You have access until <span class="highlight">{ends_at}</span>.
      After that date your probe connections will stop.</p>
      <p>Changed your mind? You can resubscribe at any time from the pricing page.</p>
      <a href="{settings.PUBLIC_URL}/#lp-pricing" class="btn">Resubscribe →</a>
    </div>
    """
    return await send_email(
        to=to,
        subject="Xarex subscription cancelled",
        html=_base_html(content),
    )
