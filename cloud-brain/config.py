from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

import structlog

log = structlog.get_logger(__name__)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://xarex:xarex@localhost:5432/xarex",
        description="Async PostgreSQL connection string",
    )
    SECRET_KEY: str = Field(
        default="change-me-in-production",
        description="JWT / token signing secret",
    )
    GRPC_PORT: int = Field(default=50051, description="Port for the gRPC server")
    WS_PORT: int = Field(default=8005, description="Port for the WebSocket / HTTP server")
    ADMIN_SECRET: str = Field(
        default="xarex-admin-secret",
        description="Shared secret for admin routes (X-Admin-Secret header)",
    )
    ENVIRONMENT: str = Field(
        default="development",
        description="Deployment environment: 'development' | 'staging' | 'production'",
    )

    # ── AI ──────────────────────────────────────────────────────
    ANTHROPIC_API_KEY: str = Field(
        default="",
        description="Anthropic API key for AI-powered scan analysis",
    )

    # ── Notifications ────────────────────────────────────────────
    SLACK_WEBHOOK_URL: str = Field(
        default="",
        description="Slack incoming webhook URL for critical finding alerts",
    )
    TEAMS_WEBHOOK_URL: str = Field(
        default="",
        description="Microsoft Teams incoming webhook URL for scan/finding alerts",
    )
    WEBHOOK_URL: str = Field(
        default="",
        description="Generic webhook URL (receives JSON POST on events)",
    )
    NOTIFY_ON_CRITICAL: bool = Field(
        default=True,
        description="Send notification when a critical/high finding is discovered",
    )
    NOTIFY_ON_SCAN_COMPLETE: bool = Field(
        default=True,
        description="Send notification when a scan completes",
    )

    # ── CVE Enrichment ───────────────────────────────────────────
    NVD_API_KEY: str = Field(
        default="",
        description="NVD API key (optional — raises rate limit from 5 to 50 req/30s)",
    )

    # ── Threat Intelligence ──────────────────────────────────────
    ABUSEIPDB_API_KEY: str = Field(
        default="",
        description="AbuseIPDB API key for IP reputation lookups",
    )
    VIRUSTOTAL_API_KEY: str = Field(
        default="",
        description="VirusTotal API key for URL/domain/IP intelligence",
    )
    THREAT_INTEL_CACHE_TTL: int = Field(
        default=3600,
        description="Seconds to cache threat intel lookup results in-process",
    )

    # ── Autonomous Engine ────────────────────────────────────────
    AUTO_ENRICH_CVE: bool = Field(default=True)
    AUTO_GENERATE_REPORT: bool = Field(default=True)
    AUTO_AI_ANALYSIS: bool = Field(default=False)

    # ── Stripe ───────────────────────────────────────────────────
    STRIPE_SECRET_KEY: str = Field(
        default="",
        description="Stripe secret key (sk_live_... or sk_test_...)",
    )
    STRIPE_WEBHOOK_SECRET: str = Field(
        default="",
        description="Stripe webhook signing secret (whsec_...)",
    )
    # DEPRECATED: legacy single-price config. Retained as empty defaults so
    # any unmigrated callers fail loudly. New code routes through
    # `Settings.stripe_price_id(tier, cadence)` and the four
    # STRIPE_PRICE_<TIER>_<CADENCE> env vars below.
    STRIPE_PRICE_ID: str = Field(
        default="",
        description="DEPRECATED — use STRIPE_PRICE_<TIER>_<CADENCE> instead",
    )
    STRIPE_PRODUCT_ID: str = Field(
        default="",
        description="DEPRECATED — products are referenced via their Price IDs",
    )

    # ── Stripe tiered pricing matrix ─────────────────────────────
    # Fill these in `.env` after creating the matching products + recurring
    # prices in the Stripe Dashboard. Each price has a fixed currency baked
    # into the Price object — `STRIPE_CURRENCY` below is informational only.
    STRIPE_PRICE_STARTER_MONTHLY: str = Field(
        default="",
        description="Stripe Price ID — Starter tier, monthly recurring (~$49/mo USD)",
    )
    STRIPE_PRICE_STARTER_ANNUAL: str = Field(
        default="",
        description="Stripe Price ID — Starter tier, annual recurring (~$470/yr USD, 2 months free)",
    )
    STRIPE_PRICE_PRO_MONTHLY: str = Field(
        default="",
        description="Stripe Price ID — Pro tier, monthly recurring (~$199/mo USD)",
    )
    STRIPE_PRICE_PRO_ANNUAL: str = Field(
        default="",
        description="Stripe Price ID — Pro tier, annual recurring (~$1900/yr USD, 2 months free)",
    )

    # Informational only — the canonical currency lives on each Stripe Price
    # object and cannot be overridden at Checkout-Session creation time. We
    # keep this field for email copy, invoice display, and analytics labels.
    STRIPE_CURRENCY: str = Field(
        default="usd",
        description="Display currency for receipts / emails (NOT used to set Stripe Price currency — that's baked into each Price object)",
    )
    # Set to 0 — we no longer run a time-based trial. The 'trial' is now
    # 2 free scans on the free plan (FREE_PLAN_SCAN_LIMIT below). Customers
    # who hit checkout pay immediately.
    STRIPE_TRIAL_DAYS: int = Field(
        default=0,
        description="Free trial days before first charge (0 = no time-based trial; use FREE_PLAN_SCAN_LIMIT for usage-based trial)",
    )

    # ── ToyyibPay ────────────────────────────────────────────────
    TOYYIBPAY_SECRET_KEY: str = Field(
        default="",
        description="ToyyibPay user secret key from dashboard",
    )
    TOYYIBPAY_CATEGORY_CODE: str = Field(
        default="",
        description="ToyyibPay category code for Xarex Pro product",
    )
    TOYYIBPAY_SANDBOX: bool = Field(
        default=True,
        description="Use dev.toyyibpay.com sandbox (set False for production)",
    )
    TOYYIBPAY_AMOUNT_CENTS: int = Field(
        default=9900,
        description="Monthly price in toyyibpay cents (RM 99.00)",
    )

    # ── Public URL ───────────────────────────────────────────────
    PUBLIC_URL: str = Field(
        default="http://localhost:8005",
        description="Public-facing URL of this server (used for webhook/callback/redirect URLs)",
    )

    # ── Email ────────────────────────────────────────────────────
    EMAIL_FROM: str = Field(
        default="noreply@xarexsec.io",
        description="Sender address for transactional emails",
    )
    EMAIL_FROM_NAME: str = Field(
        default="Xarex Security",
        description="Sender display name",
    )
    # SMTP
    SMTP_HOST: str = Field(default="smtp.gmail.com")
    SMTP_PORT: int = Field(default=587)
    SMTP_USER: str = Field(default="")
    SMTP_PASSWORD: str = Field(default="")
    SMTP_TLS: bool = Field(default=True)
    # Resend (alternative — set RESEND_API_KEY to use instead of SMTP)
    RESEND_API_KEY: str = Field(
        default="",
        description="Resend.com API key — if set, overrides SMTP for email delivery",
    )

    # ── Free Plan ────────────────────────────────────────────────
    FREE_PLAN_ENABLED: bool = Field(
        default=True,
        description="Allow users to sign up for a free tier (no payment required)",
    )
    FREE_PLAN_SCAN_LIMIT: int = Field(
        default=2,
        description="Maximum number of scans a free-plan license can run (usage-based trial)",
    )

    # ── Breach Monitor ───────────────────────────────────────────
    HIBP_API_KEY: str = Field(
        default="",
        description="HaveIBeenPwned API key (get at haveibeenpwned.com/API/Key)",
    )
    HIBP_API_URL: str = Field(
        default="https://haveibeenpwned.com/api/v3",
        description="HIBP API base URL",
    )

    # ── Link / Email Analyzer ────────────────────────────────────
    SAFE_BROWSING_KEY: str = Field(
        default="",
        description="Google Safe Browsing API key for URL reputation checks",
    )
    WHOIS_TIMEOUT: int = Field(default=5, description="WHOIS lookup timeout in seconds")

    # ── Footprint Scanner ────────────────────────────────────────
    FOOTPRINT_USER_AGENT: str = Field(
        default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        description="User-agent string for footprint HTTP requests",
    )

    # ── Lead capture: Cloudflare Turnstile (anti-bot) ────────────
    # When set, /api/v1/leads requires a valid `turnstile_token` field in
    # every submission, verified against Cloudflare's siteverify endpoint.
    # When empty (default), Turnstile is bypassed and the honeypot + rate
    # limit are the only defences. Site key for the widget is configured
    # in the marketing site (`window.XAREX_TURNSTILE_SITE_KEY`); the keys
    # are paired but only the secret lives server-side.
    TURNSTILE_SECRET_KEY: str = Field(
        default="",
        description="Cloudflare Turnstile secret key (server-side verification)",
    )
    TURNSTILE_VERIFY_URL: str = Field(
        default="https://challenges.cloudflare.com/turnstile/v0/siteverify",
        description="Cloudflare Turnstile siteverify endpoint",
    )

    # ── Lead capture retention ───────────────────────────────────
    # Days after which a lead row is hard-deleted. Default 2 years balances
    # sales utility (multi-touch attribution windows) with data-minimisation
    # principles. Tighten in jurisdictions with stricter rules.
    LEAD_RETENTION_DAYS: int = Field(
        default=730,
        description="Hard-delete leads older than this many days",
    )
    # Days after which the ip_address / user_agent columns are scrubbed
    # (set to NULL) on a lead row. The lead itself is retained for sales
    # follow-up; only the PII is shed. Default 90 days matches typical
    # log-retention windows.
    LEAD_PII_RETENTION_DAYS: int = Field(
        default=90,
        description="Null out ip_address/user_agent on leads older than this many days",
    )

    # ── CORS / Browser origins ───────────────────────────────────
    # Comma-separated list of origins permitted to call the API from a
    # browser. Defaults cover local dev (the FastAPI server on 8005, the
    # marketing site opened directly via file://, and a Vite-style dev
    # server on 5173). Override per environment via the CORS_ORIGINS env
    # var, e.g. `CORS_ORIGINS=https://xarex.io,https://app.xarex.io`.
    # An entry of "*" disables the allowlist (NOT recommended; only useful
    # as an emergency escape hatch). Use "null" to permit file:// origins,
    # which is what Chrome sends when opening website/index.html directly
    # from disk during dev.
    CORS_ORIGINS: str = Field(
        default="http://localhost:8005,http://127.0.0.1:8005,http://localhost:5173,http://127.0.0.1:5173,null",
        description="Comma-separated allowlist of browser origins for the API",
    )

    @property
    def cors_origins_list(self) -> list[str]:
        """Parsed CORS_ORIGINS as a clean list of origins."""
        raw = (self.CORS_ORIGINS or "").strip()
        if not raw:
            return []
        return [o.strip() for o in raw.split(",") if o.strip()]

    # ── Stripe pricing matrix helper ─────────────────────────────
    # Allowed values for the pricing matrix lookup. Keep these in sync with
    # the STRIPE_PRICE_<TIER>_<CADENCE> env fields defined above.
    _STRIPE_TIERS: tuple[str, ...] = ("starter", "pro")
    _STRIPE_CADENCES: tuple[str, ...] = ("monthly", "annual")

    def stripe_price_id(self, tier: str, cadence: str) -> str | None:
        """Resolve a (tier, cadence) pair to the configured Stripe Price ID.

        Returns the Price ID string, or an empty string if the operator has
        not yet configured that tier in `.env`. Raises ValueError for any
        combo that isn't a known (tier, cadence).
        """
        tier_l = (tier or "").strip().lower()
        cad_l = (cadence or "").strip().lower()
        if tier_l not in self._STRIPE_TIERS:
            raise ValueError(
                f"Unknown Stripe pricing tier: {tier!r}. "
                f"Allowed: {sorted(self._STRIPE_TIERS)}"
            )
        if cad_l not in self._STRIPE_CADENCES:
            raise ValueError(
                f"Unknown Stripe pricing cadence: {cadence!r}. "
                f"Allowed: {sorted(self._STRIPE_CADENCES)}"
            )
        attr = f"STRIPE_PRICE_{tier_l.upper()}_{cad_l.upper()}"
        return getattr(self, attr, None) or None


settings = Settings()

# ── Live-key safety check ───────────────────────────────────────
# Detect the foot-gun where a sk_live_* secret is shipped into anything
# other than ENVIRONMENT=production — would charge real cards from a dev
# laptop or staging environment. Loud structlog warning at startup; we do
# NOT raise so test/CI loads with placeholder keys continue to boot.
if settings.STRIPE_SECRET_KEY.startswith("sk_live_") and settings.ENVIRONMENT != "production":
    log.warning(
        "stripe_live_key_in_non_production_environment",
        environment=settings.ENVIRONMENT,
        message=(
            "STRIPE_SECRET_KEY is a LIVE key (sk_live_*) but ENVIRONMENT is "
            f"{settings.ENVIRONMENT!r}. Real cards will be charged. "
            "Set ENVIRONMENT=production or swap to a sk_test_* key."
        ),
    )
