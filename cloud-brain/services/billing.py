"""Xarex — billing service.

Handles:
  - License key / org provisioning
  - Stripe checkout session creation
  - ToyyibPay bill creation
  - Payment success provisioning (Customer → Subscription → License → email)

Security notes (from api-security-reviewer):
  - The Stripe Checkout Session ID is NOT a secret. /session-status pairs the
    session_id with a single-use, server-issued `reveal_token` (32 random
    bytes, sha256-hashed at rest, 10-min TTL, one-time-use) so that knowing
    a session_id alone never discloses credentials.
  - Webhook tier is derived from price_id (a controlled allowlist) rather
    than from session metadata (attacker-controllable via dashboard imports
    or any future client-supplied path).
  - BillingEvent.payload is minimised — we store only the routing-relevant
    fields, never customer email / card last-4 / postal.
  - INFO-level logs emit `email_hash` (sha256:16) instead of plaintext;
    WARNING/ERROR keeps plaintext for ops follow-up.
"""
from __future__ import annotations

import hashlib
import re
import secrets
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
import structlog
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

import stripe as stripe_lib

from config import settings
from models.tables import BillingEvent, Customer, License, Org, Subscription
from services.email_service import send_upgrade_email, send_welcome_email
from services.pii import email_hash as _email_hash
from services.pii import scrub_for_log as _scrub

log = structlog.get_logger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Constants — security
# ─────────────────────────────────────────────────────────────────────────────

# Stripe Checkout Session IDs match `cs_(test|live)_<base62>{20+}` in practice.
# We whitelist this regex everywhere the session_id leaves the URL and lands
# in app logic, so attackers can't smuggle arbitrary strings into Stripe API
# calls or HTML rendering.
_STRIPE_SESSION_ID_RE = re.compile(r"^cs_(test|live)_[A-Za-z0-9]{20,}$")

# TTL for `reveal_token` entries in the in-memory store (seconds).
_REVEAL_TTL_SECONDS = 600


def _to_plain_dict(obj: Any) -> Any:
    """Recursively convert a Stripe `StripeObject` (or nested mix of objects,
    dicts, and lists) into plain Python dicts/lists.

    Required because Stripe's StripeObject overrides `__getattr__` to do a
    `self[k]` lookup that re-raises KeyError as AttributeError. Any nested
    field that's also a StripeObject will therefore break naïve chained
    `.get()` calls (e.g. `session.get("customer_details", {}).get("email")`)
    with `AttributeError: get`.

    Tries the SDK-native conversion first (`StripeObject.to_dict()` is
    recursive in stripe-python 8+), then falls back to a manual walk over
    keys for older versions or non-Stripe dict-likes.
    """
    if obj is None:
        return None
    if isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, dict):
        return {k: _to_plain_dict(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_plain_dict(v) for v in obj]
    # Stripe StripeObject path — prefer SDK conversion when available.
    to_dict = getattr(obj, "to_dict", None)
    if callable(to_dict):
        try:
            return _to_plain_dict(to_dict())
        except Exception:  # noqa: BLE001 — fall through to manual walk
            pass
    # Last-resort manual walk: iterate keys if it behaves like a mapping.
    keys = getattr(obj, "keys", None)
    if callable(keys):
        try:
            return {k: _to_plain_dict(obj[k]) for k in keys()}
        except Exception:  # noqa: BLE001
            return obj
    return obj

# Short server-side cache to absorb the /success page's 30 polls/min hitting
# Stripe — keyed by session_id, holds the retrieved Session object for ~3s.
_SESSION_RETRIEVE_CACHE_TTL = 3.0


def is_valid_stripe_session_id(session_id: str | None) -> bool:
    """True if `session_id` matches Stripe's documented Checkout Session shape."""
    if not session_id:
        return False
    return bool(_STRIPE_SESSION_ID_RE.match(session_id))


# ─────────────────────────────────────────────────────────────────────────────
# Reveal-token store (process-local, thread-safe)
# ─────────────────────────────────────────────────────────────────────────────
#
# SECURITY / DEPLOYMENT CONSTRAINT — read before scaling the API tier:
#
# `_REVEAL_TOKENS` is a process-local dict. It does NOT survive worker
# boundaries: a token issued by worker A is invisible to worker B, so a
# multi-worker deployment will randomly 404 legitimate /session-status polls
# and break post-checkout credential reveal for ~(N-1)/N of customers.
#
# If you deploy with `uvicorn --workers N>1`, gunicorn with multiple workers,
# or Kubernetes replicas, this MUST be replaced with a Redis-backed store
# (use the existing `RATE_LIMIT_STORAGE_URI` env pattern in
# `cloud-brain/limiter.py` as a model — same TTL, same hash-at-rest, same
# one-time-use semantics, just on Redis instead of an in-memory dict).
#
# Until that migration ships, the deployment is hard-pinned to a single
# worker in BOTH `docker-compose.yml` (the `cloud-brain.command` uses
# `--reload`, which is implicitly single-worker) AND `cloud-brain/Dockerfile`
# (production CMD uses `--workers 1` with an inline comment pointing back
# here). Do not bump either without first moving this store to Redis.
#
# The cookie fallback on /checkout/stripe (HttpOnly `xrx_reveal`) is also
# process-local — same constraint applies.
#
# Storage shape (in code, not on disk):
#   _REVEAL_TOKENS[session_id] = {
#       "hash":       sha256(reveal_token) as hex,
#       "created_at": monotonic_time,
#   }

_REVEAL_TOKENS: dict[str, dict[str, Any]] = {}
_REVEAL_TOKENS_LOCK = threading.Lock()


def _reveal_token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _evict_expired_reveal_tokens(now: float) -> None:
    """Drop entries older than _REVEAL_TTL_SECONDS. Caller holds the lock."""
    expired = [
        sid for sid, rec in _REVEAL_TOKENS.items()
        if now - rec["created_at"] > _REVEAL_TTL_SECONDS
    ]
    for sid in expired:
        _REVEAL_TOKENS.pop(sid, None)


def _store_reveal_token(session_id: str) -> str:
    """Issue a fresh reveal_token for `session_id`, return the raw token.

    Old token for the same session_id is overwritten (e.g. user re-runs
    /checkout). Expired entries across the whole map are evicted on every
    write to bound memory.
    """
    token = secrets.token_urlsafe(32)
    now = time.monotonic()
    with _REVEAL_TOKENS_LOCK:
        _evict_expired_reveal_tokens(now)
        _REVEAL_TOKENS[session_id] = {
            "hash": _reveal_token_hash(token),
            "created_at": now,
        }
    return token


def validate_and_consume_reveal_token(session_id: str, token: str | None) -> bool:
    """Return True iff `token` matches the stored hash for `session_id` AND
    has not expired AND has not already been consumed.

    On success the entry is removed (one-time use) — subsequent polls get
    a 404 from the caller, preventing replay from logs / browser history.
    """
    if not session_id or not token:
        return False
    now = time.monotonic()
    with _REVEAL_TOKENS_LOCK:
        _evict_expired_reveal_tokens(now)
        rec = _REVEAL_TOKENS.get(session_id)
        if rec is None:
            return False
        if now - rec["created_at"] > _REVEAL_TTL_SECONDS:
            _REVEAL_TOKENS.pop(session_id, None)
            return False
        if not secrets.compare_digest(rec["hash"], _reveal_token_hash(token)):
            return False
        # Match — burn the entry so a second poll cannot retrieve the same
        # credentials. The license is already on disk; FE has it in memory.
        _REVEAL_TOKENS.pop(session_id, None)
        return True


def peek_reveal_token_exists(session_id: str) -> bool:
    """Lightweight check — does any (unexpired) reveal token exist for sid?"""
    now = time.monotonic()
    with _REVEAL_TOKENS_LOCK:
        rec = _REVEAL_TOKENS.get(session_id)
        if rec is None:
            return False
        if now - rec["created_at"] > _REVEAL_TTL_SECONDS:
            _REVEAL_TOKENS.pop(session_id, None)
            return False
        return True


# ─────────────────────────────────────────────────────────────────────────────
# Stripe session retrieve — short in-process cache
# ─────────────────────────────────────────────────────────────────────────────

_SESSION_CACHE: dict[str, tuple[float, Any]] = {}
_SESSION_CACHE_LOCK = threading.Lock()


def cached_stripe_session_retrieve(session_id: str) -> Any:
    """Retrieve a Stripe Checkout Session, cached ~3s per session_id.

    The FE polls /session-status every 2s for up to 60s; without a cache
    that's 30 Stripe API calls per checkout. The cache halves that without
    materially extending the pending → ready latency.
    """
    now = time.monotonic()
    with _SESSION_CACHE_LOCK:
        rec = _SESSION_CACHE.get(session_id)
        if rec is not None and now - rec[0] < _SESSION_RETRIEVE_CACHE_TTL:
            return rec[1]
    client = stripe_lib.StripeClient(settings.STRIPE_SECRET_KEY)
    obj = client.checkout.sessions.retrieve(session_id)
    with _SESSION_CACHE_LOCK:
        _SESSION_CACHE[session_id] = (time.monotonic(), obj)
        # Bound memory — drop random entries if cache grows past 1024 items.
        if len(_SESSION_CACHE) > 1024:
            for k in list(_SESSION_CACHE.keys())[:512]:
                _SESSION_CACHE.pop(k, None)
    return obj


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _new_api_key() -> str:
    return "xrx_" + secrets.token_urlsafe(40)


def _new_download_token() -> str:
    return secrets.token_urlsafe(32)


def _new_org_id() -> str:
    return str(uuid.uuid4())


def _unique_org_name(name: str, email: str, org_id: str) -> str:
    """Produce a unique display name for the customer's Org row.

    Org.name has a UNIQUE constraint in the schema, so we always append the
    first 8 hex chars of the org UUID. Two customers named "Acme Inc" stay
    distinct as "Acme Inc [a1b2c3d4]" / "Acme Inc [e5f67890]".
    """
    base = (name or "").strip() or email.split("@", 1)[0] or "Customer"
    return f"{base} [{org_id[:8]}]"


# ─────────────────────────────────────────────────────────────────────────────
# Price → tier reverse map (P0-3)
# ─────────────────────────────────────────────────────────────────────────────
#
# Building this server-side (and refusing to fall back to client-supplied
# metadata.tier) closes the trust-the-metadata vulnerability. Built lazily
# so any unconfigured price slot (empty string) doesn't collide on "".
#
# Cached after first build for the lifetime of the process; this is fine
# because Stripe Price IDs change only when an operator updates `.env` and
# restarts the service.

_PRICE_TO_TIER_CACHE: dict[str, tuple[str, str]] | None = None
_PRICE_TO_TIER_LOCK = threading.Lock()


def _price_to_tier_map() -> dict[str, tuple[str, str]]:
    """Return {price_id: (tier, cadence)} for every configured Stripe Price.

    Empty / unset env slots are skipped so they don't collide on the empty
    string. Rebuilds are not auto-invalidated; restart to pick up a change.
    """
    global _PRICE_TO_TIER_CACHE
    if _PRICE_TO_TIER_CACHE is not None:
        return _PRICE_TO_TIER_CACHE
    with _PRICE_TO_TIER_LOCK:
        if _PRICE_TO_TIER_CACHE is not None:
            return _PRICE_TO_TIER_CACHE
        m: dict[str, tuple[str, str]] = {}
        for tier in ("starter", "pro"):
            for cadence in ("monthly", "annual"):
                pid = settings.stripe_price_id(tier, cadence)
                if pid:
                    m[pid] = (tier, cadence)
        _PRICE_TO_TIER_CACHE = m
        return m


def _invalidate_price_map() -> None:
    """Test helper — force the map to rebuild on next access."""
    global _PRICE_TO_TIER_CACHE
    with _PRICE_TO_TIER_LOCK:
        _PRICE_TO_TIER_CACHE = None


_ALLOWED_TIERS = frozenset({"starter", "pro"})
_ALLOWED_CADENCES = frozenset({"monthly", "annual"})


# ─────────────────────────────────────────────────────────────────────────────
# License provisioning (shared by Stripe + ToyyibPay on payment success)
# ─────────────────────────────────────────────────────────────────────────────

async def provision_license(
    *,
    db: AsyncSession,
    email: str,
    name: str,
    provider: str,
    provider_sub_id: Optional[str],
    provider_customer_id: Optional[str],
    amount: int,
    currency: str,
    trial_days: int = 0,
    plan: str = "xarex_pro",
    scan_limit: Optional[int] = None,
) -> License:
    """Create/update Customer + Subscription + License records.

    Idempotent — if the email already has an active license, return it without
    duplicating records. On every paid event (Stripe checkout.session.completed
    or ToyyibPay status=1) we overwrite Subscription.plan/amount/currency and
    License.plan with the verified values so a Starter→Pro upgrade is reflected
    server-side immediately (H-9).
    """
    is_paid_plan = plan != "free"

    # ── 1. Get or create Customer ─────────────────────────────────────────────
    result = await db.execute(select(Customer).where(Customer.email == email))
    customer = result.scalar_one_or_none()

    if customer is None:
        customer = Customer(email=email, name=name)
        db.add(customer)
        await db.flush()

    # Update payment-gateway IDs if missing
    if provider == "stripe" and provider_customer_id and not customer.stripe_customer_id:
        customer.stripe_customer_id = provider_customer_id

    # ── 2. Get or create Subscription ────────────────────────────────────────
    result = await db.execute(
        select(Subscription).where(Subscription.customer_id == customer.id)
    )
    subscription = result.scalar_one_or_none()

    if subscription is None:
        subscription = Subscription(
            customer_id=customer.id,
            provider=provider,
            provider_sub_id=provider_sub_id,
            status="trialing" if trial_days > 0 else "active",
            plan=plan,
            amount=amount,
            currency=currency,
        )
        db.add(subscription)
    else:
        # H-9: on every paid event overwrite plan / amount / currency so a
        # Starter → Pro upgrade lands deterministically. Don't overwrite for
        # `free` plan callers (the free signup path) so a paid customer
        # doesn't get downgraded by a stale call.
        if is_paid_plan:
            subscription.plan = plan
            subscription.amount = amount
            subscription.currency = currency
        elif subscription.plan == "free":
            # First-time free signup keeps existing semantics.
            subscription.plan = plan
            subscription.amount = amount
            subscription.currency = currency
        subscription.status = "trialing" if trial_days > 0 else "active"
        subscription.provider_sub_id = provider_sub_id or subscription.provider_sub_id

    await db.flush()

    # ── 3. Get or create License ─────────────────────────────────────────────
    result = await db.execute(
        select(License).where(License.customer_id == customer.id)
    )
    license_ = result.scalar_one_or_none()
    was_upgraded = False

    if license_ is None:
        license_ = License(
            customer_id=customer.id,
            org_id=_new_org_id(),
            api_key=_new_api_key(),
            status="active",
            plan=plan,
            scan_limit=scan_limit,
            download_token=_new_download_token(),
            welcome_email_sent=False,
        )
        db.add(license_)
        await db.flush()
    else:
        license_.status = "active"
        previous_plan = license_.plan
        if is_paid_plan:
            # H-9: overwrite the License plan from the verified webhook value
            # on every paid event (covers free→Pro, Starter→Pro, etc.)
            license_.plan = plan
            # Removing scan_limit for any paid tier — free is the only gated
            # plan in the current matrix.
            license_.scan_limit = None
            if previous_plan == "free":
                was_upgraded = True

    # ── 3b. Mirror the License into an Org row ───────────────────────────────
    # auth.get_org looks up `orgs.api_key` directly; without a matching Org
    # row a paying customer's api_key returns 401. We do this for new licenses
    # AND backfill any pre-existing license that's missing an Org (covers
    # customers provisioned before this fix landed).
    org_result = await db.execute(select(Org).where(Org.id == license_.org_id))
    if org_result.scalar_one_or_none() is None:
        db.add(Org(
            id=license_.org_id,
            name=_unique_org_name(name, email, license_.org_id),
            api_key=license_.api_key,
        ))
        await db.flush()

    await db.commit()

    # Send upgrade email if this was a free → paid transition
    if was_upgraded:
        await send_upgrade_email(
            to=email,
            customer_name=name,
            org_id=license_.org_id,
            api_key=license_.api_key,
            download_token=license_.download_token,
        )
        log.info("Upgrade email sent", email_hash=_email_hash(email))

    # ── 4. Send welcome email (once only) ────────────────────────────────────
    if not license_.welcome_email_sent:
        sent = await send_welcome_email(
            to=email,
            customer_name=name,
            org_id=license_.org_id,
            api_key=license_.api_key,
            download_token=license_.download_token,
            trial_days=trial_days,
            plan=license_.plan,
            scan_limit=license_.scan_limit,
        )
        if sent:
            license_.welcome_email_sent = True
            await db.commit()
            log.info("Welcome email sent", email_hash=_email_hash(email))
        else:
            # WARNING path — keep plaintext for ops follow-up.
            log.warning("Welcome email failed to send", email=email)

    return license_


# ─────────────────────────────────────────────────────────────────────────────
# Stripe
# ─────────────────────────────────────────────────────────────────────────────

def _stripe_client() -> stripe_lib.StripeClient:
    return stripe_lib.StripeClient(settings.STRIPE_SECRET_KEY)


async def create_stripe_checkout(
    *,
    email: str,
    name: str,
    tier: str = "pro",
    cadence: str = "monthly",
) -> dict[str, str]:
    """Create a Stripe Checkout Session and return checkout_url + reveal_token.

    Return shape:
        {"checkout_url": "<hosted url>", "reveal_token": "<32B urlsafe>"}

    The reveal_token is also embedded into the Stripe `success_url` so the
    /success page can read it from URLSearchParams on redirect-back, and it
    is set as an HttpOnly cookie on the API response as a fallback (Stripe
    occasionally drops query params through aggressive enterprise proxies).

    Raises ValueError when the operator has not yet configured a price for
    that combo in `.env` — the route surfaces this as a 400 with a clear
    "contact sales" message.
    """
    # Resolve the Price ID up front so we fail before opening a Stripe
    # network connection if the combo isn't configured.
    price_id = settings.stripe_price_id(tier, cadence)
    if not price_id:
        raise ValueError(
            f"Pricing for tier={tier!r}, cadence={cadence!r} is not available yet — "
            "contact sales@xarexsec.io"
        )

    stripe = _stripe_client()

    # Find or create Stripe customer
    customers = stripe.customers.list(params={"email": email, "limit": 1})
    if customers.data:
        stripe_cid = customers.data[0].id
    else:
        cust = stripe.customers.create(params={"email": email, "name": name})
        stripe_cid = cust.id

    # tier/cadence are also stamped into metadata for diagnostic / analytics
    # purposes ONLY. The webhook MUST NOT trust these values; the canonical
    # tier is derived server-side from the price_id (see P0-3).
    meta = {
        "customer_name": name,
        "tier": tier,
        "cadence": cadence,
    }

    # We don't yet know the session_id, so issue the reveal_token after
    # creating the session. To put the token in the success_url we'd need
    # the session_id first; the order is: create session with a placeholder
    # success_url containing `{CHECKOUT_SESSION_ID}&t=<TOKEN>`, then store
    # the token keyed by session.id. Stripe substitutes CHECKOUT_SESSION_ID
    # at redirect time but does not strip unknown params like `t=`.
    reveal_token = secrets.token_urlsafe(32)

    session_params: dict = {
        "customer": stripe_cid,
        "mode": "subscription",
        "line_items": [{"price": price_id, "quantity": 1}],
        "success_url": (
            f"{settings.PUBLIC_URL}/api/billing/success"
            f"?session_id={{CHECKOUT_SESSION_ID}}&provider=stripe"
            f"&t={reveal_token}"
        ),
        "cancel_url": f"{settings.PUBLIC_URL}/#lp-pricing",
        "metadata": meta,
        "subscription_data": {
            "metadata": {**meta, "email": email},
        },
    }

    session = stripe.checkout.sessions.create(params=session_params)

    # Store the reveal_token keyed by the now-known session_id.
    now = time.monotonic()
    with _REVEAL_TOKENS_LOCK:
        _evict_expired_reveal_tokens(now)
        _REVEAL_TOKENS[session.id] = {
            "hash": _reveal_token_hash(reveal_token),
            "created_at": now,
        }

    log.info(
        "Stripe checkout session created",
        email_hash=_email_hash(email),
        session_id=session.id,
        tier=tier,
        cadence=cadence,
    )
    return {"checkout_url": session.url, "reveal_token": reveal_token}


def _minimize_payload(event_obj: Any) -> dict:
    """Return a PII-light projection of a Stripe event for BillingEvent.payload.

    Keep enough to debug a routing decision (event id, type, line item price
    IDs, totals) but drop everything that's PII: customer email, address,
    last-4, postal code, IP, browser, etc. (P0-5)
    """
    # event_obj may be a dict or the Stripe SDK object — normalise to dict.
    try:
        ev = dict(event_obj)
    except Exception:  # noqa: BLE001
        try:
            ev = event_obj.to_dict()  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            ev = {}

    data = (ev.get("data") or {})
    data_obj_raw = data.get("object") or {}
    try:
        data_obj = dict(data_obj_raw)
    except Exception:  # noqa: BLE001
        data_obj = {}

    # Line items: keep only price.id + quantity. Strip price.product metadata
    # (could carry copy/product names — not PII, but unnecessary in our log).
    line_items_min: list[dict] = []
    li_container = data_obj.get("line_items") or {}
    li_list = (
        li_container.get("data") if isinstance(li_container, dict) else li_container
    ) or []
    for item in li_list:
        try:
            it = dict(item)
        except Exception:  # noqa: BLE001
            continue
        price = it.get("price") or {}
        try:
            price_dict = dict(price)
        except Exception:  # noqa: BLE001
            price_dict = {}
        line_items_min.append({
            "price": {"id": price_dict.get("id")},
            "quantity": it.get("quantity"),
        })

    minimal = {
        "id": ev.get("id"),
        "type": ev.get("type"),
        "created": ev.get("created"),
        "api_version": ev.get("api_version"),
        "data": {
            "object": {
                "id": data_obj.get("id"),
                "customer": data_obj.get("customer"),
                "subscription": data_obj.get("subscription"),
                "mode": data_obj.get("mode"),
                "status": data_obj.get("status"),
                "payment_status": data_obj.get("payment_status"),
                "amount_total": data_obj.get("amount_total"),
                "currency": data_obj.get("currency"),
                # `metadata` is operator-controlled (we set it ourselves) and
                # so doesn't carry customer PII.
                "metadata": data_obj.get("metadata") or {},
                "line_items": line_items_min,
            }
        },
    }
    return minimal


class StripeSignatureError(Exception):
    """Raised when Stripe webhook signature verification fails.

    Distinct from generic ValueError so the route can map it specifically
    to a 400 and let everything else propagate to 500 (Stripe-retryable).
    Previously the route caught all ValueError → 400, which swallowed
    unknown-price-id failures and prevented Stripe retries (P0-4 regression).
    """


async def handle_stripe_event(*, db: AsyncSession, payload: bytes, sig_header: str) -> None:
    """Verify Stripe webhook signature and process the event.

    Raises:
      StripeSignatureError on signature verification failure — the route
      turns this into a 400, which Stripe treats as a permanent failure and
      does NOT retry. This is the correct behaviour: invalid signatures are
      not transient.

      ANY other exception (DB error, integrity error elsewhere, unknown
      price_id, programming bug) propagates out so FastAPI returns a 500
      and Stripe retries with exponential backoff (up to 3 days). This is
      the P0-4 fix — we never swallow processing errors to a 200 again, and
      we never swallow them to a 400 either (which would also stop retries).
    """
    try:
        event_obj = stripe_lib.Webhook.construct_event(
            payload, sig_header, settings.STRIPE_WEBHOOK_SECRET
        )
    except stripe_lib.error.SignatureVerificationError as exc:
        log.warning("Stripe webhook signature verification failed", error=str(exc))
        raise StripeSignatureError("Invalid Stripe signature") from exc
    except ValueError as exc:
        # construct_event raises ValueError for malformed JSON / missing
        # signature header. Permanent — Stripe should not retry.
        log.warning("Stripe webhook construct_event failed", error=str(exc))
        raise StripeSignatureError("Malformed Stripe event") from exc

    event_type = event_obj["type"]
    event_id = event_obj["id"]

    # ── Dedup via unique constraint (P0-5) ────────────────────────────────
    # The classic read-then-write pattern is racy under concurrent deliveries
    # (Stripe can fan out the same event twice within milliseconds). Let the
    # database enforce uniqueness; we catch IntegrityError and short-circuit.
    be = BillingEvent(
        provider="stripe",
        event_type=event_type,
        provider_event_id=event_id,
        payload=_minimize_payload(event_obj),
    )
    db.add(be)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        log.info("Duplicate Stripe event — skipping", event_id=event_id)
        return

    # The raw object from Stripe is a `StripeObject` (or subclass). Handlers
    # below chain `.get()` calls on nested fields (e.g. `customer_details.email`,
    # `line_items.data[0].price.id`). Stripe's `StripeObject.__getattr__` falls
    # back to `self[k]`, which raises `KeyError → AttributeError("get")` when
    # the nested value is itself a StripeObject — so chained `.get()` blows up
    # at runtime for events like `checkout.session.completed` whose payload has
    # nested children. Convert recursively to plain Python dicts so downstream
    # handlers work uniformly regardless of which subtype Stripe returns.
    data_obj = _to_plain_dict(event_obj["data"]["object"])

    if event_type == "checkout.session.completed":
        await _stripe_session_completed(db=db, session=data_obj, event_id=event_id)

    elif event_type in ("invoice.payment_succeeded", "invoice.paid"):
        await _stripe_invoice_paid(db=db, invoice=data_obj)

    elif event_type == "customer.subscription.deleted":
        await _stripe_subscription_deleted(db=db, subscription=data_obj)

    elif event_type == "invoice.payment_failed":
        await _stripe_invoice_failed(db=db, invoice=data_obj)

    be.processed = True
    await db.commit()
    log.info("Stripe event processed", event_type=event_type)


def _resolve_tier_from_session(session: dict) -> tuple[str, str]:
    """Return (tier, cadence) by reading the FIRST line item's price.id and
    looking it up in the server-side reverse map.

    Raises ValueError if the session has no line items, or the price isn't
    in the map (unknown / unconfigured price → ops alert).
    """
    # Direct first
    li_container = session.get("line_items") or {}
    li_list = (
        li_container.get("data") if isinstance(li_container, dict) else li_container
    ) or []

    if not li_list:
        # The webhook payload sometimes lacks expanded line_items — retrieve.
        session_id = session.get("id")
        if not session_id:
            raise ValueError("Stripe session missing id; cannot resolve tier")
        client = stripe_lib.StripeClient(settings.STRIPE_SECRET_KEY)
        full = client.checkout.sessions.retrieve(
            session_id,
            params={"expand": ["line_items"]},
        )
        try:
            full_dict = dict(full)
        except Exception:  # noqa: BLE001
            try:
                full_dict = full.to_dict()  # type: ignore[attr-defined]
            except Exception:  # noqa: BLE001
                full_dict = {}
        li_container = full_dict.get("line_items") or {}
        li_list = (
            li_container.get("data") if isinstance(li_container, dict) else li_container
        ) or []

    if not li_list:
        raise ValueError("Stripe session has no line_items; cannot resolve tier")

    first = li_list[0]
    try:
        first_d = dict(first)
    except Exception:  # noqa: BLE001
        first_d = {}
    price = first_d.get("price") or {}
    try:
        price_d = dict(price)
    except Exception:  # noqa: BLE001
        price_d = {}
    price_id = price_d.get("id") or first_d.get("price")
    if not isinstance(price_id, str) or not price_id:
        raise ValueError("Stripe line_item missing price.id")

    mapping = _price_to_tier_map()
    if price_id not in mapping:
        # P0-3: surface as an exception. We must NOT silently default to a
        # tier on an unknown price — that would let a price imported via
        # dashboard or any future client-supplied price provision a license.
        raise ValueError(
            f"Stripe price_id {price_id!r} is not in the configured "
            f"price→tier map. Ops must update STRIPE_PRICE_<TIER>_<CADENCE>."
        )
    tier, cadence = mapping[price_id]
    if tier not in _ALLOWED_TIERS or cadence not in _ALLOWED_CADENCES:
        # Defence-in-depth — the map is only populated from settings, but
        # this guards a misconfiguration that slips through.
        raise ValueError(f"Resolved tier/cadence outside allowlist: {tier}/{cadence}")
    return tier, cadence


async def _stripe_session_completed(*, db: AsyncSession, session, event_id: str) -> None:
    customer_id = session.get("customer")
    email = session.get("customer_details", {}).get("email") or session.get("customer_email", "")
    metadata = session.get("metadata") or {}
    name = metadata.get("customer_name", email.split("@")[0] if email else "")
    sub_id = session.get("subscription")

    if not email:
        # Plaintext is fine here — WARNING path, no email anyway.
        log.warning(
            "Stripe session.completed missing email",
            session_id=session.get("id"),
            event_id=event_id,
        )
        return

    # P0-3: derive tier+cadence from price_id, NOT from metadata.tier
    tier, cadence = _resolve_tier_from_session(session)

    amount_total = session.get("amount_total") or 0
    currency = (session.get("currency") or settings.STRIPE_CURRENCY).lower()

    await provision_license(
        db=db,
        email=email,
        name=name,
        provider="stripe",
        provider_sub_id=sub_id,
        provider_customer_id=customer_id,
        amount=amount_total,
        currency=currency,
        trial_days=0,
        plan=f"xarex_{tier}",
    )
    log.info(
        "Stripe checkout provisioned",
        email_hash=_email_hash(email),
        tier=tier,
        cadence=cadence,
    )


async def _stripe_invoice_paid(*, db: AsyncSession, invoice) -> None:
    """Reactivate suspended license on successful renewal payment."""
    customer_id = invoice.get("customer")
    email = invoice.get("customer_email", "")
    if not email:
        return

    result = await db.execute(
        select(Customer).where(Customer.stripe_customer_id == customer_id)
    )
    customer = result.scalar_one_or_none()
    if not customer:
        return

    result = await db.execute(
        select(Subscription).where(Subscription.customer_id == customer.id)
    )
    sub = result.scalar_one_or_none()
    if sub and sub.status in ("past_due", "suspended"):
        sub.status = "active"

    result = await db.execute(
        select(License).where(License.customer_id == customer.id)
    )
    lic = result.scalar_one_or_none()
    if lic and lic.status == "suspended":
        lic.status = "active"

    await db.commit()
    log.info(
        "Stripe invoice paid — license reactivated",
        email_hash=_email_hash(email),
    )


async def _stripe_subscription_deleted(*, db: AsyncSession, subscription) -> None:
    """Cancel the license when Stripe subscription is deleted."""
    customer_id = subscription.get("customer")

    result = await db.execute(
        select(Customer).where(Customer.stripe_customer_id == customer_id)
    )
    customer = result.scalar_one_or_none()
    if not customer:
        return

    result = await db.execute(
        select(Subscription).where(Subscription.customer_id == customer.id)
    )
    sub = result.scalar_one_or_none()
    if sub:
        sub.status = "cancelled"
        sub.cancelled_at = datetime.now(timezone.utc)

    result = await db.execute(
        select(License).where(License.customer_id == customer.id)
    )
    lic = result.scalar_one_or_none()
    if lic:
        lic.status = "cancelled"

    await db.commit()
    # WARNING-ish path (cancellation is operator-relevant) — keep customer_id
    # only, no email.
    log.info("Stripe subscription deleted — license cancelled", customer_id=customer_id)


async def _stripe_invoice_failed(*, db: AsyncSession, invoice) -> None:
    customer_id = invoice.get("customer")
    result = await db.execute(
        select(Customer).where(Customer.stripe_customer_id == customer_id)
    )
    customer = result.scalar_one_or_none()
    if not customer:
        return

    result = await db.execute(
        select(Subscription).where(Subscription.customer_id == customer.id)
    )
    sub = result.scalar_one_or_none()
    if sub:
        sub.status = "past_due"

    await db.commit()
    # Failure path — full email retained for dunning follow-up.
    log.warning(
        "Stripe invoice payment failed",
        customer_id=customer_id,
        email=invoice.get("customer_email", ""),
    )


# ─────────────────────────────────────────────────────────────────────────────
# ToyyibPay
# ─────────────────────────────────────────────────────────────────────────────

def _toyyibpay_base() -> str:
    return "https://dev.toyyibpay.com" if settings.TOYYIBPAY_SANDBOX else "https://toyyibpay.com"


async def create_toyyibpay_bill(*, email: str, name: str) -> str:
    """Create a ToyyibPay bill and return the payment URL."""
    base = _toyyibpay_base()

    amount_rm = f"{settings.TOYYIBPAY_AMOUNT_CENTS / 100:.2f}"

    callback_url = f"{settings.PUBLIC_URL}/api/billing/callback/toyyibpay"
    return_url = f"{settings.PUBLIC_URL}/api/billing/success?provider=toyyibpay"

    payload = {
        "userSecretKey":      settings.TOYYIBPAY_SECRET_KEY,
        "categoryCode":       settings.TOYYIBPAY_CATEGORY_CODE,
        "billName":           "Xarex Pro",
        "billDescription":    f"Xarex Pro subscription – {name}",
        "billPriceSetting":   1,
        "billPayorInfo":      1,
        "billAmount":         amount_rm,
        "billReturnUrl":      return_url,
        "billCallbackUrl":    callback_url,
        "billExternalReferenceNo": f"XRX-{secrets.token_hex(6).upper()}",
        "billTo":             name,
        "billEmail":          email,
        "billPhone":          "",
        "billSplitPayment":   0,
        "billSplitPaymentArgs": "",
        "billPaymentChannel": 0,
        "billDisplayMerchant": 1,
        "billContentEmail":   f"Thank you for subscribing to Xarex Pro, {name}!",
        "billChargeToCustomer": 0,
    }

    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.post(f"{base}/index.php/api/createBill", data=payload)
        resp.raise_for_status()
        data = resp.json()

    if not data or not isinstance(data, list) or not data[0].get("BillCode"):
        raise RuntimeError(f"ToyyibPay createBill failed: {data}")

    bill_code = data[0]["BillCode"]
    pay_url = f"{base}/{bill_code}"
    log.info("ToyyibPay bill created", email_hash=_email_hash(email), bill_code=bill_code)
    return pay_url


async def handle_toyyibpay_callback(
    *,
    db: AsyncSession,
    ref_no: str,
    status: str,
    reason: str,
    bill_code: str,
    order_id: str,
    amount: str,
    name: str,
    email: str,
    phone: str,
) -> None:
    """Process ToyyibPay payment callback.

    status: "1" = success, "2" = pending, "3" = failed
    """
    # ToyyibPay payload is much smaller and operator-controlled, but we
    # still drop `phone` (PII) to match the Stripe minimisation policy.
    be = BillingEvent(
        provider="toyyibpay",
        event_type=f"payment.status.{status}",
        provider_event_id=ref_no or bill_code,
        customer_email=email,
        payload={
            "ref_no": ref_no,
            "status": status,
            "reason": reason,
            "bill_code": bill_code,
            "order_id": order_id,
            "amount": amount,
        },
    )
    db.add(be)

    if status == "1":
        await provision_license(
            db=db,
            email=email,
            name=name or email.split("@")[0],
            provider="toyyibpay",
            provider_sub_id=bill_code,
            provider_customer_id=None,
            amount=settings.TOYYIBPAY_AMOUNT_CENTS,
            currency=settings.STRIPE_CURRENCY,
            trial_days=0,
        )
        be.processed = True
    else:
        await db.commit()
        log.info(
            "ToyyibPay callback received",
            status=status,
            email_hash=_email_hash(email),
        )


# ─────────────────────────────────────────────────────────────────────────────
# License lookup
# ─────────────────────────────────────────────────────────────────────────────

async def get_license_by_email(*, db: AsyncSession, email: str) -> Optional[License]:
    result = await db.execute(
        select(Customer).where(Customer.email == email)
    )
    customer = result.scalar_one_or_none()
    if not customer:
        return None

    result = await db.execute(
        select(License).where(License.customer_id == customer.id)
    )
    return result.scalar_one_or_none()


async def get_license_by_token(*, db: AsyncSession, token: str) -> Optional[License]:
    result = await db.execute(
        select(License).where(License.download_token == token)
    )
    return result.scalar_one_or_none()


# ─────────────────────────────────────────────────────────────────────────────
# Free plan
# ─────────────────────────────────────────────────────────────────────────────

async def provision_free_license(*, db: AsyncSession, email: str, name: str) -> License:
    """Provision a free-tier license (no payment required)."""
    if not settings.FREE_PLAN_ENABLED:
        raise ValueError("Free plan is currently disabled")

    existing = await get_license_by_email(db=db, email=email)
    if existing:
        raise ValueError("An account already exists for this email address")

    return await provision_license(
        db=db,
        email=email,
        name=name,
        provider="free",
        provider_sub_id=None,
        provider_customer_id=None,
        amount=0,
        currency=settings.STRIPE_CURRENCY,
        trial_days=0,
        plan="free",
        scan_limit=settings.FREE_PLAN_SCAN_LIMIT,
    )


async def check_scan_allowed(*, db: AsyncSession, api_key: str) -> tuple[bool, str]:
    """Return (allowed, reason)."""
    result = await db.execute(select(License).where(License.api_key == api_key))
    lic = result.scalar_one_or_none()

    if not lic:
        return False, "Invalid API key"
    if lic.status != "active":
        return False, f"License is {lic.status}"
    if lic.plan == "free" and lic.scan_limit is not None and lic.scan_count >= lic.scan_limit:
        return False, (
            f"Free plan limit reached ({lic.scan_limit} scans). "
            "Upgrade to Xarex Pro for unlimited scans."
        )
    return True, "ok"


async def increment_scan_count(*, db: AsyncSession, api_key: str) -> None:
    """Increment scan_count for a license (called when a scan is launched)."""
    result = await db.execute(select(License).where(License.api_key == api_key))
    lic = result.scalar_one_or_none()
    if lic and lic.plan == "free":
        lic.scan_count = (lic.scan_count or 0) + 1
        await db.commit()
