"""Unit tests for billing endpoints (POST /api/billing/*, GET /session-status).

Covers the tiered Stripe checkout refactor:
  - Pydantic Literal validation on tier/cadence (422 on garbage)
  - Unconfigured tier → 400 with a "contact sales" message (no Stripe call)
  - Happy-path checkout with a stubbed Stripe client returns a URL
  - /session-status: pending vs ready transitions
  - Free signup regression — still works end-to-end

The fake AsyncSession from conftest.py underpins all DB access. The Stripe
client is stubbed via monkeypatch on the module-level `stripe_lib` import
so no test makes a real network call.
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# Stripe client stub
# ─────────────────────────────────────────────────────────────────────────────

class _FakeCustomers:
    """Stand-in for stripe.customers.{list,create}."""
    def list(self, *, params: dict) -> SimpleNamespace:
        # No existing customer → forces .create() path.
        return SimpleNamespace(data=[])

    def create(self, *, params: dict) -> SimpleNamespace:
        return SimpleNamespace(id="cus_test_123")


class _FakeSessions:
    """Stand-in for stripe.checkout.sessions.{create,retrieve}."""
    def __init__(self) -> None:
        self.last_params: dict | None = None
        # Default retrieve() response — overridden per test.
        self.retrieve_response: Any = SimpleNamespace(
            status="complete",
            payment_status="paid",
            customer_details={"email": "ready@example.com"},
            customer_email="ready@example.com",
        )

    def create(self, *, params: dict) -> SimpleNamespace:
        self.last_params = params
        return SimpleNamespace(
            id="cs_test_abc",
            url="https://checkout.stripe.com/c/pay/cs_test_abc",
        )

    def retrieve(self, session_id: str) -> Any:
        return self.retrieve_response


class _FakeCheckout:
    def __init__(self, sessions: _FakeSessions) -> None:
        self.sessions = sessions


class _FakeStripeClient:
    def __init__(self, secret: str = "") -> None:
        self.customers = _FakeCustomers()
        self.checkout = _FakeCheckout(_FakeSessions())


@pytest.fixture
def fake_stripe(monkeypatch: pytest.MonkeyPatch) -> _FakeStripeClient:
    """Replace the Stripe SDK with a deterministic fake for one test."""
    client = _FakeStripeClient()

    # Patch the StripeClient constructor on both modules that import it.
    # services.billing builds one inside create_stripe_checkout; api.billing
    # builds one inside /session-status.
    import services.billing as svc_billing
    import api.billing as api_billing

    def _factory(_secret: str) -> _FakeStripeClient:
        return client

    monkeypatch.setattr(svc_billing.stripe_lib, "StripeClient", _factory)
    monkeypatch.setattr(api_billing.stripe_lib, "StripeClient", _factory)

    # STRIPE_SECRET_KEY is a real Settings field, so monkeypatch.setattr on
    # the instance is OK (pydantic v2 allows setting existing fields).
    monkeypatch.setattr(svc_billing.settings, "STRIPE_SECRET_KEY", "sk_test_unit")
    monkeypatch.setattr(api_billing.settings, "STRIPE_SECRET_KEY", "sk_test_unit")

    return client


# ─────────────────────────────────────────────────────────────────────────────
# POST /checkout/stripe — validation
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_checkout_invalid_tier_returns_422(client) -> None:
    """Pydantic Literal rejects unknown tiers before any service code runs."""
    resp = await client.post(
        "/api/billing/checkout/stripe",
        json={
            "email": "buyer@example.com",
            "name": "Buyer",
            "tier": "garbage",
            "cadence": "monthly",
        },
    )
    assert resp.status_code == 422, resp.text


@pytest.mark.asyncio
async def test_checkout_invalid_cadence_returns_422(client) -> None:
    resp = await client.post(
        "/api/billing/checkout/stripe",
        json={
            "email": "buyer@example.com",
            "name": "Buyer",
            "tier": "pro",
            "cadence": "weekly",  # not in {"monthly","annual"}
        },
    )
    assert resp.status_code == 422, resp.text


@pytest.mark.asyncio
async def test_checkout_unconfigured_tier_returns_400(
    client, fake_stripe, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Valid tier+cadence but operator hasn't created the Price in Stripe yet."""
    # Force every price lookup to return empty (the "not configured" state).
    # Patch on the Settings class because pydantic v2 BaseSettings blocks
    # setattr on instances.
    from config import Settings

    monkeypatch.setattr(
        Settings,
        "stripe_price_id",
        lambda self, tier, cadence: None,
    )

    resp = await client.post(
        "/api/billing/checkout/stripe",
        json={
            "email": "buyer@example.com",
            "name": "Buyer",
            "tier": "starter",
            "cadence": "annual",
        },
    )
    assert resp.status_code == 400, resp.text
    body = resp.json()
    # The message must surface the actionable next step (contact sales).
    assert "contact" in body["detail"].lower() or "not available" in body["detail"].lower()


@pytest.mark.asyncio
async def test_checkout_happy_path_returns_url(
    client, fake_stripe, monkeypatch: pytest.MonkeyPatch
) -> None:
    """tier=pro, cadence=monthly with a configured Price → returns Checkout URL."""
    from config import Settings

    monkeypatch.setattr(
        Settings,
        "stripe_price_id",
        lambda self, tier, cadence: "price_test_PRO_MONTHLY",
    )

    resp = await client.post(
        "/api/billing/checkout/stripe",
        json={
            "email": "buyer@example.com",
            "name": "Buyer",
            "tier": "pro",
            "cadence": "monthly",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["url"].startswith("https://checkout.stripe.com/")
    # Verify the tier+cadence made it into Stripe Session metadata so the
    # webhook can recover them.
    sent = fake_stripe.checkout.sessions.last_params
    assert sent is not None
    assert sent["metadata"]["tier"] == "pro"
    assert sent["metadata"]["cadence"] == "monthly"
    # And no time-based trial — usage-based only now.
    assert "trial_period_days" not in sent.get("subscription_data", {})


@pytest.mark.asyncio
async def test_checkout_503_when_stripe_unconfigured(
    client, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Missing STRIPE_SECRET_KEY → 503 (operator hasn't wired anything yet)."""
    import api.billing as api_billing
    monkeypatch.setattr(api_billing.settings, "STRIPE_SECRET_KEY", "")

    resp = await client.post(
        "/api/billing/checkout/stripe",
        json={
            "email": "buyer@example.com",
            "name": "Buyer",
            "tier": "pro",
            "cadence": "monthly",
        },
    )
    assert resp.status_code == 503, resp.text


# ─────────────────────────────────────────────────────────────────────────────
# GET /session-status — closes the post-redirect race
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# Helpers for the reveal-token security model (P0-1)
# ─────────────────────────────────────────────────────────────────────────────

# 32 chars matches the regex `cs_(test|live)_[A-Za-z0-9]{20,200}$`.
_VALID_SID_PENDING = "cs_test_" + "Pending1234567890ABCDEF1234"
_VALID_SID_READY   = "cs_test_" + "Ready1234567890ABCDEF12345"
_VALID_SID_DEAD    = "cs_test_" + "Dead1234567890ABCDEF123456"


def _install_reveal_token(session_id: str) -> str:
    """Issue a reveal_token for `session_id` directly in the in-memory store
    (mirrors what create_stripe_checkout does on the live path)."""
    import time
    import services.billing as svc_billing
    token = "rvl_test_" + "x" * 30
    with svc_billing._REVEAL_TOKENS_LOCK:
        svc_billing._REVEAL_TOKENS[session_id] = {
            "hash": svc_billing._reveal_token_hash(token),
            "created_at": time.monotonic(),
        }
    return token


@pytest.fixture(autouse=True)
def _reset_reveal_token_store() -> None:
    """Clear the process-local reveal_token store between tests."""
    import services.billing as svc_billing
    with svc_billing._REVEAL_TOKENS_LOCK:
        svc_billing._REVEAL_TOKENS.clear()
    with svc_billing._SESSION_CACHE_LOCK:
        svc_billing._SESSION_CACHE.clear()


@pytest.mark.asyncio
async def test_session_status_pending_when_no_license(
    client, fake_stripe, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Session complete on Stripe's side but webhook hasn't provisioned yet."""
    sid = _VALID_SID_PENDING
    token = _install_reveal_token(sid)
    # Stripe says complete + paid…
    fake_stripe.checkout.sessions.retrieve_response = SimpleNamespace(
        status="complete",
        payment_status="paid",
        customer_details={"email": "racing@example.com"},
        customer_email="racing@example.com",
    )
    # …but no License row exists.
    import api.billing as api_billing

    async def _no_license(*, db, email):  # noqa: ANN001
        return None

    monkeypatch.setattr(api_billing, "get_license_by_email", _no_license)

    resp = await client.get(
        "/api/billing/session-status",
        params={"session_id": sid, "t": token},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "pending"
    assert body["license"] is None


@pytest.mark.asyncio
async def test_session_status_ready_when_license_provisioned(
    client, fake_stripe, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Session complete AND License row exists → status='ready' with creds."""
    sid = _VALID_SID_READY
    token = _install_reveal_token(sid)
    fake_stripe.checkout.sessions.retrieve_response = SimpleNamespace(
        status="complete",
        payment_status="paid",
        customer_details={"email": "ready@example.com"},
        customer_email="ready@example.com",
    )

    import api.billing as api_billing

    fake_license = SimpleNamespace(
        org_id="org-uuid-123",
        api_key="xrx_test_abc",
        plan="xarex_pro",
        download_token="tok_test_xyz",
        status="active",
    )

    async def _ready(*, db, email):  # noqa: ANN001
        assert email == "ready@example.com"
        return fake_license

    monkeypatch.setattr(api_billing, "get_license_by_email", _ready)

    resp = await client.get(
        "/api/billing/session-status",
        params={"session_id": sid, "t": token},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "ready"
    assert body["license"] == {
        "org_id": "org-uuid-123",
        "api_key": "xrx_test_abc",
        "plan": "xarex_pro",
        "download_token": "tok_test_xyz",
    }


@pytest.mark.asyncio
async def test_session_status_failed_when_expired(
    client, fake_stripe, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Stripe reports expired/unpaid → status='failed'."""
    sid = _VALID_SID_DEAD
    token = _install_reveal_token(sid)
    fake_stripe.checkout.sessions.retrieve_response = SimpleNamespace(
        status="expired",
        payment_status="unpaid",
        customer_details={},
        customer_email="",
    )

    resp = await client.get(
        "/api/billing/session-status",
        params={"session_id": sid, "t": token},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "failed"


@pytest.mark.asyncio
async def test_session_status_rejects_bad_session_id(client, fake_stripe) -> None:
    """session_id that doesn't match Stripe's regex → 404 (no oracle, H-6)."""
    resp = await client.get(
        "/api/billing/session-status",
        params={"session_id": "not-a-stripe-id", "t": "anything"},
    )
    assert resp.status_code == 404, resp.text


# ─────────────────────────────────────────────────────────────────────────────
# P0/H security regression tests (api-security-reviewer remediation)
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_session_status_requires_reveal_token(client, fake_stripe) -> None:
    """Missing `t` query param → 404 (no oracle vs other failures)."""
    sid = _VALID_SID_PENDING
    _install_reveal_token(sid)
    resp = await client.get(
        "/api/billing/session-status",
        params={"session_id": sid},
    )
    assert resp.status_code == 404, resp.text


@pytest.mark.asyncio
async def test_session_status_wrong_token_returns_404_not_403(
    client, fake_stripe, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Wrong token returns 404 — same shape as missing/expired (no oracle)."""
    sid = _VALID_SID_READY
    _install_reveal_token(sid)  # ignore returned token; pass a wrong one

    fake_stripe.checkout.sessions.retrieve_response = SimpleNamespace(
        status="complete",
        payment_status="paid",
        customer_details={"email": "ready@example.com"},
        customer_email="ready@example.com",
    )
    import api.billing as api_billing

    fake_license = SimpleNamespace(
        org_id="o", api_key="k", plan="xarex_pro",
        download_token="d", status="active",
    )

    async def _ready(*, db, email):  # noqa: ANN001
        return fake_license

    monkeypatch.setattr(api_billing, "get_license_by_email", _ready)

    resp = await client.get(
        "/api/billing/session-status",
        params={"session_id": sid, "t": "this_is_not_the_real_token"},
    )
    assert resp.status_code == 404, resp.text


@pytest.mark.asyncio
async def test_session_status_token_is_one_time_use(
    client, fake_stripe, monkeypatch: pytest.MonkeyPatch
) -> None:
    """First poll returns ready and burns the token; second poll → 404."""
    sid = _VALID_SID_READY
    token = _install_reveal_token(sid)

    fake_stripe.checkout.sessions.retrieve_response = SimpleNamespace(
        status="complete",
        payment_status="paid",
        customer_details={"email": "once@example.com"},
        customer_email="once@example.com",
    )
    import api.billing as api_billing

    fake_license = SimpleNamespace(
        org_id="o", api_key="k", plan="xarex_pro",
        download_token="d", status="active",
    )

    async def _ready(*, db, email):  # noqa: ANN001
        return fake_license

    monkeypatch.setattr(api_billing, "get_license_by_email", _ready)

    resp1 = await client.get(
        "/api/billing/session-status",
        params={"session_id": sid, "t": token},
    )
    assert resp1.status_code == 200, resp1.text
    assert resp1.json()["status"] == "ready"

    # Second poll on the same session+token → 404 (burned)
    resp2 = await client.get(
        "/api/billing/session-status",
        params={"session_id": sid, "t": token},
    )
    assert resp2.status_code == 404, resp2.text


@pytest.mark.asyncio
async def test_session_status_rate_limited(
    client, fake_stripe, monkeypatch: pytest.MonkeyPatch
) -> None:
    """31 hits/min from the same IP → at least one 429 (slowapi 30/minute)."""
    # We don't care about the response shape — only that the limiter trips.
    saw_429 = False
    for i in range(35):
        resp = await client.get(
            "/api/billing/session-status",
            params={"session_id": "cs_test_x", "t": "y"},
        )
        if resp.status_code == 429:
            saw_429 = True
            break
    assert saw_429, "Expected at least one 429 within 35 rapid hits"


@pytest.mark.asyncio
async def test_checkout_rate_limited(
    client, fake_stripe, monkeypatch: pytest.MonkeyPatch
) -> None:
    """11 hits/min on /checkout/stripe → at least one 429."""
    from config import Settings
    monkeypatch.setattr(
        Settings, "stripe_price_id",
        lambda self, tier, cadence: "price_test_PRO_MONTHLY",
    )
    saw_429 = False
    for _ in range(15):
        resp = await client.post(
            "/api/billing/checkout/stripe",
            json={
                "email": "rl@example.com",
                "name": "RL",
                "tier": "pro",
                "cadence": "monthly",
            },
        )
        if resp.status_code == 429:
            saw_429 = True
            break
    assert saw_429, "Expected at least one 429 within 15 rapid checkout hits"


# ─────────────────────────────────────────────────────────────────────────────
# Webhook security regressions (P0-3, P0-4, P0-5)
# ─────────────────────────────────────────────────────────────────────────────

def _make_event(*, event_id: str, price_id: str, email: str = "buyer@example.com",
                metadata: dict | None = None) -> dict:
    """Build a minimal checkout.session.completed event payload."""
    return {
        "id": event_id,
        "type": "checkout.session.completed",
        "created": 1700000000,
        "api_version": "2024-06-20",
        "data": {
            "object": {
                "id": "cs_test_" + "Z" * 24,
                "object": "checkout.session",
                "customer": "cus_test_abc",
                "customer_email": email,
                "customer_details": {"email": email, "name": "Buyer"},
                "mode": "subscription",
                "status": "complete",
                "payment_status": "paid",
                "amount_total": 4900,
                "currency": "usd",
                "subscription": "sub_test_xyz",
                "metadata": metadata or {"tier": "pro", "cadence": "monthly"},
                "line_items": {
                    "data": [{
                        "price": {"id": price_id},
                        "quantity": 1,
                    }],
                },
            },
        },
    }


@pytest.fixture
def _stub_webhook_signature(monkeypatch: pytest.MonkeyPatch):
    """Bypass Stripe webhook signature verification — return supplied event."""
    import services.billing as svc_billing

    captured: dict = {}

    def _factory(event_dict: dict):
        def _construct_event(payload, sig_header, secret):  # noqa: ANN001
            captured["called"] = True
            return event_dict
        return _construct_event

    return _factory, captured


@pytest.mark.asyncio
async def test_webhook_derives_tier_from_price_not_metadata(
    client, fake_stripe, monkeypatch: pytest.MonkeyPatch, _stub_webhook_signature,
) -> None:
    """metadata.tier='pro' but line_items has Starter price → plan=xarex_starter."""
    import services.billing as svc_billing
    factory, _ = _stub_webhook_signature

    # Configure prices so the reverse map maps STARTER_MONTHLY → ("starter","monthly")
    monkeypatch.setattr(
        svc_billing.settings, "STRIPE_PRICE_STARTER_MONTHLY", "price_STARTER_M"
    )
    monkeypatch.setattr(
        svc_billing.settings, "STRIPE_PRICE_STARTER_ANNUAL", "price_STARTER_A"
    )
    monkeypatch.setattr(
        svc_billing.settings, "STRIPE_PRICE_PRO_MONTHLY", "price_PRO_M"
    )
    monkeypatch.setattr(
        svc_billing.settings, "STRIPE_PRICE_PRO_ANNUAL", "price_PRO_A"
    )
    svc_billing._invalidate_price_map()

    ev = _make_event(event_id="evt_starter_1", price_id="price_STARTER_M",
                     metadata={"tier": "pro", "cadence": "monthly"})
    monkeypatch.setattr(svc_billing.stripe_lib.Webhook, "construct_event", factory(ev))

    captured_plan: dict = {}

    async def _fake_provision(*, db, email, name, provider, provider_sub_id,
                              provider_customer_id, amount, currency,
                              trial_days=0, plan="xarex_pro", scan_limit=None):
        captured_plan["plan"] = plan
        return SimpleNamespace(org_id="o", api_key="k", download_token="d", scan_limit=None)

    monkeypatch.setattr(svc_billing, "provision_license", _fake_provision)

    resp = await client.post(
        "/api/billing/webhook/stripe",
        content=b"{}",
        headers={"stripe-signature": "t=1,v1=fake"},
    )
    assert resp.status_code == 200, resp.text
    assert captured_plan.get("plan") == "xarex_starter"


@pytest.mark.asyncio
async def test_webhook_rejects_unknown_price_id(
    client, fake_stripe, monkeypatch: pytest.MonkeyPatch, _stub_webhook_signature,
) -> None:
    """Price not in reverse map → bubbles out (5xx in production, raises in tests).

    P0-4: the webhook must NOT swallow processing errors to a 200. In a real
    FastAPI deployment this surfaces as a 500 (default exception handler) so
    Stripe retries. In httpx + ASGITransport the raised exception propagates
    instead of being converted — both are correct "do not 200" signals.
    """
    import services.billing as svc_billing
    factory, _ = _stub_webhook_signature

    monkeypatch.setattr(svc_billing.settings, "STRIPE_PRICE_STARTER_MONTHLY", "price_KNOWN")
    monkeypatch.setattr(svc_billing.settings, "STRIPE_PRICE_STARTER_ANNUAL", "")
    monkeypatch.setattr(svc_billing.settings, "STRIPE_PRICE_PRO_MONTHLY", "")
    monkeypatch.setattr(svc_billing.settings, "STRIPE_PRICE_PRO_ANNUAL", "")
    svc_billing._invalidate_price_map()

    ev = _make_event(event_id="evt_unknown_1", price_id="price_UNCONFIGURED")
    monkeypatch.setattr(svc_billing.stripe_lib.Webhook, "construct_event", factory(ev))

    raised: Exception | None = None
    resp = None
    try:
        resp = await client.post(
            "/api/billing/webhook/stripe",
            content=b"{}",
            headers={"stripe-signature": "t=1,v1=fake"},
        )
    except Exception as exc:  # noqa: BLE001
        raised = exc

    # Either path is acceptable: 5xx response OR raised exception.
    assert raised is not None or (resp is not None and resp.status_code >= 500), (
        f"Expected a 5xx or raised exception; got resp={resp!r} raised={raised!r}"
    )


@pytest.mark.asyncio
async def test_webhook_dedup_via_unique_constraint(
    client, fake_stripe, monkeypatch: pytest.MonkeyPatch, _stub_webhook_signature, fake_db,
) -> None:
    """Same event_id twice → both 2xx but provision_license called only once."""
    import services.billing as svc_billing
    from sqlalchemy.exc import IntegrityError
    factory, _ = _stub_webhook_signature

    monkeypatch.setattr(svc_billing.settings, "STRIPE_PRICE_PRO_MONTHLY", "price_PRO_M")
    monkeypatch.setattr(svc_billing.settings, "STRIPE_PRICE_STARTER_MONTHLY", "")
    monkeypatch.setattr(svc_billing.settings, "STRIPE_PRICE_STARTER_ANNUAL", "")
    monkeypatch.setattr(svc_billing.settings, "STRIPE_PRICE_PRO_ANNUAL", "")
    svc_billing._invalidate_price_map()

    ev = _make_event(event_id="evt_dup_1", price_id="price_PRO_M")
    monkeypatch.setattr(svc_billing.stripe_lib.Webhook, "construct_event", factory(ev))

    call_count = {"n": 0}

    async def _fake_provision(*args, **kwargs):
        call_count["n"] += 1
        return SimpleNamespace(org_id="o", api_key="k", download_token="d")

    monkeypatch.setattr(svc_billing, "provision_license", _fake_provision)

    # First call: succeeds normally.
    resp1 = await client.post(
        "/api/billing/webhook/stripe",
        content=b"{}",
        headers={"stripe-signature": "t=1,v1=fake"},
    )
    assert resp1.status_code == 200, resp1.text

    # Now simulate the unique constraint kicking in on the duplicate.
    original_flush = fake_db.flush
    flush_calls = {"n": 0}

    async def _flush_raise_once():
        flush_calls["n"] += 1
        if flush_calls["n"] == 1:
            raise IntegrityError("dup", {}, Exception("duplicate key"))
        return await original_flush()

    monkeypatch.setattr(fake_db, "flush", _flush_raise_once)

    resp2 = await client.post(
        "/api/billing/webhook/stripe",
        content=b"{}",
        headers={"stripe-signature": "t=1,v1=fake"},
    )
    assert resp2.status_code == 200, resp2.text
    # Only the first call should have provisioned.
    assert call_count["n"] == 1


@pytest.mark.asyncio
async def test_webhook_db_error_bubbles_to_500(
    client, fake_stripe, monkeypatch: pytest.MonkeyPatch, _stub_webhook_signature,
) -> None:
    """provision_license raises → response is 500, NOT 200 (P0-4)."""
    import services.billing as svc_billing
    factory, _ = _stub_webhook_signature

    monkeypatch.setattr(svc_billing.settings, "STRIPE_PRICE_PRO_MONTHLY", "price_PRO_M")
    monkeypatch.setattr(svc_billing.settings, "STRIPE_PRICE_STARTER_MONTHLY", "")
    monkeypatch.setattr(svc_billing.settings, "STRIPE_PRICE_STARTER_ANNUAL", "")
    monkeypatch.setattr(svc_billing.settings, "STRIPE_PRICE_PRO_ANNUAL", "")
    svc_billing._invalidate_price_map()

    ev = _make_event(event_id="evt_err_1", price_id="price_PRO_M")
    monkeypatch.setattr(svc_billing.stripe_lib.Webhook, "construct_event", factory(ev))

    async def _explode(*args, **kwargs):
        raise RuntimeError("simulated DB failure")

    monkeypatch.setattr(svc_billing, "provision_license", _explode)

    raised: Exception | None = None
    resp = None
    try:
        resp = await client.post(
            "/api/billing/webhook/stripe",
            content=b"{}",
            headers={"stripe-signature": "t=1,v1=fake"},
        )
    except Exception as exc:  # noqa: BLE001
        raised = exc

    # P0-4: must NOT return 200 — either 5xx or raised exception.
    assert raised is not None or (resp is not None and resp.status_code >= 500), (
        f"Expected a 5xx or raised exception; got resp={resp!r} raised={raised!r}"
    )


def test_billing_event_payload_is_minimized() -> None:
    """_minimize_payload strips PII fields from a full Stripe event."""
    import services.billing as svc_billing
    raw = {
        "id": "evt_x",
        "type": "checkout.session.completed",
        "created": 1700000000,
        "api_version": "2024-06-20",
        "request": {"id": "req_x", "idempotency_key": "key_x"},
        "data": {
            "object": {
                "id": "cs_x",
                "customer": "cus_x",
                "customer_email": "leak@example.com",
                "customer_details": {
                    "email": "leak@example.com",
                    "address": {"line1": "1 Lane", "postal_code": "12345"},
                    "phone": "+1-555",
                    "name": "Mr Leak",
                },
                "payment_method_details": {"card": {"last4": "4242"}},
                "shipping": {"address": {"line1": "x"}},
                "subscription": "sub_x",
                "mode": "subscription",
                "status": "complete",
                "amount_total": 4900,
                "currency": "usd",
                "metadata": {"tier": "pro"},
                "line_items": {"data": [{"price": {"id": "price_x"}, "quantity": 1}]},
            },
        },
    }
    minimal = svc_billing._minimize_payload(raw)
    flat = repr(minimal)
    assert "leak@example.com" not in flat
    assert "customer_email" not in minimal["data"]["object"]
    assert "customer_details" not in minimal["data"]["object"]
    assert "payment_method_details" not in minimal["data"]["object"]
    assert "shipping" not in minimal["data"]["object"]
    # Keepers
    assert minimal["id"] == "evt_x"
    assert minimal["data"]["object"]["id"] == "cs_x"
    assert minimal["data"]["object"]["amount_total"] == 4900
    assert minimal["data"]["object"]["line_items"][0]["price"]["id"] == "price_x"


@pytest.mark.asyncio
async def test_session_id_regex_rejects_garbage(client, fake_stripe) -> None:
    """/session-status with bad sid → 404; /success with bad sid → failed HTML."""
    resp = await client.get(
        "/api/billing/session-status",
        params={"session_id": "garbage", "t": "anything"},
    )
    assert resp.status_code == 404, resp.text

    resp2 = await client.get("/api/billing/success", params={"session_id": "garbage"})
    assert resp2.status_code == 200, resp2.text
    # Failed-state element should be active in the HTML.
    assert 'id="state-failed" class="active"' in resp2.text or "state-failed" in resp2.text
    # And the JS must NOT have garbage as a literal session id.
    assert "SESSION_ID_VALID = false" in resp2.text


@pytest.mark.asyncio
async def test_email_is_hashed_in_success_logs(
    client, fake_stripe, monkeypatch: pytest.MonkeyPatch, caplog,
) -> None:
    """INFO log on /session-status success uses email_hash, not raw email."""
    import logging
    sid = _VALID_SID_READY
    token = _install_reveal_token(sid)

    fake_stripe.checkout.sessions.retrieve_response = SimpleNamespace(
        status="complete",
        payment_status="paid",
        customer_details={"email": "hashme@example.com"},
        customer_email="hashme@example.com",
    )
    import api.billing as api_billing

    fake_license = SimpleNamespace(
        org_id="o", api_key="k", plan="xarex_pro",
        download_token="d", status="active",
    )

    async def _ready(*, db, email):  # noqa: ANN001
        return fake_license

    monkeypatch.setattr(api_billing, "get_license_by_email", _ready)

    with caplog.at_level(logging.INFO):
        resp = await client.get(
            "/api/billing/session-status",
            params={"session_id": sid, "t": token},
        )
        assert resp.status_code == 200, resp.text

    full = "\n".join(rec.getMessage() + " " + repr(getattr(rec, "__dict__", {})) for rec in caplog.records)
    # Plaintext local-part must not appear on the INFO success path.
    assert "hashme@example.com" not in full


@pytest.mark.asyncio
async def test_starter_to_pro_upgrade_updates_plan_and_amount(
    monkeypatch: pytest.MonkeyPatch, fake_db,
) -> None:
    """Provision Starter then Pro on the same email → plan + amount overwrite (H-9)."""
    import services.billing as svc_billing

    # Build an in-memory store that fake_db.execute resolves against.
    # We stub provision_license's internal selects by patching db.execute to
    # return objects from a tiny dict.
    state: dict = {"customer": None, "subscription": None, "license": None, "org": None}

    class _Result:
        def __init__(self, obj):
            self._obj = obj
        def scalar_one_or_none(self):
            return self._obj

    async def _execute(*args, **kwargs):
        # Inspect the SQL select target to decide which entity to return.
        stmt = args[0] if args else None
        text = str(stmt)
        if "FROM customers" in text:
            return _Result(state["customer"])
        if "FROM subscriptions" in text:
            return _Result(state["subscription"])
        if "FROM licenses" in text:
            return _Result(state["license"])
        if "FROM orgs" in text:
            return _Result(state["org"])
        return _Result(None)

    async def _flush():
        # Mimic server defaults on first insert.
        for key in ("customer", "subscription", "license", "org"):
            if state[key] is None:
                continue
            if getattr(state[key], "id", None) in (None, ""):
                state[key].id = "id_" + key

    captured_add: list = []
    def _add(row):
        captured_add.append(row)
        # Persist into the state dict by detecting the type.
        cls = row.__class__.__name__
        if cls == "Customer":
            state["customer"] = row
            if row.id is None:
                row.id = "cust_1"
        elif cls == "Subscription":
            state["subscription"] = row
            if row.id is None:
                row.id = "sub_1"
        elif cls == "License":
            state["license"] = row
            if row.id is None:
                row.id = "lic_1"
        elif cls == "Org":
            state["org"] = row

    async def _commit():
        pass

    fake_db.execute = _execute
    fake_db.flush = _flush
    fake_db.commit = _commit
    fake_db.add = _add

    async def _no_email(**kwargs):
        return True

    monkeypatch.setattr(svc_billing, "send_welcome_email", _no_email)
    monkeypatch.setattr(svc_billing, "send_upgrade_email", _no_email)

    # First: Starter
    await svc_billing.provision_license(
        db=fake_db, email="ladder@example.com", name="L",
        provider="stripe", provider_sub_id="sub1",
        provider_customer_id="cus1", amount=1900, currency="usd",
        plan="xarex_starter",
    )
    assert state["license"].plan == "xarex_starter"
    assert state["subscription"].plan == "xarex_starter"
    assert state["subscription"].amount == 1900

    # Then: Pro upgrade — same customer
    await svc_billing.provision_license(
        db=fake_db, email="ladder@example.com", name="L",
        provider="stripe", provider_sub_id="sub2",
        provider_customer_id="cus1", amount=4900, currency="usd",
        plan="xarex_pro",
    )
    assert state["license"].plan == "xarex_pro", "License plan must reflect the upgrade"
    assert state["subscription"].plan == "xarex_pro"
    assert state["subscription"].amount == 4900
    # The Org row must exist so the customer's api_key actually authenticates.
    assert state["org"] is not None, "provision_license must create an Org row"
    assert state["org"].id == state["license"].org_id
    assert state["org"].api_key == state["license"].api_key
    assert state["license"].org_id[:8] in state["org"].name


# ─────────────────────────────────────────────────────────────────────────────
# POST /signup/free — regression: must keep working
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_free_signup_regression(client, monkeypatch: pytest.MonkeyPatch) -> None:
    """Free signup still provisions a license without touching Stripe."""
    import api.billing as api_billing

    async def _fake_provision(*, db, email, name):  # noqa: ANN001
        return SimpleNamespace(
            org_id="free-org-uuid",
            api_key="xrx_free_key",
            download_token="tok_free",
            scan_limit=2,
        )

    monkeypatch.setattr(api_billing, "provision_free_license", _fake_provision)
    # FREE_PLAN_ENABLED defaults to True; we set it again here to be explicit
    # and to demonstrate the per-instance setattr path works for known fields.
    monkeypatch.setattr(api_billing.settings, "FREE_PLAN_ENABLED", True)

    resp = await client.post(
        "/api/billing/signup/free",
        json={"email": "freebie@example.com", "name": "Freebie"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body == {
        "org_id": "free-org-uuid",
        "api_key": "xrx_free_key",
        "download_token": "tok_free",
        "scan_limit": 2,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Settings.stripe_price_id — direct unit tests
# ─────────────────────────────────────────────────────────────────────────────

def test_settings_stripe_price_id_unknown_tier_raises() -> None:
    from config import settings as cfg
    with pytest.raises(ValueError, match="tier"):
        cfg.stripe_price_id("enterprise", "monthly")


def test_settings_stripe_price_id_unknown_cadence_raises() -> None:
    from config import settings as cfg
    with pytest.raises(ValueError, match="cadence"):
        cfg.stripe_price_id("pro", "weekly")


def test_settings_stripe_price_id_returns_none_when_unconfigured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Default state in tests: env vars empty → helper returns None."""
    from config import settings as cfg
    monkeypatch.setattr(cfg, "STRIPE_PRICE_PRO_MONTHLY", "")
    assert cfg.stripe_price_id("pro", "monthly") is None


def test_settings_stripe_price_id_returns_configured_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from config import settings as cfg
    monkeypatch.setattr(cfg, "STRIPE_PRICE_STARTER_ANNUAL", "price_xyz")
    assert cfg.stripe_price_id("starter", "annual") == "price_xyz"


# ─────────────────────────────────────────────────────────────────────────────
# Issue 1: timing-oracle removal on /session-status
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_session_status_no_timing_oracle(
    client, fake_stripe, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both "no stored token" and "stored token but wrong t" run the same
    downstream code path (no fast-path peek). We assert by mocking
    `cached_stripe_session_retrieve` and confirming it is called on both
    branches — that's the canary that proves both requests share path-length
    rather than one short-circuiting before the Stripe call."""
    import api.billing as api_billing

    sid_a = "cs_test_" + "NoStoredTokenAtAll1234567890"  # no install
    sid_b = "cs_test_" + "StoredTokenWrongInputTTTTTT2"
    _install_reveal_token(sid_b)  # ignore real token; client will pass garbage

    fake_stripe.checkout.sessions.retrieve_response = SimpleNamespace(
        status="complete",
        payment_status="paid",
        customer_details={"email": "x@example.com"},
        customer_email="x@example.com",
    )

    calls: list[str] = []

    def _spy_retrieve(session_id: str):
        calls.append(session_id)
        return fake_stripe.checkout.sessions.retrieve_response

    monkeypatch.setattr(api_billing, "cached_stripe_session_retrieve", _spy_retrieve)

    # No license either way — keeps the path uniform up to the consume step.
    async def _no_license(*, db, email):  # noqa: ANN001
        return None

    monkeypatch.setattr(api_billing, "get_license_by_email", _no_license)

    # Branch 1: regex-valid sid that was NEVER stored, with some token value
    r1 = await client.get(
        "/api/billing/session-status",
        params={"session_id": sid_a, "t": "anything"},
    )
    # Branch 2: regex-valid sid that IS stored, but with a wrong t
    r2 = await client.get(
        "/api/billing/session-status",
        params={"session_id": sid_b, "t": "definitely_not_the_real_token"},
    )

    # Both should hit Stripe retrieve (no fast-path peek short-circuit).
    assert sid_a in calls, "Branch 1 must reach Stripe retrieve (no peek shortcut)"
    assert sid_b in calls, "Branch 2 must reach Stripe retrieve (no peek shortcut)"
    # Both end as pending (no license) — neither leaks data, neither 404s
    # before the Stripe call. (When a license DOES exist, the consume step
    # decides 200 vs 404; that's covered by other tests in this module.)
    assert r1.status_code == 200
    assert r1.json()["status"] == "pending"
    assert r2.status_code == 200
    assert r2.json()["status"] == "pending"


# ─────────────────────────────────────────────────────────────────────────────
# Issue 2: /subscription must not leak credentials
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_subscription_endpoint_does_not_leak_credentials(
    client, fake_db, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A live license exists for the email — endpoint must return safe fields
    only (plan, status, etc.) and MUST NOT include api_key / download_token /
    org_id. (Issue 2: api-security-reviewer SHIP-WITH-CHANGES)"""
    import api.billing as api_billing

    fake_license = SimpleNamespace(
        org_id="secret-org-id",
        api_key="xrx_super_secret_key",
        download_token="tok_super_secret",
        status="active",
        plan="xarex_pro",
        customer_id="cust_1",
        scan_count=3,
        scan_limit=None,
    )
    fake_sub = SimpleNamespace(status="active", current_period_end=None)

    async def _has_license(*, db, email):  # noqa: ANN001
        return fake_license

    monkeypatch.setattr(api_billing, "get_license_by_email", _has_license)

    class _Result:
        def __init__(self, obj):
            self._obj = obj
        def scalar_one_or_none(self):
            return self._obj

    async def _execute(*args, **kwargs):
        return _Result(fake_sub)

    fake_db.execute = _execute

    resp = await client.get(
        "/api/billing/subscription",
        params={"email": "leak-probe@example.com"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()

    # Credentials MUST NOT appear in the response (defence-in-depth: check
    # both the key and the value, since pydantic may serialize None fields).
    assert "api_key" not in body, body
    assert "download_token" not in body, body
    assert "org_id" not in body, body
    flat = repr(body)
    assert "xrx_super_secret_key" not in flat
    assert "tok_super_secret" not in flat
    assert "secret-org-id" not in flat

    # Safe fields ARE present.
    assert body["email"] == "leak-probe@example.com"
    assert body["has_license"] is True
    assert body["plan"] == "xarex_pro"
    assert body["status"] in ("active", "trialing")
    assert body["support_contact"] == "support@xarexsec.io"


@pytest.mark.asyncio
async def test_subscription_endpoint_returns_safe_shape_for_unknown_email(
    client, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unknown email → has_license=False, no error leak, no credential keys."""
    import api.billing as api_billing

    async def _none(*, db, email):  # noqa: ANN001
        return None

    monkeypatch.setattr(api_billing, "get_license_by_email", _none)

    resp = await client.get(
        "/api/billing/subscription",
        params={"email": "nobody@example.com"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["has_license"] is False
    assert body["email"] == "nobody@example.com"
    assert "api_key" not in body
    assert "download_token" not in body
    assert "org_id" not in body
