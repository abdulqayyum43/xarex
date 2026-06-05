"""Unit tests for POST /api/v1/leads.

Covers:
  - Happy path (201, row persisted, response shape correct)
  - Honeypot (201 fake-success, no row written, db.execute called for timing parity)
  - Validation: missing email, malformed email, oversized email, oversized name,
    invalid `size` bucket, extra unknown field
  - Persistence failure → 503 with neutral detail (no schema leak)
  - Rate limit: 6th submission from same simulated IP within window → 429
  - IP extraction: X-Forwarded-For wins over request.client.host
  - PII hygiene: response payload contains only id/email/created_at (no IP/UA)

These tests use the in-memory fake AsyncSession from conftest.py — they
exercise the endpoint's logic, not the real ORM/SQL path. Postgres-backed
integration tests run separately under Docker.
"""
from __future__ import annotations

from typing import Any

import pytest

# httpx AsyncClient is supplied by the `client` fixture (see conftest.py).


# ─────────────────────────────────────────────────────────────────────────────
# Happy path
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_lead_happy_path(client, fake_db) -> None:
    payload = {
        "email": "alice@example.com",
        "name": "Alice",
        "company": "Acme Corp",
        "size": "11–50",
        "source": "sample-report-gate",
    }
    resp = await client.post("/api/v1/leads", json=payload)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert set(body.keys()) == {"id", "email", "created_at"}, body
    assert body["email"] == "alice@example.com"
    # PII fields must NOT be echoed in the response.
    assert "ip_address" not in body
    assert "user_agent" not in body
    # The fake session should have one row added with the expected fields.
    assert len(fake_db.added_rows) == 1
    row = fake_db.added_rows[0]
    assert row.email == "alice@example.com"
    assert row.name == "Alice"
    assert row.company == "Acme Corp"
    assert row.size == "11–50"
    assert row.source == "sample-report-gate"


@pytest.mark.asyncio
async def test_optional_fields_default_to_none(client, fake_db) -> None:
    """Submitting only `email` should succeed; optional fields default to None."""
    resp = await client.post("/api/v1/leads", json={"email": "minimal@example.com"})
    assert resp.status_code == 201, resp.text
    row = fake_db.added_rows[0]
    assert row.name is None
    assert row.company is None
    assert row.size is None
    assert row.message is None
    # source falls back to its default.
    assert row.source == "sample-report-gate"


@pytest.mark.asyncio
async def test_whitespace_optional_strings_become_none(client, fake_db) -> None:
    """Empty / whitespace-only optional strings should be stored as None."""
    resp = await client.post(
        "/api/v1/leads",
        json={"email": "ws@example.com", "name": "   ", "company": ""},
    )
    assert resp.status_code == 201, resp.text
    row = fake_db.added_rows[0]
    assert row.name is None
    assert row.company is None


# ─────────────────────────────────────────────────────────────────────────────
# Honeypot
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_honeypot_returns_fake_success_and_skips_persistence(client, fake_db) -> None:
    resp = await client.post(
        "/api/v1/leads",
        json={"email": "bot@example.com", "website": "http://spam.example"},
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["email"] == "bot@example.com"
    # The id should be a UUID-looking string but no row was added.
    assert len(fake_db.added_rows) == 0
    # The endpoint runs a SELECT 1 round-trip to match real-path timing.
    assert len(fake_db.executed) == 1


@pytest.mark.asyncio
async def test_honeypot_whitespace_is_not_triggered(client, fake_db) -> None:
    """A whitespace-only `website` value should NOT trip the honeypot."""
    resp = await client.post(
        "/api/v1/leads",
        json={"email": "real@example.com", "website": "   "},
    )
    assert resp.status_code == 201, resp.text
    assert len(fake_db.added_rows) == 1


# ─────────────────────────────────────────────────────────────────────────────
# Validation
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_missing_email_returns_422(client) -> None:
    resp = await client.post("/api/v1/leads", json={"name": "Eve"})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_malformed_email_returns_422(client) -> None:
    resp = await client.post("/api/v1/leads", json={"email": "not-an-email"})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_oversized_email_returns_422(client) -> None:
    # Local part + @ + domain just over 320 chars; Pydantic EmailStr will
    # also reject malformed structures, but we want the LENGTH cap to fire.
    long_local = "a" * 310
    resp = await client.post(
        "/api/v1/leads",
        json={"email": f"{long_local}@example.com"},  # > 320 chars total
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_oversized_name_returns_422(client) -> None:
    resp = await client.post(
        "/api/v1/leads",
        json={"email": "ok@example.com", "name": "x" * 201},  # > 200 cap
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_invalid_size_bucket_returns_422(client) -> None:
    resp = await client.post(
        "/api/v1/leads",
        json={"email": "ok@example.com", "size": "5"},  # not in allowed set
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_extra_unknown_field_returns_422(client) -> None:
    """`extra='forbid'` should reject undeclared fields."""
    resp = await client.post(
        "/api/v1/leads",
        json={"email": "ok@example.com", "secret_admin": True},
    )
    assert resp.status_code == 422


# ─────────────────────────────────────────────────────────────────────────────
# Persistence failure
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_db_error_returns_503_neutral_detail(client, fake_db) -> None:
    fake_db.raise_on_flush = True
    resp = await client.post(
        "/api/v1/leads",
        json={"email": "alice@example.com"},
    )
    assert resp.status_code == 503
    detail = resp.json()["detail"]
    # The client message must NOT leak the underlying exception.
    assert "simulated" not in detail.lower()
    assert "sqlalchemy" not in detail.lower()
    assert "retry" in detail.lower()


# ─────────────────────────────────────────────────────────────────────────────
# Rate limit
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_rate_limit_returns_429_after_quota(client) -> None:
    """5 submissions per IP per 60s; the 6th must 429.

    httpx's ASGI transport defaults to `request.client.host = "127.0.0.1"`,
    so every request in this test shares the same simulated IP.
    """
    for i in range(5):
        resp = await client.post(
            "/api/v1/leads",
            json={"email": f"user{i}@example.com"},
        )
        assert resp.status_code == 201, f"submission {i} failed: {resp.text}"
    resp = await client.post(
        "/api/v1/leads",
        json={"email": "user6@example.com"},
    )
    assert resp.status_code == 429
    # slowapi uses its own response shape (`error`), not FastAPI's `detail`.
    body = resp.json()
    msg = (body.get("error") or body.get("detail") or "").lower()
    assert "rate" in msg or "exceed" in msg or "limit" in msg, body


# ─────────────────────────────────────────────────────────────────────────────
# IP extraction
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_xff_header_wins_over_client_host(client, fake_db) -> None:
    """When `X-Forwarded-For` is set, the first IP in the chain wins."""
    resp = await client.post(
        "/api/v1/leads",
        json={"email": "xff@example.com"},
        headers={"X-Forwarded-For": "198.51.100.42, 10.0.0.1"},
    )
    assert resp.status_code == 201, resp.text
    row = fake_db.added_rows[0]
    assert row.ip_address == "198.51.100.42"


@pytest.mark.asyncio
async def test_user_agent_captured_and_truncated(client, fake_db) -> None:
    long_ua = "A" * 1000  # > 500 cap
    resp = await client.post(
        "/api/v1/leads",
        json={"email": "ua@example.com"},
        headers={"User-Agent": long_ua},
    )
    assert resp.status_code == 201, resp.text
    row = fake_db.added_rows[0]
    assert row.user_agent is not None
    assert len(row.user_agent) == 500


# ─────────────────────────────────────────────────────────────────────────────
# Turnstile (env-gated)
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_turnstile_disabled_accepts_no_token(client) -> None:
    """With no TURNSTILE_SECRET_KEY set, the endpoint accepts submissions
    that lack a `turnstile_token` field. This is the default dev posture."""
    resp = await client.post(
        "/api/v1/leads",
        json={"email": "noturn@example.com"},
    )
    assert resp.status_code == 201, resp.text


@pytest.mark.asyncio
async def test_turnstile_required_rejects_missing_token(client, monkeypatch) -> None:
    """When a secret is configured but the client omits the token, return 400."""
    from services import turnstile as ts_mod

    async def _fake_enabled() -> bool:
        return True

    async def _fake_verify(token, remote_ip=None):
        # Real implementation would call Cloudflare; under test we don't.
        return False  # missing/invalid token → False

    monkeypatch.setattr(ts_mod, "turnstile_enabled", _fake_enabled)
    monkeypatch.setattr(ts_mod, "verify_turnstile_token", _fake_verify)
    # Also patch the names re-exported into api.leads at import time.
    from api import leads as leads_mod
    monkeypatch.setattr(leads_mod, "turnstile_enabled", _fake_enabled)
    monkeypatch.setattr(leads_mod, "verify_turnstile_token", _fake_verify)

    resp = await client.post(
        "/api/v1/leads",
        json={"email": "needstoken@example.com"},
    )
    assert resp.status_code == 400
    assert "verify" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_turnstile_required_accepts_valid_token(client, fake_db, monkeypatch) -> None:
    """When the verifier returns True, the submission proceeds normally."""
    from api import leads as leads_mod
    from services import turnstile as ts_mod

    async def _fake_enabled() -> bool:
        return True

    async def _fake_verify(token, remote_ip=None):
        return token == "good-token"

    monkeypatch.setattr(ts_mod, "turnstile_enabled", _fake_enabled)
    monkeypatch.setattr(ts_mod, "verify_turnstile_token", _fake_verify)
    monkeypatch.setattr(leads_mod, "turnstile_enabled", _fake_enabled)
    monkeypatch.setattr(leads_mod, "verify_turnstile_token", _fake_verify)

    resp = await client.post(
        "/api/v1/leads",
        json={"email": "ok@example.com", "turnstile_token": "good-token"},
    )
    assert resp.status_code == 201, resp.text
    assert len(fake_db.added_rows) == 1
