"""Pytest configuration for cloud-brain tests.

Strategy
--------
Unit tests for `api/leads.py` use an in-memory fake `AsyncSession` instead of
aiosqlite. SQLite has poor compatibility with the Postgres-specific column
types used in `models/tables.py` (`UUID(as_uuid=False)`, `JSON` from
`sqlalchemy.dialects.postgresql`, tz-aware `DateTime`), so a fake session
keeps these tests focused on endpoint logic and avoids dialect drift.

Full integration tests against real Postgres should run inside Docker as part
of Step 6's end-to-end suite; those will exercise the real ORM path.

Conventions
-----------
- `client` fixture: returns an `httpx.AsyncClient` wired to the FastAPI app
  via `ASGITransport` (in-process, no real network).
- `fake_db` fixture: returns the `_FakeSession` instance used by the request
  so tests can assert on `.added_rows`.
- `reset_rate_limiter` autouse fixture: clears the in-process leads rate
  limiter between tests so one test's submissions don't affect the next.

Environment overrides applied before app import
-----------------------------------------------
- DATABASE_URL is replaced with a sqlite URL so `create_async_engine` in
  `models/database.py` doesn't try to connect to Postgres at import time.
  The fake session replaces `get_db` so no real query ever runs.
"""
from __future__ import annotations

import os
import sys
import uuid
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── Path + env setup MUST run before importing the app ──────────────────────
# Make `cloud-brain/` importable as the root.
_CB_ROOT = Path(__file__).resolve().parent.parent
if str(_CB_ROOT) not in sys.path:
    sys.path.insert(0, str(_CB_ROOT))

# `models.database` builds an async engine eagerly at import time using pool
# kwargs that are PostgreSQL/asyncpg-specific. We can't use sqlite here
# (rejected pool kwargs); instead we point at a Postgres-shaped URL on an
# unreachable port. `create_async_engine` does NOT connect until a query
# runs, and we override `get_db` per-test so no query ever runs against it.
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@127.0.0.1:65535/test")
os.environ.setdefault("SECRET_KEY", "test-secret-do-not-use-in-prod")
os.environ.setdefault("ADMIN_SECRET", "test-admin-secret")
# Pin to dev defaults so the suite is hermetic.
os.environ.setdefault("TURNSTILE_SECRET_KEY", "")
os.environ.setdefault("CORS_ORIGINS", "http://testserver")

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient


# ─────────────────────────────────────────────────────────────────────────────
# Fake AsyncSession
# ─────────────────────────────────────────────────────────────────────────────

class _FakeSession:
    """Just enough of AsyncSession for api/leads.py to function.

    Behavior toggles via attributes:
      - `raise_on_flush=True`: `flush()` raises SQLAlchemyError, simulating
        a transient DB failure (503 path).
      - `raise_on_execute=False`: `execute()` (used by the honeypot's
        SELECT 1) is silently swallowed by the endpoint, so toggling this
        on shouldn't change observable behavior — but we expose it for
        completeness.

    Recorded state:
      - `added_rows`: list of every object passed to `add()`.
      - `executed`: list of SQL statements passed to `execute()`.
    """

    def __init__(self) -> None:
        self.added_rows: list[Any] = []
        self.executed: list[Any] = []
        self.raise_on_flush = False
        self.raise_on_execute = False

    def add(self, row: Any) -> None:
        self.added_rows.append(row)

    async def flush(self) -> None:
        if self.raise_on_flush:
            from sqlalchemy.exc import SQLAlchemyError
            raise SQLAlchemyError("simulated flush failure")

    async def refresh(self, row: Any) -> None:
        # The endpoint relies on `id` and `created_at` being populated after
        # refresh. In the real path these come from server defaults; here we
        # populate them ourselves to match the contract.
        if getattr(row, "id", None) in (None, ""):
            row.id = str(uuid.uuid4())
        if getattr(row, "created_at", None) is None:
            row.created_at = datetime.now(timezone.utc)

    async def execute(self, *_args, **_kwargs) -> None:
        if self.raise_on_execute:
            from sqlalchemy.exc import SQLAlchemyError
            raise SQLAlchemyError("simulated execute failure")
        self.executed.append(_args)

    async def commit(self) -> None:
        pass

    async def rollback(self) -> None:
        pass

    async def close(self) -> None:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def fake_db() -> _FakeSession:
    """The fake session that backs each test request."""
    return _FakeSession()


@pytest_asyncio.fixture
async def client(fake_db: _FakeSession) -> AsyncIterator[AsyncClient]:
    """FastAPI test client wired to a fresh fake session per test.

    We import the app lazily so the DATABASE_URL override above takes effect
    before `models.database.engine` is constructed.
    """
    from main import app
    from models.database import get_db

    async def _override_get_db() -> AsyncIterator[_FakeSession]:
        yield fake_db

    app.dependency_overrides[get_db] = _override_get_db
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
            yield ac
    finally:
        app.dependency_overrides.pop(get_db, None)


@pytest.fixture(autouse=True)
def reset_rate_limiter() -> None:
    """Reset slowapi's per-route counters so quotas don't bleed across tests."""
    try:
        from limiter import limiter
        # slowapi stores state in `limiter._storage` (a MovingWindowStorage by
        # default). `reset()` clears the in-memory dict. For Redis-backed
        # storage (production), this fixture is a no-op — tests should run
        # against the in-memory backend.
        if hasattr(limiter, "reset"):
            limiter.reset()
        elif hasattr(limiter, "_storage") and hasattr(limiter._storage, "storage"):
            limiter._storage.storage.clear()  # type: ignore[attr-defined]
    except Exception:  # pragma: no cover — defensive
        pass
