"""Authentication dependencies for the Xarex Cloud Brain API."""
from __future__ import annotations

import time
from typing import Any

from fastapi import Depends, HTTPException, Query, Security, status
from fastapi.security import APIKeyHeader
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from models.database import get_db
from models.tables import Org

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
_admin_secret_header = APIKeyHeader(name="X-Admin-Secret", auto_error=False)

# ---------------------------------------------------------------------------
# In-process org cache — eliminates a DB round-trip on every request.
# TTL of 60 s is fine; org records almost never change mid-session.
# ---------------------------------------------------------------------------
_ORG_CACHE: dict[str, tuple[Any, float]] = {}   # api_key → (Org, expires_at)
_CACHE_TTL = 60.0                                # seconds


def _cache_get(api_key: str):
    entry = _ORG_CACHE.get(api_key)
    if entry and time.monotonic() < entry[1]:
        return entry[0]
    _ORG_CACHE.pop(api_key, None)
    return None


def _cache_set(api_key: str, org) -> None:
    _ORG_CACHE[api_key] = (org, time.monotonic() + _CACHE_TTL)
    # Evict stale entries whenever the cache grows large
    if len(_ORG_CACHE) > 500:
        now = time.monotonic()
        stale = [k for k, v in _ORG_CACHE.items() if v[1] < now]
        for k in stale:
            _ORG_CACHE.pop(k, None)


# ---------------------------------------------------------------------------
# Org auth
# ---------------------------------------------------------------------------

async def get_org(
    api_key_header: str | None = Security(_api_key_header),
    api_key_query: str | None = Query(None, alias="api_key"),
    db: AsyncSession = Depends(get_db),
) -> Org:
    api_key = api_key_header or api_key_query
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    org = _cache_get(api_key)
    if org is None:
        result = await db.execute(select(Org).where(Org.api_key == api_key))
        org = result.scalar_one_or_none()
        if org is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key",
                headers={"WWW-Authenticate": "ApiKey"},
            )
        _cache_set(api_key, org)

    return org


# ---------------------------------------------------------------------------
# Admin auth
# ---------------------------------------------------------------------------

async def get_admin(
    secret: str | None = Security(_admin_secret_header),
) -> str:
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-Admin-Secret header",
        )
    if secret != settings.ADMIN_SECRET:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid admin secret",
        )
    return secret
