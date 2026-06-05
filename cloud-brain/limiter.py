"""Process-wide rate limiter for the Cloud Brain API.

We centralise the `slowapi.Limiter` here (rather than in `main.py`) so that
routers in `api/*.py` can import the limiter to decorate their endpoints
without creating a circular dependency on `main.py`.

Backend
-------
Default storage is in-process memory — fine for a single uvicorn worker,
but does NOT share state across workers or instances. Production should
set `RATE_LIMIT_STORAGE_URI` in env to a Redis URL (e.g.
`redis://localhost:6379/0`); slowapi will pick it up automatically.

Key function
------------
We honour `X-Forwarded-For` (first hop) so the limit applies to the real
client IP when the app is behind nginx / a CDN. The deployment is
responsible for ensuring that XFF is set by a trusted proxy and not by
the client — see `cloud-brain/api/leads.py` security follow-ups.
"""
from __future__ import annotations

import os

from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address


def _xff_aware_key(request: Request) -> str:
    """Return the first IP in X-Forwarded-For, else the socket peer.

    Mirrors the logic in `api/leads.py::_extract_ip` so the rate limit
    keys off the same identifier we eventually store on the row.
    """
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        first = xff.split(",", 1)[0].strip()
        if first:
            return first
    return get_remote_address(request)


# Optional Redis backend, controlled via env. Empty / unset = in-memory.
_STORAGE_URI = os.environ.get("RATE_LIMIT_STORAGE_URI", "").strip() or None

limiter = Limiter(
    key_func=_xff_aware_key,
    storage_uri=_STORAGE_URI,
    # Default to no global limit; each route opts in via @limiter.limit(...).
    default_limits=[],
    # Empty string disables slowapi's .env auto-load — pydantic-settings is
    # already the single source of truth for env vars, and slowapi's starlette
    # Config reads files with the default OS codec, which breaks on Windows
    # when the .env contains UTF-8 bytes (e.g. arrow glyphs in comments).
    config_filename="",
)
