"""WebSocket connection manager for real-time scan event streaming."""
from __future__ import annotations

import asyncio
import json
from collections import defaultdict, deque
from typing import Any

import structlog
from fastapi import WebSocket

logger = structlog.get_logger(__name__)

# Max events buffered per scan so late-joining clients catch up on the full history.
_BUFFER_SIZE = 500


class WebSocketManager:
    """Manages WebSocket connections grouped by scan_id."""

    def __init__(self) -> None:
        # scan_id → set of active WebSocket connections
        self._connections: dict[str, set[WebSocket]] = defaultdict(set)
        # scan_id → ordered replay buffer (capped at _BUFFER_SIZE)
        self._buffers: dict[str, deque] = defaultdict(lambda: deque(maxlen=_BUFFER_SIZE))
        self._lock = asyncio.Lock()
        # Main FastAPI event loop — set at startup so gRPC thread can post events
        self._main_loop: asyncio.AbstractEventLoop | None = None

    def set_main_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Call once at app startup to store the FastAPI event loop."""
        self._main_loop = loop

    def broadcast_from_thread(self, scan_id: str, event: dict[str, Any]) -> None:
        """Thread-safe broadcast — call this from the gRPC background thread."""
        if self._main_loop is None or self._main_loop.is_closed():
            return
        asyncio.run_coroutine_threadsafe(self.broadcast(scan_id, event), self._main_loop)

    async def connect(self, scan_id: str, websocket: WebSocket) -> None:
        """Accept, register, and replay buffered events to a new WebSocket client."""
        await websocket.accept()
        async with self._lock:
            self._connections[scan_id].add(websocket)
            buffered = list(self._buffers.get(scan_id, []))

        # Replay all buffered events so late-joining clients see the full history.
        for event in buffered:
            try:
                await websocket.send_text(json.dumps(event))
            except Exception:
                break

        logger.info(
            "WebSocket connected",
            scan_id=scan_id,
            replayed=len(buffered),
            total=len(self._connections[scan_id]),
        )

    async def disconnect(self, scan_id: str, websocket: WebSocket) -> None:
        """Remove a WebSocket connection."""
        async with self._lock:
            self._connections[scan_id].discard(websocket)
            if not self._connections[scan_id]:
                del self._connections[scan_id]
        logger.info("WebSocket disconnected", scan_id=scan_id)

    async def broadcast(self, scan_id: str, event: dict[str, Any]) -> None:
        """
        Buffer the event then send to all WebSocket listeners for scan_id.

        Dead connections are silently removed.
        """
        # Always buffer so late-joining clients replay the full scan history.
        async with self._lock:
            self._buffers[scan_id].append(event)
            connections = set(self._connections.get(scan_id, set()))

        payload = json.dumps(event)
        dead: list[WebSocket] = []

        for ws in connections:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)

        if dead:
            async with self._lock:
                for ws in dead:
                    self._connections[scan_id].discard(ws)
            logger.warning(
                "Removed dead WebSocket connections",
                scan_id=scan_id,
                count=len(dead),
            )

    def connection_count(self, scan_id: str) -> int:
        """Return the number of active connections for a scan."""
        return len(self._connections.get(scan_id, set()))


# Module-level singleton used across the app
ws_manager = WebSocketManager()
