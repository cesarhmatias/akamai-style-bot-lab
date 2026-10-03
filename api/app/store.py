"""SessionStore implementations: Redis (production) and in-memory (tests / fallback)."""

from __future__ import annotations

import json
import os
import time
from typing import Any

from .contract import SessionStore


class MemoryStore:
    """In-process KV with per-key TTLs (monotonic clock)."""

    def __init__(self) -> None:
        self._data: dict[str, tuple[str, float | None]] = {}

    def _live(self, key: str) -> str | None:
        item = self._data.get(key)
        if item is None:
            return None
        value, exp = item
        if exp is not None and exp <= time.monotonic():
            del self._data[key]
            return None
        return value

    @staticmethod
    def _exp(ttl: int | None) -> float | None:
        return time.monotonic() + ttl if ttl else None

    async def get(self, key: str) -> str | None:
        return self._live(key)

    async def set(self, key: str, value: str, ttl: int | None = None) -> None:
        self._data[key] = (value, self._exp(ttl))

    async def incr(self, key: str, ttl: int | None = None) -> int:
        cur = self._live(key)
        new = int(cur) + 1 if cur is not None else 1
        exp = self._data[key][1] if cur is not None else self._exp(ttl)
        self._data[key] = (str(new), exp)
        return new

    async def delete(self, key: str) -> None:
        self._data.pop(key, None)

    async def clear(self) -> None:
        self._data.clear()


class RedisStore:
    """Redis-backed store (redis.asyncio)."""

    def __init__(self, url: str) -> None:
        import redis.asyncio as aioredis

        self._r: Any = aioredis.from_url(url, decode_responses=True)

    async def get(self, key: str) -> str | None:
        value = await self._r.get(key)
        return None if value is None else str(value)

    async def set(self, key: str, value: str, ttl: int | None = None) -> None:
        await self._r.set(key, value, ex=ttl or None)

    async def incr(self, key: str, ttl: int | None = None) -> int:
        n = int(await self._r.incr(key))
        if n == 1 and ttl:
            await self._r.expire(key, ttl)
        return n

    async def delete(self, key: str) -> None:
        await self._r.delete(key)

    async def clear(self) -> None:
        await self._r.flushdb()

    async def close(self) -> None:
        await self._r.aclose()


def make_store() -> SessionStore:
    """RedisStore if REDIS_URL is set, else MemoryStore."""
    url = os.environ.get("REDIS_URL")
    return RedisStore(url) if url else MemoryStore()


# --- sliding-window helpers (built on the minimal SessionStore protocol) -----------------
# Event timestamps live as a JSON list under one key. The read-modify-write is not atomic
# across processes; that is fine for the lab's per-session counters (one client at a time).


async def window_events(
    store: SessionStore, key: str, window: float, now: float | None = None
) -> list[float]:
    """Timestamps recorded under ``key`` that are still inside the last ``window`` seconds."""
    now = time.time() if now is None else now
    raw = await store.get(key)
    if not raw:
        return []
    try:
        stamps = [float(t) for t in json.loads(raw)]
    except (ValueError, TypeError):
        return []
    return [t for t in stamps if now - t < window]


async def window_add(store: SessionStore, key: str, window: float, now: float | None = None) -> int:
    """Record one event now; return how many events (including this one) are in the window."""
    now = time.time() if now is None else now
    stamps = await window_events(store, key, window, now)
    stamps.append(now)
    await store.set(key, json.dumps(stamps), ttl=max(1, int(window) + 1))
    return len(stamps)


async def window_count(
    store: SessionStore, key: str, window: float, now: float | None = None
) -> int:
    """Events inside the window, without recording one."""
    return len(await window_events(store, key, window, now))
