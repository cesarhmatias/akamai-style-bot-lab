"""Shared fixtures. Module agents: reuse `make_ctx` and `memory_store`."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from typing import Any

import httpx
import pytest
import pytest_asyncio
from app.contract import RequestContext
from app.store import MemoryStore

DEFAULT_HEADERS = [
    ("host", "localhost"),
    (
        "user-agent",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    ),
    ("accept", "text/html,application/xhtml+xml,*/*;q=0.8"),
    ("accept-language", "en-US,en;q=0.9"),
    ("accept-encoding", "gzip, deflate, br"),
]


@pytest.fixture
def memory_store() -> MemoryStore:
    return MemoryStore()


@pytest.fixture
def make_ctx(memory_store: MemoryStore) -> Callable[..., RequestContext]:
    """Factory: ``make_ctx(**overrides) -> RequestContext`` bound to `memory_store`."""

    def factory(**overrides: Any) -> RequestContext:
        headers = overrides.pop("headers", None) or list(DEFAULT_HEADERS)
        ua = overrides.pop("user_agent", None)
        if ua is None:
            ua = next((v for k, v in headers if k == "user-agent"), "")
        base: dict[str, Any] = {
            "method": "GET",
            "path": "/protected/all",
            "client_ip": "203.0.113.7",
            "headers": headers,
            "header_order": [k.title() for k, _ in headers],
            "cookies": {},
            "user_agent": ua,
            "session_id": "",
            "store": memory_store,
        }
        base.update(overrides)
        return RequestContext(**base)

    return factory


@pytest_asyncio.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    """httpx client over a fresh app (memory store, auto-discovered modules)."""
    from app.main import create_app

    app = create_app(store=MemoryStore())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        c.app = app  # type: ignore[attr-defined]
        yield c
