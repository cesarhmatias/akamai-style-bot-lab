from __future__ import annotations

from collections.abc import AsyncIterator, Callable

import httpx
import pytest_asyncio
from app.contract import RequestContext, Verdict
from app.modules.pixel_challenge import PixelChallenge
from app.store import MemoryStore
from fastapi import FastAPI

SID = "c" * 32 + "~12345678"
P = "/akam/pixel_challenge"


@pytest_asyncio.fixture
async def mod() -> PixelChallenge:
    return PixelChallenge(secret=b"k" * 32)


@pytest_asyncio.fixture
async def http(mod: PixelChallenge, memory_store: MemoryStore) -> AsyncIterator[httpx.AsyncClient]:
    app = FastAPI()
    app.state.store = memory_store
    app.include_router(mod.router(), prefix=P)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://t", cookies={"bm_sz": SID}
    ) as c:
        yield c


async def test_token_deterministic_and_per_session(mod: PixelChallenge) -> None:
    assert mod.token(SID) == PixelChallenge(secret=b"k" * 32).token(SID)
    assert mod.token(SID) != mod.token("d" * 32 + "~1")
    assert mod.token(SID) != PixelChallenge(secret=b"z" * 32).token(SID)


async def test_full_flow(
    http: httpx.AsyncClient, mod: PixelChallenge, make_ctx: Callable[..., RequestContext]
) -> None:
    cfg = (await http.get(f"{P}/config")).json()
    g = await http.get(f"{P}/pixel.gif", params={"ap": cfg["pixel_id"], "t": cfg["token"]})
    assert g.headers["content-type"] == "image/gif" and g.content[:3] == b"GIF"
    r = await http.post(f"{P}/beacon", json={"ap": cfg["pixel_id"], "t": cfg["token"], "ts": 1})
    assert r.status_code == 200
    assert (await mod.evaluate(make_ctx(session_id=SID))).verdict == Verdict.PASS


async def test_beacon_before_gif_rejected(
    http: httpx.AsyncClient, mod: PixelChallenge, make_ctx: Callable[..., RequestContext]
) -> None:
    cfg = (await http.get(f"{P}/config")).json()
    r = await http.post(f"{P}/beacon", json={"ap": cfg["pixel_id"], "t": cfg["token"], "ts": 1})
    assert r.status_code == 403 and r.json()["error"] == "gif_not_fetched"
    sig = await mod.evaluate(make_ctx(session_id=SID))
    assert sig.verdict == Verdict.FAIL and sig.score == 70


async def test_bad_token(http: httpx.AsyncClient) -> None:
    cfg = (await http.get(f"{P}/config")).json()
    await http.get(f"{P}/pixel.gif", params={"ap": cfg["pixel_id"], "t": "0" * 32})
    r = await http.post(f"{P}/beacon", json={"ap": cfg["pixel_id"], "t": "0" * 32, "ts": 1})
    assert r.status_code == 403
    r = await http.post(f"{P}/beacon", json={"ap": cfg["pixel_id"], "t": cfg["token"], "ts": 1})
    assert r.status_code == 403  # gif with the bad token did not count


async def test_token_from_other_session(http: httpx.AsyncClient) -> None:
    cfg = (await http.get(f"{P}/config")).json()
    http.cookies.set("bm_sz", "e" * 32 + "~99999999")
    await http.get(f"{P}/pixel.gif", params={"ap": cfg["pixel_id"], "t": cfg["token"]})
    r = await http.post(f"{P}/beacon", json={"ap": cfg["pixel_id"], "t": cfg["token"], "ts": 1})
    assert r.status_code == 403


async def test_bad_body_and_no_session(http: httpx.AsyncClient) -> None:
    assert (await http.post(f"{P}/beacon", json={"ap": "x"})).status_code == 400
    http.cookies.clear()
    assert (await http.get(f"{P}/config")).status_code == 400


async def test_js(http: httpx.AsyncClient) -> None:
    t = (await http.get(f"{P}/pixel.js")).text
    assert "__akPixelDone" in t and "ak:pixel" in t
