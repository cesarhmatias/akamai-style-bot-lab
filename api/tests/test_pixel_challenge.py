from __future__ import annotations

import re
import time
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlencode

import httpx
import pytest
from app.contract import RequestContext, Verdict
from app.main import create_app
from app.modules.pixel_challenge import GLOBAL_NAME, PIXEL_N, PixelChallenge, pixel_digest
from app.store import MemoryStore
from browser_stub import run_js


class Lab:
    def __init__(self) -> None:
        self.store = MemoryStore()
        self.mod = PixelChallenge(secret=b"k" * 32)
        self.app = create_app(store=self.store, modules=[self.mod])

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url="http://t")

    async def start(self, c: httpx.AsyncClient) -> tuple[str, str]:
        """Load the page like a pure-HTTP client would; parse value and hex from the HTML."""
        html = (await c.get("/", headers={"accept": "text/html"})).text
        value = re.search(rf"{GLOBAL_NAME}=(\d+);", html)
        src = re.search(r'src="(/akam/(\d+)/([0-9a-f]{8}))"', html)
        assert value and src, html
        self.value, self.path, self.n, self.hex = (
            value.group(1),
            src.group(1),
            src.group(2),
            src.group(3),
        )
        return c.cookies["bm_sz"], html

    def body(self, sid: str, ts_ms: int | None = None, value: str | None = None) -> str:
        ts = ts_ms if ts_ms is not None else int(time.time() * 1000)
        digest = pixel_digest(value or self.value, self.hex, ts, sid)
        return urlencode({"p": f"{ts}.{digest}"})


FORM = {"content-type": "application/x-www-form-urlencoded"}


@pytest.fixture
def lab() -> Lab:
    return Lab()


def test_artifacts_are_deterministic_and_per_session() -> None:
    mod = PixelChallenge(secret=b"k" * 32)
    assert mod.value("sidA") == PixelChallenge(secret=b"k" * 32).value("sidA")
    assert mod.value("sidA") != mod.value("sidB")
    assert 1_000_000_000 <= mod.value("sidA") < 10_000_000_000
    assert (
        mod.hex_id("sidA") != mod.hex_id("sidB") != PixelChallenge(secret=b"z" * 32).hex_id("sidB")
    )
    assert mod.script_path("sidA") == f"/akam/{PIXEL_N}/{mod.hex_id('sidA')}"
    assert mod.beacon_path("sidA") == f"/akam/{PIXEL_N}/pixel_{mod.hex_id('sidA')}"


async def test_html_embeds_value_and_script_and_no_config_route(lab: Lab) -> None:
    async with lab.client() as c:
        sid, html = await lab.start(c)
        assert lab.value == str(lab.mod.value(sid)) and lab.n == str(PIXEL_N)
        assert f'<script type="text/javascript">{GLOBAL_NAME}={lab.value};</script>' in html
        assert "noscript" not in html  # unconfirmed fallback is not built
        for old in ("config", "pixel.gif", "beacon", "pixel.js"):
            assert (await c.get(f"/akam/pixel_challenge/{old}")).status_code in {404, 405}
    assert PixelChallenge.client_scripts == []


async def test_pure_http_flow_passes(lab: Lab, make_ctx: Callable[..., RequestContext]) -> None:
    async with lab.client() as c:
        sid, _ = await lab.start(c)
        js = await c.get(lab.path)
        assert js.status_code == 200 and "javascript" in js.headers["content-type"]
        assert f"/akam/{PIXEL_N}/pixel_{lab.hex}" in js.text
        r = await c.post(f"/akam/{PIXEL_N}/pixel_{lab.hex}", content=lab.body(sid), headers=FORM)
        assert r.status_code == 200 and r.json() == {"ok": True}
        assert await lab.store.get(f"pixel:{sid}") == "ok"
        sig = await lab.mod.evaluate(make_ctx(session_id=sid, store=lab.store))
        assert sig.verdict == Verdict.PASS


async def test_rejections(lab: Lab, make_ctx: Callable[..., RequestContext]) -> None:
    async with lab.client() as c:
        sid, _ = await lab.start(c)
        url = f"/akam/{PIXEL_N}/pixel_{lab.hex}"
        now = int(time.time() * 1000)
        # wrong embedded value, other session's digest, stale timestamp, garbage, wrong method
        r = await c.post(url, content=lab.body(sid, value="123"), headers=FORM)
        assert r.status_code == 403 and r.json()["error"] == "bad_pixel"
        r = await c.post(url, content=lab.body("other-sid"), headers=FORM)
        assert r.status_code == 403
        r = await c.post(url, content=lab.body(sid, ts_ms=now - 600_000), headers=FORM)
        assert r.status_code == 403 and r.json()["error"] == "stale"
        for junk in (b"", b"p=abc", b"q=1.2", b"p=1"):
            assert (await c.post(url, content=junk, headers=FORM)).status_code == 400
        assert (await c.get(url)).status_code == 404
        assert (await c.post(lab.path, content=lab.body(sid), headers=FORM)).status_code == 404
        # another session cannot use this session's path
        mine = lab.path
        async with lab.client() as other:
            await lab.start(other)
            assert lab.path != mine
            assert (await other.get(mine)).status_code == 404
        assert await lab.store.get(f"pixel:{sid}") is None
        sig = await lab.mod.evaluate(make_ctx(session_id=sid, store=lab.store))
        assert sig.verdict == Verdict.FAIL and sig.score == 70
        # no session cookie on the POST -> 400
        c.cookies.delete("bm_sz")
        assert (await c.post(url, content=lab.body(sid), headers=FORM)).status_code == 404


async def test_ak_bmsc_tie_flag(lab: Lab, make_ctx: Callable[..., RequestContext]) -> None:
    await lab.store.set("flag:pixel_ties_ak_bmsc", "1")
    await lab.store.set("flag:ak_bmsc_httponly", "1")
    async with lab.client() as c:
        sid, _ = await lab.start(c)
        old = c.cookies["ak_bmsc"]
        r = await c.post(f"/akam/{PIXEL_N}/pixel_{lab.hex}", content=lab.body(sid), headers=FORM)
        assert r.status_code == 200
        cookie = next(h for h in r.headers.get_list("set-cookie") if h.startswith("ak_bmsc="))
        assert "HttpOnly" in cookie and "Max-Age" in cookie
        new = cookie.split(";")[0].split("=", 1)[1]
        assert new != old
        flags = {"pixel_ties_ak_bmsc": True}
        # still presenting the stale ak_bmsc: pixel solved but not tied -> FAIL
        stale = make_ctx(session_id=sid, store=lab.store, flags=flags, cookies={"ak_bmsc": old})
        assert (await lab.mod.evaluate(stale)).verdict == Verdict.FAIL
        fresh = make_ctx(session_id=sid, store=lab.store, flags=flags, cookies={"ak_bmsc": new})
        assert (await lab.mod.evaluate(fresh)).verdict == Verdict.PASS
        # flag off: ak_bmsc is not consulted
        plain = make_ctx(session_id=sid, store=lab.store, cookies={"ak_bmsc": old})
        assert (await lab.mod.evaluate(plain)).verdict == Verdict.PASS


async def test_ak_bmsc_not_reissued_without_flag(lab: Lab) -> None:
    async with lab.client() as c:
        sid, _ = await lab.start(c)
        r = await c.post(f"/akam/{PIXEL_N}/pixel_{lab.hex}", content=lab.body(sid), headers=FORM)
        assert not any(h.startswith("ak_bmsc=") for h in r.headers.get_list("set-cookie"))


def test_declared_flags() -> None:
    by_name = {f.name: f for f in PixelChallenge.flags}
    assert set(by_name) == {"pixel_ties_ak_bmsc", "ak_bmsc_httponly"}
    assert all(f.confidence.value == "low" and f.default is False for f in by_name.values())


async def test_script_runs_in_node_and_its_post_is_accepted(lab: Lab, tmp_path: Path) -> None:
    async with lab.client() as c:
        sid, _ = await lab.start(c)
        js = (await c.get(lab.path)).text
        driver = f"""
        window.{GLOBAL_NAME} = {lab.value};
        """
        # run the global assignment first, then the pixel script (as the page does)
        out = run_js(
            tmp_path,
            [driver, js],
            """
            drain();
            var f = calls.filter(function (c) { return c.fetch; })[0];
            result = {url: f.input, body: f.init.body, method: f.init.method,
                      done: window.__akPixelDone, ok: window.__akPixelOk, events: window.__events};
            """,
            cookie=f"foo=bar; bm_sz={sid}; other=1",
        )
        assert out["method"] == "POST" and out["done"] is True and out["ok"] is True
        assert out["events"] == ["ak:pixel"] and out["url"] == f"/akam/{PIXEL_N}/pixel_{lab.hex}"
        r = await c.post(out["url"], content=out["body"], headers=FORM)
        assert r.status_code == 200, r.text
        assert await lab.store.get(f"pixel:{sid}") == "ok"
