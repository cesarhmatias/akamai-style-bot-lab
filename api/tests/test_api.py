from typing import ClassVar

import httpx
from app.contract import DetectionModule, RequestContext, Signal, Verdict
from app.main import create_app
from app.store import MemoryStore
from fastapi import APIRouter, Response


class Fixed(DetectionModule):
    slug = "fixed"
    title = "Fixed"
    description = "returns 80 unless header x-ok"
    category = "passive"
    client_scripts: ClassVar[list[str]] = ["fixed.js"]

    async def evaluate(self, ctx: RequestContext) -> Signal:
        if ctx.header("x-ok"):
            return self.signal(Verdict.PASS, 0, "ok")
        return self.signal(Verdict.FAIL, 80, "bad")

    def router(self) -> APIRouter:
        r = APIRouter()

        @r.get("/fixed.js")
        async def js() -> Response:
            return Response("//js", media_type="text/javascript")

        return r


def mk() -> tuple[httpx.AsyncClient, MemoryStore]:
    store = MemoryStore()
    app = create_app(store=store, modules=[Fixed()])
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t"), store


async def test_protected_block_pass_and_cookies() -> None:
    c, _ = mk()
    async with c:
        r = await c.get("/protected/fixed", headers={"x-lab-client": "naive"})
        assert r.status_code == 403 and r.json()["report"]["client_label"] == "naive"
        assert {"bm_sz", "ak_bmsc", "_abck"} <= set(r.cookies)
        assert (await c.get("/protected/fixed", headers={"x-ok": "1"})).status_code == 200
        assert (await c.get("/protected/all")).status_code == 403
        assert (await c.get("/protected/nope")).status_code == 404
        assert (await c.get("/akam/fixed/fixed.js")).text == "//js"


async def test_edge_headers_and_html_deny_page() -> None:
    c, _ = mk()
    async with c:
        h = {"x-ja3-hash": "abc", "x-client-ip": "9.9.9.9", "x-header-order": "Host,Accept"}
        rep = (await c.get("/protected/fixed", headers=h)).json()["report"]
        assert rep["fingerprint"]["ja3_hash"] == "abc" and rep["client_ip"] == "9.9.9.9"
        assert rep["fingerprint"]["header_order"] == "Host,Accept"
        assert all(k != "x-ja3-hash" for k, _ in rep["headers"])
        r = await c.get("/protected/fixed", headers={"accept": "text/html"})
        # v2: a deny is the Akamai-style 403 page (no scripts), not a script-bearing interstitial
        assert r.status_code == 403 and "Access Denied" in r.text and "Reference" in r.text


async def test_landing_includes_scripts() -> None:
    c, _ = mk()
    async with c:
        r = await c.get("/")
        assert r.status_code == 200 and '<script src="/akam/fixed/fixed.js"' in r.text


async def test_control_plane() -> None:
    c, store = mk()
    async with c:
        await c.get("/protected/fixed")
        mods = (await c.get("/api/modules")).json()
        assert mods[0]["slug"] == "fixed" and mods[0]["last_verdict"]["score"] == 80
        assert (await c.put("/api/modules/fixed", json={"enabled": False})).status_code == 200
        assert (await c.get("/protected/fixed")).status_code == 200
        assert (await c.put("/api/modules/zzz", json={"enabled": True})).status_code == 404
        assert len((await c.get("/api/requests?limit=1")).json()) == 1
        assert (await c.get("/healthz")).json() == {"status": "ok"}
        assert (await c.post("/api/reset")).status_code == 200
        assert (await c.get("/api/requests")).json() == []
        assert await store.get("toggle:fixed") == "0"


async def test_abck_reflects_validated_state() -> None:
    from app.session import mark_abck_validated

    c, store = mk()
    async with c:
        await c.get("/protected/fixed")
        sid = c.cookies["bm_sz"]
        await mark_abck_validated(store, sid)
        r = await c.get("/protected/fixed")
        assert "~0~" in r.cookies["_abck"]


async def test_cors() -> None:
    c, _ = mk()
    async with c:
        r = await c.get("/healthz", headers={"origin": "http://x"})
        assert r.headers["access-control-allow-origin"] == "*"
