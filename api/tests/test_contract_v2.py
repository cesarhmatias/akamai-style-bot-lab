"""Tests for the v2 contract hooks: flags, page snippets, dynamic paths, report ids."""

from typing import Any, ClassVar

import httpx
from app.contract import (
    Confidence,
    DetectionModule,
    EndpointClass,
    FlagSpec,
    RequestContext,
    Signal,
    Verdict,
)
from app.main import create_app
from app.store import MemoryStore
from fastapi import Request
from fastapi.responses import PlainTextResponse


class Hooked(DetectionModule):
    slug = "hooked"
    title = "Hooked"
    description = "exercises the v2 hooks"
    category = "js"
    confidence = Confidence.MEDIUM
    flags: ClassVar[list[FlagSpec]] = [FlagSpec(name="hooked_strict", description="strict mode")]

    async def evaluate(self, ctx: RequestContext) -> Signal:
        if ctx.flag("hooked_strict"):
            return self.signal(Verdict.FAIL, 90, "strict flag on")
        return self.signal(Verdict.PASS, 0, "ok", sid=ctx.session_id)

    async def page_snippets(self, ctx: RequestContext) -> list[str]:
        return [f'<script src="/r/{ctx.session_id[:8]}"></script>']

    async def handle_dynamic(self, request: Request, ctx: RequestContext) -> Any | None:
        if request.url.path == f"/r/{ctx.session_id[:8]}":
            return PlainTextResponse(f"script for {request.method}")
        return None


class PageOnly(DetectionModule):
    slug = "page_only"
    title = "Page only"
    description = "only evaluated on transactional endpoints"
    category = "passive"
    applies_to = frozenset({EndpointClass.TRANSACTIONAL})

    async def evaluate(self, ctx: RequestContext) -> Signal:
        return self.signal(Verdict.FAIL, 99, "should not run on /protected/all")


def mk() -> httpx.AsyncClient:
    app = create_app(store=MemoryStore(), modules=[Hooked(), PageOnly()])
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")


async def test_first_visit_has_session_and_snippet_and_dynamic_path() -> None:
    async with mk() as c:
        r = await c.get("/")
        sid = r.cookies["bm_sz"]
        assert f'src="/r/{sid[:8]}"' in r.text  # snippet rendered with the minted session
        rep = (await c.get(f"/api/requests/{r.headers['x-lab-report-id']}")).json()
        assert rep["endpoint_class"] == "page"
        assert (await c.get(f"/r/{sid[:8]}")).text == "script for GET"
        assert (await c.post(f"/r/{sid[:8]}")).text == "script for POST"
        assert (await c.get("/r/nope")).status_code == 404


async def test_applies_to_filters_all_but_not_single_slug() -> None:
    async with mk() as c:
        rep = (await c.get("/protected/all")).json()["report"]
        assert [s["module"] for s in rep["signals"]] == ["hooked"]
        assert rep["signals"][0]["confidence"] == "medium"
        assert (await c.get("/protected/page_only")).status_code == 403


async def test_flags_endpoint_toggles_behaviour(monkeypatch: Any) -> None:
    async with mk() as c:
        flags = (await c.get("/api/flags")).json()
        assert flags[0]["name"] == "hooked_strict" and flags[0]["value"] is False
        assert flags[0]["confidence"] == "low"
        assert (await c.get("/protected/hooked")).status_code == 200
        assert (await c.put("/api/flags/hooked_strict", json={"value": True})).status_code == 200
        assert (await c.get("/protected/hooked")).status_code == 403
        assert (await c.put("/api/flags/nope", json={"value": True})).status_code == 404
        assert (await c.get("/api/requests/nope")).status_code == 404


async def test_flag_env_fallback(monkeypatch: Any) -> None:
    monkeypatch.setenv("LAB_FLAG_HOOKED_STRICT", "true")
    async with mk() as c:
        assert (await c.get("/protected/hooked")).status_code == 403
