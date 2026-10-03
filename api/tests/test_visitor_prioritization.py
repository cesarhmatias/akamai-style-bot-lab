"""Waiting room: deterministic admission, parking with TTL cookie, cookie naming flag."""

from __future__ import annotations

import httpx
from app.contract import DetectionModule, RequestContext, Signal, Verdict
from app.main import create_app
from app.modules.visitor_prioritization import VisitorPrioritization, bucket
from app.store import MemoryStore


class Clock:
    t = 100.0

    def __call__(self) -> float:
        return self.t


def sid_in(admitted: bool, percent: int = 50) -> str:
    n = 0
    while True:
        sid = f"{n:032x}~00000000"
        if (bucket(sid) < percent) == admitted:
            return sid
        n += 1


def mk(
    percent: float = 50, wait: float = 30
) -> tuple[httpx.AsyncClient, Clock, VisitorPrioritization]:
    clock = Clock()
    mod = VisitorPrioritization(admit_percent=percent, wait_seconds=wait, label="drop", clock=clock)
    app = create_app(store=MemoryStore(), modules=[mod])
    c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")
    return c, clock, mod


def test_bucket_is_deterministic_and_spread() -> None:
    assert bucket("abc") == bucket("abc")
    assert 30 < sum(bucket(f"s{i}") < 50 for i in range(200)) < 170


async def test_off_by_default_and_toggle() -> None:
    c, _, mod = mk(percent=0)
    async with c:
        assert not mod.default_enabled and mod.confidence.value == "low"
        parked_sid = sid_in(False)
        c.cookies.set("bm_sz", parked_sid)
        assert "Protected Storefront" in (await c.get("/")).text  # disabled: no gate
        await c.put("/api/modules/visitor_prioritization", json={"enabled": True})
        assert "waiting room" in (await c.get("/", headers={"accept": "text/html"})).text


async def test_admitted_new_session_gets_allowed_cookie() -> None:
    c, _, _ = mk()
    async with c:
        await c.put("/api/modules/visitor_prioritization", json={"enabled": True})
        c.cookies.set("bm_sz", sid_in(True))
        r = await c.get("/", headers={"accept": "text/html"})
        assert r.status_code == 200 and "Protected Storefront" in r.text
        assert "lab_vp_allowed" in r.cookies and not any(
            k.startswith("akavpau_") for k in r.cookies
        )
        again = await c.get("/protected/all")
        assert again.status_code == 200


async def test_parked_until_wait_elapsed_with_ttl_cookie_and_json_503() -> None:
    c, clock, _ = mk(wait=30)
    async with c:
        await c.put("/api/modules/visitor_prioritization", json={"enabled": True})
        c.cookies.set("bm_sz", sid_in(False))
        page = await c.get("/", headers={"accept": "text/html"})
        assert page.status_code == 200 and "You are in the waiting room" in page.text
        assert "Protected Storefront" not in page.text and "refresh" in page.text
        assert (
            "lab_vp_waiting" in page.headers["set-cookie"]
            and "Max-Age=30" in page.headers["set-cookie"]
        )
        api = await c.get("/protected/all")
        assert api.status_code == 503 and api.json()["error"] == "waiting_room"
        assert int(api.headers["retry-after"]) <= 30
        clock.t += 31
        ok = await c.get("/", headers={"accept": "text/html"})
        assert "Protected Storefront" in ok.text and "lab_vp_allowed" in ok.cookies
        clock.t += 1000  # stays admitted even though it started parked
        assert (await c.get("/protected/all")).status_code == 200


async def test_akavpau_cookie_name_only_behind_flag() -> None:
    c, _, _ = mk()
    async with c:
        await c.put("/api/modules/visitor_prioritization", json={"enabled": True})
        await c.put("/api/flags/akavpau_cookie_name", json={"value": True})
        c.cookies.set("bm_sz", sid_in(True))
        r = await c.get("/")
        assert "akavpau_drop" in r.cookies and "lab_vp_allowed" not in r.cookies
        flag = next(
            f for f in (await c.get("/api/flags")).json() if f["name"] == "akavpau_cookie_name"
        )
        assert flag["confidence"] == "low" and flag["default"] is False


async def test_dropped_cookie_is_restored_and_evaluate_skips() -> None:
    c, _, _ = mk()
    async with c:
        await c.put("/api/modules/visitor_prioritization", json={"enabled": True})
        c.cookies.set("bm_sz", sid_in(True))
        await c.get("/")
        c.cookies.delete("lab_vp_allowed")
        r = await c.get("/")
        assert "lab_vp_allowed" in r.cookies
        rep = (await c.get("/protected/visitor_prioritization")).json()["report"]
        assert rep["signals"][0]["verdict"] == "skip"


class Snip(DetectionModule):
    slug = "snip"
    title = "Snip"
    description = "adds a per-session snippet to every lab HTML page"
    category = "js"

    async def evaluate(self, ctx: RequestContext) -> Signal:
        return self.signal(Verdict.PASS, 0, "ok")

    async def page_snippets(self, ctx: RequestContext) -> list[str]:
        return [f'<script src="/s/{ctx.session_id[:4]}.js"></script>']


async def test_waiting_room_page_still_carries_page_snippets() -> None:
    clock = Clock()
    mod = VisitorPrioritization(admit_percent=0, wait_seconds=30, clock=clock)
    app = create_app(store=MemoryStore(), modules=[mod, Snip()])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        await c.put("/api/modules/visitor_prioritization", json={"enabled": True})
        c.cookies.set("bm_sz", "ab12" + "0" * 28 + "~00000000")
        r = await c.get("/", headers={"accept": "text/html"})
        assert "waiting room" in r.text and '<script src="/s/ab12.js">' in r.text
        assert "lab_vp_waiting" in r.headers["set-cookie"]  # cookies survive the injection
