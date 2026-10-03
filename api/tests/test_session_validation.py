from __future__ import annotations

from collections.abc import Callable

import httpx
from app.contract import EndpointClass, RequestContext, Signal, Verdict
from app.main import create_app
from app.modules.session_validation import SessionValidationModule, classify
from app.session import bm_sv_value
from app.store import MemoryStore

SID = "F" * 32 + "~YAAQSV~1~2"
CHROME = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36"
mod = SessionValidationModule()

NAV = [
    ("user-agent", CHROME),
    ("host", "localhost:8443"),
    ("accept", "text/html,application/xhtml+xml"),
    ("sec-fetch-mode", "navigate"),
    ("sec-fetch-dest", "document"),
    ("sec-fetch-site", "none"),
]


def xhr(
    site: str = "same-origin", referer: str | None = "https://localhost:8443/"
) -> list[tuple[str, str]]:
    h = [
        ("user-agent", CHROME),
        ("host", "localhost:8443"),
        ("accept", "application/json"),
        ("sec-fetch-mode", "cors"),
        ("sec-fetch-dest", "empty"),
        ("sec-fetch-site", site),
    ]
    return h + ([("referer", referer)] if referer is not None else [])


async def run(
    make_ctx: Callable[..., RequestContext],
    headers: list[tuple[str, str]],
    cls: EndpointClass = EndpointClass.PROTECTED,
    **kw: object,
) -> Signal:
    return await mod.evaluate(make_ctx(session_id=SID, headers=headers, endpoint_class=cls, **kw))


def test_classification() -> None:
    def ctx(headers: list[tuple[str, str]]) -> RequestContext:
        return RequestContext(
            method="GET", path="/", client_ip="1.1.1.1", headers=headers, header_order=[],
            cookies={}, user_agent="UA",
        )  # fmt: skip

    assert classify(ctx(NAV)) == ("nav", True)
    assert classify(ctx(xhr())) == ("xhr", True)
    assert classify(ctx([("accept", "text/html")])) == ("nav", False)
    assert classify(ctx([("accept", "*/*")])) == ("xhr", False)


async def test_real_browser_flow_passes(
    make_ctx: Callable[..., RequestContext], memory_store: MemoryStore
) -> None:
    landing = await run(make_ctx, NAV, EndpointClass.PAGE)
    assert landing.verdict == Verdict.PASS and landing.details["navigations"] == 1
    protected = await run(make_ctx, NAV)  # page.goto(/protected/x): navigation, site=none
    assert protected.verdict == Verdict.PASS and protected.details["navigations"] == 2
    login = await run(make_ctx, xhr(), EndpointClass.TRANSACTIONAL)
    assert login.verdict == Verdict.PASS and login.details["xhr"] == 1
    assert await memory_store.get(f"sv:nav:{SID}") == "2"
    assert await memory_store.get(f"sv:lastnav:{SID}") == "/protected/all"


async def test_api_only_session_fails(make_ctx: Callable[..., RequestContext]) -> None:
    sig = await run(make_ctx, xhr(), EndpointClass.TRANSACTIONAL)
    assert sig.verdict == Verdict.FAIL and sig.score >= 80 and "no page navigation" in sig.reason
    # a transactional call is checked even when the headers claim a navigation
    sig = await run(make_ctx, NAV, EndpointClass.TRANSACTIONAL, method="POST")
    assert sig.verdict == Verdict.PASS  # this request itself counted as a navigation


async def test_broken_xhr_chains_fail(make_ctx: Callable[..., RequestContext]) -> None:
    await run(make_ctx, NAV, EndpointClass.PAGE)
    cross = await run(make_ctx, xhr(site="cross-site"))
    assert cross.verdict == Verdict.FAIL and "Sec-Fetch-Site" in cross.reason
    no_ref = await run(make_ctx, xhr(referer=None))
    assert no_ref.verdict == Verdict.FAIL and "without a Referer" in no_ref.reason
    foreign = await run(make_ctx, xhr(site="same-site", referer="https://evil.example/x"))
    assert foreign.verdict == Verdict.FAIL and "not same-origin" in foreign.reason
    # the browser asserted same-origin: do not second-guess a host the proxy may have rewritten
    ok = await run(make_ctx, xhr(site="same-origin", referer="https://other-host/x"))
    assert ok.verdict == Verdict.PASS


async def test_browser_ua_without_fetch_metadata_warns_but_does_not_block(
    make_ctx: Callable[..., RequestContext],
) -> None:
    headers = [("user-agent", CHROME), ("accept", "text/html")]
    sig = await mod.evaluate(make_ctx(session_id=SID, headers=headers, user_agent=CHROME))
    assert sig.verdict == Verdict.WARN and "Sec-Fetch" in sig.reason and sig.score < 50
    naive = [("user-agent", "python-requests/2.32"), ("accept", "*/*")]
    sig = await mod.evaluate(make_ctx(session_id="naive", headers=naive))
    assert sig.verdict == Verdict.FAIL and sig.details["navigations"] == 0


async def test_xhr_flood_per_navigation_warns(make_ctx: Callable[..., RequestContext]) -> None:
    await run(make_ctx, NAV, EndpointClass.PAGE)
    last = None
    for _ in range(22):
        last = await run(make_ctx, xhr())
    assert last is not None and last.verdict == Verdict.WARN and "XHR calls" in last.reason


async def test_bm_sv_flag(make_ctx: Callable[..., RequestContext]) -> None:
    await run(make_ctx, NAV, EndpointClass.PAGE)
    flags = {"bm_sv_cookies": True}
    off = await run(make_ctx, xhr())
    assert off.verdict == Verdict.PASS  # flag off: cookies are not consulted
    missing = await run(make_ctx, xhr(), flags=flags)
    assert missing.verdict == Verdict.WARN and "bm_sv" in missing.reason
    good = await run(make_ctx, xhr(), flags=flags, cookies={"bm_sv": bm_sv_value(SID)})
    assert good.verdict == Verdict.PASS
    forged = await run(make_ctx, xhr(), flags=flags, cookies={"bm_sv": "x" * 40})
    assert forged.verdict == Verdict.WARN
    assert [f.name for f in SessionValidationModule.flags] == ["bm_sv_cookies"]
    assert SessionValidationModule.flags[0].confidence.value == "low"


async def test_module_metadata_and_default() -> None:
    assert mod.default_enabled and mod.confidence.value == "medium"
    assert mod.applies_to == frozenset(
        {EndpointClass.PAGE, EndpointClass.PROTECTED, EndpointClass.TRANSACTIONAL}
    )


async def test_browser_flow_through_the_app() -> None:
    app = create_app(store=MemoryStore(), modules=[SessionValidationModule()])
    hdr_nav = {"user-agent": CHROME, "accept": "text/html", "sec-fetch-mode": "navigate",
               "sec-fetch-dest": "document", "sec-fetch-site": "none"}  # fmt: skip
    hdr_xhr = {"user-agent": CHROME, "accept": "application/json", "sec-fetch-mode": "cors",
               "sec-fetch-dest": "empty", "sec-fetch-site": "same-origin",
               "referer": "http://t/"}  # fmt: skip
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as browser:
        await browser.get("/", headers=hdr_nav)  # landing
        r = await browser.get("/protected/session_validation", headers=hdr_nav)
        assert r.status_code == 200 and r.json()["report"]["signals"][0]["verdict"] == "pass"
        r = await browser.get("/protected/session_validation", headers=hdr_xhr)
        assert r.status_code == 200
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as scraper:
        r = await scraper.get("/protected/session_validation", headers=hdr_xhr)  # no page load
        assert r.status_code == 403
