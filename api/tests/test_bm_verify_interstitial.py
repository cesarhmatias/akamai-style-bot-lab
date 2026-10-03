"""Cookieless bm-verify interstitial: page shape, verification through the shared route, the
proof precedence (sec_cpt / validated _abck > solved interstitial > none), the cookieless gate,
the meta-refresh path, the LOW location flag and the LAB hardened shape."""

from __future__ import annotations

import json
import random
import re
from collections.abc import AsyncIterator, Callable

import httpx
import pytest
import pytest_asyncio
from app.contract import RequestContext, Verdict
from app.main import create_app
from app.modules.bm_verify_interstitial import (
    REFRESH_SECONDS,
    SOLVED_SCORE,
    BmVerifyInterstitial,
    render_page,
    safe_location,
    with_token,
)
from app.modules.sec_cpt_challenge import SecCptChallenge
from app.session import mark_abck_validated
from app.store import MemoryStore
from test_actions import Scored
from test_sec_cpt_challenge import DIFF, SID, Clock, answers_for, issue, verify

BASIC_RE = re.compile(r'var\s+j\s*=\s*i\s*\+\s*Number\("(\d+)"\s*\+\s*"(\d+)"\)')
HTML = {"accept": "text/html"}
ARITH = 'var i = 1; var j = i + Number("2" + "3");'


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def mod(clock: Clock) -> BmVerifyInterstitial:
    return BmVerifyInterstitial(rng=random.Random(1), clock=clock)


@pytest_asyncio.fixture
async def http(mod: BmVerifyInterstitial, clock: Clock) -> AsyncIterator[httpx.AsyncClient]:
    sec = SecCptChallenge(rng=random.Random(2), clock=clock, difficulty=DIFF, duration=2)
    app = create_app(store=MemoryStore(), modules=[Scored(), sec, mod])
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://t", cookies={"bm_sz": SID}
    ) as c:
        c.app = app  # type: ignore[attr-defined]
        yield c


def ctx_for(
    http: httpx.AsyncClient, make_ctx: Callable[..., RequestContext], **kw
) -> RequestContext:
    """A context bound to the app's own store (make_ctx defaults to the fixture store)."""
    return make_ctx(store=http.app.state.store, session_id=SID, **kw)  # type: ignore[attr-defined]


def script_of(page: str) -> str:
    m = re.search(r"<script>(.*?)</script>", page, re.S)
    assert m
    return m.group(1)


def token_of(page: str) -> str:
    return re.search(r'"bm-verify":"(\w+)"', page).group(1)  # type: ignore[union-attr]


def basic_answer(page: str) -> int:
    """What a fixed-regex solver does: no JavaScript is run."""
    i = int(re.search(r"var\s+i\s*=\s*(\d+)", page).group(1))  # type: ignore[union-attr]
    a, b = BASIC_RE.search(page).groups()  # type: ignore[union-attr]
    return i + int(a + b)


def robust_answer(js: str) -> int:
    """A parser-based solver: reads the declarations, whatever the shape."""
    decls = re.findall(r"(?:var|let)\s+([\w$]+)\s*=\s*([^;]+);", js)
    values: dict[str, int] = {}
    for name, rhs in decls:
        rhs = rhs.strip()
        if re.fullmatch(r"0x[0-9a-fA-F]+|\d+", rhs):
            values[name] = int(rhs, 16 if rhs.lower().startswith("0x") else 10)
    for _name, rhs in decls:
        strings = re.findall(r"""(['"])(\d+)\1""", rhs)
        if strings:
            ref = next(
                v
                for k, v in values.items()
                if re.search(rf"(?<![\w$]){re.escape(k)}(?![\w$])", rhs)
            )
            return ref + int("".join(s for _, s in strings))
    raise AssertionError("no arithmetic found")


async def get_page(http: httpx.AsyncClient, **params: str) -> str:
    r = await http.get("/akam/bm_verify_interstitial/page", params=params)
    assert r.status_code == 200 and "text/html" in r.headers["content-type"]
    return r.text


async def solve_page(http: httpx.AsyncClient, page: str) -> httpx.Response:
    return await http.post(
        "/_sec/verify?provider=interstitial",
        json={"bm-verify": token_of(page), "pow": basic_answer(page)},
    )


async def test_page_shape_and_correct_answer(
    http: httpx.AsyncClient, mod: BmVerifyInterstitial, make_ctx: Callable[..., RequestContext]
) -> None:
    page = await get_page(http)
    assert "var i = " in page and BASIC_RE.search(page)
    assert "/_sec/verify?provider=interstitial" in page
    assert 'location.replace("/")' in page  # the on-demand route never reloads itself
    tok = token_of(page)
    assert tok.startswith("AAQ")  # the observed token prefix
    assert f"content=\"{REFRESH_SECONDS}; URL='/?bm-verify={tok}'\"" in page  # no-JS path
    r = await solve_page(http, page)
    assert r.status_code == 200 and r.json() == {"ok": True, "provider": "interstitial"}
    assert {"_abck", "ak_bmsc"} <= set(r.cookies)  # lab cookie issuance (bm_sz already sent)
    sig = await mod.evaluate(ctx_for(http, make_ctx))
    # a regex solves the basic page without JavaScript: WARN in the cautious band, never PASS
    assert sig.verdict == Verdict.WARN and sig.score == SOLVED_SCORE == 20
    assert "regex" in sig.reason
    assert await mod.challenge_satisfied(ctx_for(http, make_ctx), "interstitial")
    assert not await mod.challenge_satisfied(ctx_for(http, make_ctx), "crypto")


async def test_failures_replay_session_expiry(http: httpx.AsyncClient, clock: Clock) -> None:
    page = await get_page(http)
    ans, tok = basic_answer(page), token_of(page)
    wrong = await http.post("/_sec/verify", json={"bm-verify": tok, "pow": ans + 1})
    assert wrong.status_code == 403 and wrong.json()["error"] == "wrong_answer"
    again = await http.post("/_sec/verify", json={"bm-verify": tok, "pow": ans})
    assert again.json()["error"] == "unknown_or_replayed"  # consumed by the failed attempt

    page = await get_page(http)
    assert (await solve_page(http, page)).status_code == 200
    replay = await solve_page(http, page)
    assert replay.json()["error"] == "unknown_or_replayed"

    page = await get_page(http)
    clock.t += 61
    assert (await solve_page(http, page)).json()["error"] == "expired"

    page = await get_page(http)
    http.cookies.set("bm_sz", "b" * 32 + "~00000000")
    assert (await solve_page(http, page)).json()["error"] == "wrong_session"
    http.cookies.set("bm_sz", SID)
    bad = await http.post("/_sec/verify", json={"bm-verify": "x", "pow": "nan"})
    assert bad.json()["error"] == "unknown_or_replayed"
    page = await get_page(http)
    nan = await http.post("/_sec/verify", json={"bm-verify": token_of(page), "pow": "nan"})
    assert nan.json()["error"] == "bad_answer"


async def test_shared_verify_route_hands_each_token_to_its_issuer(
    http: httpx.AsyncClient, clock: Clock
) -> None:
    """``/_sec/verify`` asks only the modules that serve ``?provider=``: an interstitial token
    posted as ``crypto`` is unknown to the crypto verifier and stays redeemable."""
    page = await get_page(http)
    as_crypto = await http.post(
        "/_sec/verify?provider=crypto",
        json={"bm-verify": token_of(page), "pow": basic_answer(page)},
    )
    assert as_crypto.status_code == 403 and as_crypto.json()["error"] == "unknown_or_replayed"
    assert (await solve_page(http, page)).json()["ok"]  # not consumed by the wrong verifier
    ch = await issue(http)
    clock.t += 2
    as_interstitial = await verify(http, ch, provider="interstitial")
    assert as_interstitial.json()["error"] == "unknown_or_replayed"
    no_provider = await http.post(
        "/_sec/verify", json={"token": ch["token"], "answers": answers_for(ch)}
    )
    assert no_provider.json() == {"ok": True, "provider": "crypto"}  # found its issuer


async def test_best_proof_wins(
    http: httpx.AsyncClient,
    mod: BmVerifyInterstitial,
    clock: Clock,
    make_ctx: Callable[..., RequestContext],
) -> None:
    """sec_cpt or validated _abck (PASS) > solved interstitial (WARN 20) > none."""
    await solve_page(http, await get_page(http))
    assert (await mod.evaluate(ctx_for(http, make_ctx))).verdict == Verdict.WARN
    ch = await issue(http)
    clock.t += 2
    cookie = (await verify(http, ch)).cookies["sec_cpt"]
    sig = await mod.evaluate(ctx_for(http, make_ctx, cookies={"sec_cpt": cookie}))
    assert sig.verdict == Verdict.PASS and "sec_cpt" in sig.reason
    # solving another interstitial never downgrades the stronger proof
    await solve_page(http, await get_page(http))
    sig = await mod.evaluate(ctx_for(http, make_ctx, cookies={"sec_cpt": cookie}))
    assert sig.verdict == Verdict.PASS
    other = "c" * 32 + "~cafebabe"
    await mark_abck_validated(http.app.state.store, other)  # type: ignore[attr-defined]
    ctx = make_ctx(store=http.app.state.store, session_id=other)  # type: ignore[attr-defined]
    sig = await mod.evaluate(ctx)
    assert sig.verdict == Verdict.PASS and "_abck" in sig.reason
    assert await mod.challenge_satisfied(ctx, "interstitial")


async def test_no_proof_fails_only_while_the_interstitial_is_in_use(
    http: httpx.AsyncClient, mod: BmVerifyInterstitial, make_ctx: Callable[..., RequestContext]
) -> None:
    ctx = ctx_for(http, make_ctx)
    sig = await mod.evaluate(ctx)
    assert sig.verdict == Verdict.SKIP and "not in use" in sig.reason
    await http.put("/api/policy", json={"params": {"challenge_provider": "interstitial"}})
    sig = await mod.evaluate(ctx)
    assert sig.verdict == Verdict.FAIL and sig.score == 45
    await http.put("/api/policy", json={"params": {"challenge_provider": "crypto"}})
    gated = ctx_for(http, make_ctx, flags={"interstitial_cookieless_gate": True})
    assert (await mod.evaluate(gated)).verdict == Verdict.FAIL
    assert not await mod.challenge_satisfied(gated, "interstitial")


def test_safe_location_guard() -> None:
    assert safe_location("/protected/all?x=1") == "/protected/all?x=1"
    for bad in (
        None,
        "",
        "https://evil.example/x",
        "//evil.example",
        "/\\evil.example",
        "evil.example",
        "javascript:alert(1)",
        "/ok\r\nSet-Cookie: a=b",
        "http:/evil",
    ):
        assert safe_location(bad) is None


async def test_basic_numbers_follow_the_observed_shape(
    http: httpx.AsyncClient, clock: Clock
) -> None:
    """Observed: ``var i = 1789910678; var j = i + Number("3886" + "11036");`` where i is the
    issuing Unix time (2026-09-20 UTC) and the answer no longer fits a 32-bit int."""
    clock.t = 1789910678.4
    page = await get_page(http)
    i = int(re.search(r"var i = (\d+);", page).group(1))  # type: ignore[union-attr]
    a, b = BASIC_RE.search(page).groups()  # type: ignore[union-attr]
    assert i == 1789910678 and (len(a), len(b)) == (4, 5)
    r = await http.post("/_sec/verify", json={"bm-verify": token_of(page), "pow": i + int(a + b)})
    assert r.status_code == 200


async def test_location_only_with_the_low_flag_and_same_origin(http: httpx.AsyncClient) -> None:
    page = await get_page(http, return_to="/protected/all?x=1")
    assert "location" not in (await solve_page(http, page)).json()  # off: the observed reload
    await http.put("/api/flags/interstitial_location", json={"value": True})
    page = await get_page(http, return_to="/protected/all?x=1")
    assert (await solve_page(http, page)).json()["location"] == "/protected/all?x=1"
    for evil in ("//evil.example/x", "https://evil.example/", "/\\evil.example"):
        r = await solve_page(http, await get_page(http, return_to=evil))
        assert r.status_code == 200 and "location" not in r.json()


async def test_cookieless_gate_serves_the_page_and_solving_clears_it(
    http: httpx.AsyncClient,
) -> None:
    assert "Protected Storefront" in (await http.get("/", headers={"accept": "text/html"})).text
    await http.put("/api/flags/interstitial_cookieless_gate", json={"value": True})
    app = http.app  # type: ignore[attr-defined]
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        r = await c.get("/", headers=HTML)
        assert (
            r.status_code == 200
            and '"bm-verify"' in r.text
            and "Protected Storefront" not in r.text
        )
        assert f"URL='/?bm-verify={token_of(r.text)}'" in r.text  # meta refresh, same URL
        # issued with the interstitial (the lab binds the token to bm_sz), so they prove nothing
        assert {"bm_sz", "_abck", "ak_bmsc"} <= set(c.cookies)
        again = await c.get("/", headers=HTML)  # a reload with those cookies, nothing solved
        assert '"bm-verify"' in again.text and "Protected Storefront" not in again.text
        v = await solve_page(c, again.text)
        assert v.json()["ok"] and "location" not in v.json()  # the page just reloads
        after = await c.get("/", headers=HTML)  # the page's reload
        assert "Protected Storefront" in after.text
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        assert "Protected Storefront" in (await c.get("/")).text  # no text/html accept: not gated


async def test_solved_interstitial_is_monitored_not_rechallenged(http: httpx.AsyncClient) -> None:
    """WARN 20 sits in the cautious band: the protected page is served under monitoring (the
    captures show a cleared session getting the real page), but the signal never PASSes."""
    await http.put("/api/flags/interstitial_cookieless_gate", json={"value": True})
    before = (await http.get("/protected/bm_verify_interstitial")).json()  # Accept */*: not gated
    assert before["report"]["action"] == "challenge"  # no proof: FAIL 45, strict band
    await solve_page(http, await get_page(http))
    report = (await http.get("/protected/bm_verify_interstitial")).json()["report"]
    sig = next(s for s in report["signals"] if s["module"] == "bm_verify_interstitial")
    assert (sig["verdict"], sig["score"]) == ("warn", SOLVED_SCORE)
    assert (report["segment"], report["action"]) == ("cautious", "monitor")


async def test_cookieless_gate_cleared_by_sec_cpt_or_validated_abck(
    http: httpx.AsyncClient, clock: Clock
) -> None:
    """Server-side proof clears the gate: a valid sec_cpt (sec_cpt_challenge) or an _abck the
    sensor flow validated, as well as a solved interstitial."""
    await http.put("/api/flags/interstitial_cookieless_gate", json={"value": True})
    assert '"bm-verify"' in (await http.get("/", headers=HTML)).text  # SID has no proof yet
    ch = await issue(http)
    clock.t += 2
    assert (await verify(http, ch)).status_code == 200  # sec_cpt now in the jar
    assert "Protected Storefront" in (await http.get("/", headers=HTML)).text
    app = http.app  # type: ignore[attr-defined]
    other = "c" * 32 + "~cafebabe"
    await mark_abck_validated(app.state.store, other)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://t", cookies={"bm_sz": other}
    ) as c:
        assert "Protected Storefront" in (await c.get("/", headers=HTML)).text


async def test_meta_refresh_token_admits_one_navigation_after_the_wait(
    http: httpx.AsyncClient, clock: Clock
) -> None:
    """No JavaScript: following the page's meta refresh after the delay passes the gate once."""
    await http.put("/api/flags/interstitial_cookieless_gate", json={"value": True})
    app = http.app  # type: ignore[attr-defined]

    def client(cookies: dict[str, str] | None = None) -> httpx.AsyncClient:
        transport = httpx.ASGITransport(app=app)
        return httpx.AsyncClient(transport=transport, base_url="http://t", cookies=cookies)

    async with client() as c:
        tok = token_of((await c.get("/", headers=HTML)).text)
        early = await c.get(f"/?bm-verify={tok}", headers=HTML)
        assert '"bm-verify"' in early.text  # the time penalty: too early, token kept
        clock.t += REFRESH_SECONDS
        async with client(cookies={"bm_sz": "d" * 32 + "~00000001"}) as stranger:
            assert '"bm-verify"' in (await stranger.get(f"/?bm-verify={tok}", headers=HTML)).text
        passed = await c.get(f"/?bm-verify={tok}", headers=HTML)
        assert "Protected Storefront" in passed.text  # one page, no JavaScript
        replay = await c.get(f"/?bm-verify={tok}", headers=HTML)
        assert '"bm-verify"' in replay.text  # single use
        assert '"bm-verify"' in (await c.get("/", headers=HTML)).text  # nothing was cleared
    async with client() as c:  # the observed refetch needs no cookies
        tok = token_of((await c.get("/", headers=HTML)).text)
        clock.t += REFRESH_SECONDS
        async with client() as cookieless:
            refetch = await cookieless.get(f"/?bm-verify={tok}", headers=HTML)
            assert "Protected Storefront" in refetch.text


async def test_challenge_action_with_interstitial_provider(http: httpx.AsyncClient) -> None:
    await http.put("/api/policy", json={"params": {"challenge_provider": "interstitial"}})
    j = (await http.get("/protected/all", headers={"x-score": "40"})).json()
    assert j["provider"] == "interstitial" and j["report"]["challenge_provider"] == "interstitial"
    # explicit /protected/<slug> only: no second "nothing solved" signal next to sec_cpt's
    assert "bm_verify_interstitial" not in {s["module"] for s in j["report"]["signals"]}
    assert j["token"] == j["bm-verify"] and BASIC_RE.search(j["expression"])
    assert "result_var" not in j and "chlg_duration" not in j  # no minimum wait on this page
    page = await http.get("/protected/all", headers={"x-score": "40", "accept": "text/html"})
    assert page.status_code == 200 and '"bm-verify"' in page.text
    assert (await solve_page(http, page.text)).json()["ok"]
    after = await http.get("/protected/all", headers={"x-score": "40"})
    assert after.json()["report"]["action"] == "monitor"  # satisfied for the interstitial provider


async def test_hardened_breaks_fixed_regex_but_not_a_parser(http: httpx.AsyncClient) -> None:
    await http.put("/api/flags/interstitial_hardened", json={"value": True})
    shapes = set()
    for _ in range(40):
        page = await get_page(http)
        assert BASIC_RE.search(page) is None  # the fixed pattern no longer matches
        js = script_of(page)
        shapes.add(re.sub(r"\d+", "N", re.split(r"fetch\(", js)[0]))
        r = await http.post(
            "/_sec/verify?provider=interstitial",
            json={"bm-verify": token_of(page), "pow": robust_answer(js.split("fetch(")[0])},
        )
        assert r.status_code == 200, (page, r.text)  # a parser-based solver still succeeds
    assert len(shapes) > 15  # genuinely varied shapes
    await http.put("/api/flags/interstitial_hardened", json={"value": False})
    assert BASIC_RE.search(await get_page(http))  # and the basic page matches again


async def test_hardened_stale_regex_answer_is_wrong(http: httpx.AsyncClient) -> None:
    """A solver that falls back to the basic shape's regex on hardened output has no match,
    and answering with a stale/basic value is rejected."""
    stale = basic_answer(await get_page(http))
    await http.put("/api/flags/interstitial_hardened", json={"value": True})
    page = await get_page(http)
    assert BASIC_RE.search(page) is None
    r = await http.post("/_sec/verify", json={"bm-verify": token_of(page), "pow": stale})
    assert r.status_code == 403 and r.json()["error"] == "wrong_answer"


async def test_page_route_needs_a_session(http: httpx.AsyncClient) -> None:
    no_sid = httpx.AsyncClient(transport=httpx.ASGITransport(app=http.app), base_url="http://t")  # type: ignore[attr-defined]
    async with no_sid:
        assert (await no_sid.get("/akam/bm_verify_interstitial/page")).status_code == 400


def run_in_node(js: str) -> dict | None:
    """Run the served script under node:20-alpine with fetch stubbed; None if unavailable."""
    import shutil
    import subprocess

    if not shutil.which("docker"):
        return None
    driver = (
        "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{"
        "let cap=null;const fetchStub=(u,o)=>{cap=JSON.parse(o.body);return new Promise(()=>{})};"
        "new Function('fetch','location','document',s)(fetchStub,{reload(){}},{});"
        "console.log(JSON.stringify(cap))})"
    )
    try:
        out = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "-i",
                "--network",
                "none",
                "node:20-alpine",
                "node",
                "-e",
                driver,
            ],
            input=js,
            capture_output=True,
            text=True,
            timeout=90,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    if out.returncode != 0:
        return None
    return json.loads(out.stdout.strip().splitlines()[-1])  # type: ignore[no-any-return]


@pytest.mark.parametrize("hardened", [False, True])
async def test_node_executes_served_script_to_the_servers_answer(
    http: httpx.AsyncClient, hardened: bool
) -> None:
    if hardened:
        await http.put("/api/flags/interstitial_hardened", json={"value": True})
    pages = [await get_page(http) for _ in range(6 if hardened else 1)]
    first = run_in_node(script_of(pages[0]))
    if first is None:
        pytest.skip("docker with node:20-alpine is not available")
    for page in pages:
        cap = run_in_node(script_of(page))
        assert cap is not None and cap["bm-verify"] == token_of(page)
        r = await http.post("/_sec/verify?provider=interstitial", json=cap)
        assert r.status_code == 200 and r.json()["ok"], (page, cap, r.text)


def test_script_reloads_except_on_the_on_demand_route() -> None:
    """The gate's page reloads (as observed); reloading /akam/bm_verify_interstitial/page would
    mint a fresh page forever, so that route's page goes to its return path instead."""
    gate = render_page("TOK", ARITH, "j", refresh_url="/x?bm-verify=TOK")
    assert "location.reload()" in gate and "location.replace(l)" in gate  # location: LOW flag
    assert "content=\"5; URL='/x?bm-verify=TOK'\"" in gate
    demand = render_page("TOK", ARITH, "j", refresh_url="/?bm-verify=TOK", after="/x")
    assert 'location.replace("/x")' in demand and "location.reload()" not in demand


def test_page_escapes_the_challenged_url() -> None:
    evil = "/p\"><script>alert(1)</script>?q='x"
    page = render_page("TOK", ARITH, "j", refresh_url=with_token(evil, "TOK"), after=evil)
    assert "<script>alert(1)" not in page and page.count("</script>") == 1
    assert with_token("/a?bm-verify=old&x=1", "NEW") == "/a?x=1&bm-verify=NEW"
