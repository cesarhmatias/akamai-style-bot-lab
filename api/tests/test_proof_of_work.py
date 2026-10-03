"""sec_cpt-style proof of work: providers, 428 vs interstitial, chlg_duration, sec_cpt
validation, re-challenge interval, safeguard interplay and the LAB-only simple variant."""

from __future__ import annotations

import base64
import hashlib
import json
import random
import re
from collections.abc import AsyncIterator, Callable

import httpx
import pytest
import pytest_asyncio
from app.contract import RequestContext, Verdict
from app.main import create_app
from app.modules.proof_of_work import (
    INTERSTITIAL_SCORE,
    REFRESH_SECONDS,
    ProofOfWork,
    eval_expression,
    sub_nonce,
)
from app.session import mark_abck_validated
from app.store import MemoryStore
from test_actions import Scored

SID = "a" * 32 + "~deadbeef"
DIFF = 3


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def mod(clock: Clock) -> ProofOfWork:
    return ProofOfWork(rng=random.Random(1), clock=clock, difficulty=DIFF, duration=2, interval=600)


@pytest_asyncio.fixture
async def http(mod: ProofOfWork) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(store=MemoryStore(), modules=[Scored(), mod])
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


def solve(nonce: str, difficulty: int = DIFF) -> int:
    i = 0
    while not hashlib.sha256(f"{nonce}{i}".encode()).hexdigest().startswith("0" * difficulty):
        i += 1
    return i


async def issue(http: httpx.AsyncClient, provider: str = "crypto", **params: str) -> dict:
    r = await http.get("/akam/proof_of_work/challenge", params={"provider": provider, **params})
    assert r.status_code == 200
    return r.json()  # type: ignore[no-any-return]


def answers_for(ch: dict) -> list[int]:
    count = ch.get("count", 1)
    return [solve(sub_nonce(ch["nonce"], i, count), ch["difficulty"]) for i in range(count)]


async def verify(http: httpx.AsyncClient, ch: dict, provider: str | None = None, **body: object):
    provider = provider or ch["provider"]
    payload = body or {"token": ch["token"], "answers": answers_for(ch)}
    return await http.post(f"/_sec/verify?provider={provider}", json=payload)


async def test_crypto_flow_with_min_duration(
    http: httpx.AsyncClient, mod: ProofOfWork, clock: Clock, make_ctx: Callable[..., RequestContext]
) -> None:
    ch = await issue(http)
    assert ch["provider"] == "crypto" and ch["chlg_duration"] == 2 and ch["difficulty"] == DIFF
    assert ch["token"] == ch["challenge_id"] and "count" not in ch
    early = await verify(http, ch)  # correct answer, but no waiting
    assert early.status_code == 403 and early.json()["error"] == "too_early"
    assert early.json()["retry_after"] > 0
    ch = await issue(http)
    clock.t += 2
    ok = await verify(http, ch)
    assert ok.status_code == 200 and ok.json() == {
        "ok": True,
        "variant": "hard",
        "provider": "crypto",
    }
    cookie = ok.cookies["sec_cpt"]
    assert "~3~" in cookie
    sig = await mod.evaluate(ctx_for(http, make_ctx, cookies={"sec_cpt": cookie}))
    assert sig.verdict == Verdict.PASS


async def test_sec_cpt_is_validated_and_forgery_fails(
    http: httpx.AsyncClient, mod: ProofOfWork, clock: Clock, make_ctx: Callable[..., RequestContext]
) -> None:
    ch = await issue(http)
    clock.t += 2
    cookie = (await verify(http, ch)).cookies["sec_cpt"]
    assert (
        await mod.evaluate(ctx_for(http, make_ctx, cookies={"sec_cpt": cookie}))
    ).verdict == Verdict.PASS
    forged = "0" * 32 + "~3~" + str(int(clock.t))
    for cookies in ({"sec_cpt": forged}, {"sec_cpt": cookie.replace("~3~", "~2~")}):
        sig = await mod.evaluate(ctx_for(http, make_ctx, cookies=cookies))
        assert sig.verdict == Verdict.FAIL and sig.score == 80 and "forged" in sig.reason
    sig = await mod.evaluate(ctx_for(http, make_ctx, cookies={}))  # dropped the cookie
    assert sig.verdict == Verdict.FAIL and sig.score == 45 and "not presented" in sig.reason
    # a cookie with no matching server state at all is just unsolved
    stranger = make_ctx(
        store=http.app.state.store,  # type: ignore[attr-defined]
        session_id="b" * 32,
        cookies={"sec_cpt": cookie},
    )
    other = await mod.evaluate(stranger)
    assert other.verdict == Verdict.FAIL and "no proof of work" in other.reason


async def test_rechallenge_after_interval(
    http: httpx.AsyncClient, mod: ProofOfWork, clock: Clock, make_ctx: Callable[..., RequestContext]
) -> None:
    ch = await issue(http)
    clock.t += 2
    cookie = (await verify(http, ch)).cookies["sec_cpt"]
    ctx = ctx_for(http, make_ctx, cookies={"sec_cpt": cookie})
    clock.t += 599
    assert (await mod.evaluate(ctx)).verdict == Verdict.PASS
    clock.t += 2
    sig = await mod.evaluate(ctx)
    assert sig.verdict == Verdict.FAIL and sig.details["rechallenge"] is True
    assert not await mod.challenge_satisfied(ctx)


async def test_adaptive_needs_count_solutions_and_sensor(
    http: httpx.AsyncClient, clock: Clock
) -> None:
    ch = await issue(http, "adaptive")
    assert ch["count"] == 3 and ch["difficulty"] == DIFF - 1
    clock.t += 2
    one = await http.post(
        "/_sec/verify?provider=adaptive",
        json={"token": ch["token"], "answer": solve(ch["nonce"] + ".0", ch["difficulty"])},
    )
    assert one.status_code == 403 and one.json()["error"] == "wrong_answer"
    ch = await issue(http, "adaptive")
    clock.t += 2
    r = await verify(http, ch)  # all three solved, but no sensor posts yet
    assert r.status_code == 403 and r.json()["error"] == "no_sensor"
    await http.app.state.store.set(f"sensor:n:{SID}", "1")  # type: ignore[attr-defined]
    ch = await issue(http, "adaptive")
    clock.t += 2
    assert (await verify(http, ch)).status_code == 200


async def test_behavioral_requires_sensor_and_wait(http: httpx.AsyncClient, clock: Clock) -> None:
    store = http.app.state.store  # type: ignore[attr-defined]
    ch = await issue(http, "behavioral")
    assert "nonce" not in ch
    clock.t += 2
    r = await http.post(
        "/_sec/cp_challenge/verify?provider=behavioral", json={"token": ch["token"]}
    )
    assert r.status_code == 403 and r.json()["error"] == "no_sensor"
    await store.set(f"sensor:{SID}", "{}")  # legacy single-record key also counts
    ch = await issue(http, "behavioral")
    early = await http.post("/_sec/verify?provider=behavioral", json={"token": ch["token"]})
    assert early.json()["error"] == "too_early"
    ch = await issue(http, "behavioral")
    clock.t += 2
    ok = await http.post("/_sec/verify?provider=behavioral", json={"token": ch["token"]})
    assert ok.status_code == 200 and "sec_cpt" in ok.cookies


async def test_wrong_answer_replay_expiry_session_provider(
    http: httpx.AsyncClient, clock: Clock
) -> None:
    ch = await issue(http)
    bad = solve(ch["nonce"]) + 1
    while hashlib.sha256(f"{ch['nonce']}{bad}".encode()).hexdigest().startswith("0" * DIFF):
        bad += 1
    r = await http.post("/_sec/verify", json={"token": ch["token"], "answer": bad})
    assert r.status_code == 403 and r.json()["error"] == "wrong_answer"
    clock.t += 2
    again = await verify(http, ch)
    assert again.json()["error"] == "unknown_or_replayed"  # consumed by the failed attempt
    ch = await issue(http)
    clock.t += 61
    assert (await verify(http, ch)).json()["error"] == "expired"
    ch = await issue(http)
    clock.t += 2
    assert (await verify(http, ch, provider="adaptive")).json()["error"] == "wrong_provider"
    ch = await issue(http)
    http.cookies.set("bm_sz", "b" * 32 + "~00000000")
    clock.t += 2
    assert (await verify(http, ch)).json()["error"] == "wrong_session"
    http.cookies.clear()
    assert (await http.post("/_sec/verify", json={"token": "x"})).status_code == 400
    assert (await http.get("/akam/proof_of_work/challenge")).status_code == 400


async def test_bad_requests(http: httpx.AsyncClient) -> None:
    assert (await http.post("/_sec/verify", json={"x": 1})).status_code == 400
    assert (await http.post("/_sec/verify", json=[1])).status_code == 400
    assert (await http.post("/_sec/verify", content=b"not json")).status_code == 400
    assert (await http.get("/akam/proof_of_work/challenge?variant=nope")).status_code == 400
    assert (await http.get("/akam/proof_of_work/challenge?provider=nope")).status_code == 400
    ch = await issue(http)
    r = await http.post("/_sec/verify", json={"token": ch["token"], "answers": ["x"]})
    assert r.json()["error"] == "bad_answer"


async def test_legacy_routes_keep_working_after_the_wait(
    http: httpx.AsyncClient, clock: Clock
) -> None:
    ch = await issue(http, variant="hard")
    assert ch["variant"] == "hard" and ch["challenge_id"]
    clock.t += 2
    r = await http.post(
        "/akam/proof_of_work/verify",
        json={"challenge_id": ch["challenge_id"], "answer": solve(ch["nonce"])},
    )
    assert r.status_code == 200 and "~3~" in r.cookies["sec_cpt"]


async def test_simple_variant_is_free_form_and_only_warns(
    http: httpx.AsyncClient, mod: ProofOfWork, make_ctx: Callable[..., RequestContext]
) -> None:
    ch = await issue(http, variant="simple")
    assert ch["lab_only"] is True and "interstitial" in ch["note"]
    r = await http.post(
        "/akam/proof_of_work/verify",
        json={"challenge_id": ch["challenge_id"], "answer": eval_expression(ch["expression"])},
    )
    assert r.json()["ok"] and "sec_cpt" not in r.cookies  # no real sec_cpt for this variant
    sig = await mod.evaluate(ctx_for(http, make_ctx))
    assert sig.verdict == Verdict.WARN and sig.score < 50
    assert mod.confidence.value == "medium"


async def test_unsolved_fails(mod: ProofOfWork, make_ctx: Callable[..., RequestContext]) -> None:
    sig = await mod.evaluate(make_ctx(session_id=SID))
    assert sig.verdict == Verdict.FAIL and sig.score == 45


async def test_js_served_everywhere(http: httpx.AsyncClient) -> None:
    for url in ("/akam/proof_of_work/pow.js", "/_sec/cp_challenge/sec-cpt-1.0.js"):
        r = await http.get(url)
        assert "__akPowDone" in r.text and "sec-cpt-if" in r.text
    assert "Checking" in (await http.get("/_sec/cp_challenge/message.htm")).text


# -- end to end through the challenge action ------------------------------------------------


def decode_iframe(page: str) -> tuple[str, dict, str]:
    tag = re.search(r'<iframe id="sec-cpt-if"[^>]*>', page)
    assert tag
    attrs = dict(re.findall(r'([\w-]+)="([^"]*)"', tag.group(0)))
    return (
        attrs["provider"],
        json.loads(base64.b64decode(attrs["challenge"])),
        attrs["data-duration"],
    )


async def test_challenge_action_428_json_vs_iframe_interstitial(
    http: httpx.AsyncClient, clock: Clock
) -> None:
    r = await http.get("/protected/all", headers={"x-score": "40"})
    j = r.json()
    assert r.status_code == 428 and r.headers["content-type"].startswith("application/json")
    assert j["provider"] == "crypto" and j["ok"] is False and j["report"]["action"] == "challenge"
    assert {"token", "nonce", "difficulty", "timestamp", "timeout", "chlg_duration"} <= set(j)
    assert j["report"]["blocked"] and j["report"]["challenge_provider"] == "crypto"

    page = await http.get(
        "/protected/all", headers={"x-score": "40", "accept": "text/html,application/xhtml+xml"}
    )
    assert page.status_code == 200 and "<title>Checking your browser</title>" in page.text
    provider, ch, duration = decode_iframe(page.text)
    assert provider == "crypto" and duration == "2" and ch["chlg_duration"] == 2
    assert "/_sec/cp_challenge/sec-cpt-1.0.js" in page.text

    # solve it exactly like the browser script does
    clock.t += 2
    ok = await http.post(
        "/_sec/verify?provider=crypto", json={"token": ch["token"], "answers": [solve(ch["nonce"])]}
    )
    assert ok.status_code == 200
    # with a valid sec_cpt the strict segment is no longer challenged
    after = await http.get("/protected/all", headers={"x-score": "40"})
    assert after.status_code == 200 and after.json()["report"]["action"] == "monitor"
    # forged cookie: back to the challenge (module fails 80 -> aggressive deny for slug all)
    forged = await http.get(
        "/protected/proof_of_work", headers={"cookie": f"bm_sz={SID}; sec_cpt={'f' * 32}~3~1"}
    )
    assert forged.status_code == 403


async def test_policy_selects_provider_and_duration(http: httpx.AsyncClient) -> None:
    await http.put(
        "/api/policy", json={"params": {"challenge_provider": "adaptive", "adaptive_count": 2}}
    )
    j = (await http.get("/protected/all", headers={"x-score": "40"})).json()
    assert j["provider"] == "adaptive" and j["count"] == 2
    assert j["report"]["challenge_provider"] == "adaptive"


async def test_default_duration_comes_from_policy_not_constructor() -> None:
    app = create_app(store=MemoryStore(), modules=[Scored(), ProofOfWork()])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        await c.put("/api/policy", json={"params": {"chlg_duration": 7}})
        j = (await c.get("/protected/all", headers={"x-score": "40"})).json()
        assert j["chlg_duration"] == 7


# -- cookieless arithmetic interstitial (bm-verify) -----------------------------------------

BASIC_RE = re.compile(r'var\s+j\s*=\s*i\s*\+\s*Number\("(\d+)"\s*\+\s*"(\d+)"\)')
USER_RE = BASIC_RE  # the pattern the user quoted
HTML = {"accept": "text/html"}


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


async def get_interstitial(http: httpx.AsyncClient, **params: str) -> str:
    r = await http.get("/akam/proof_of_work/interstitial", params=params)
    assert r.status_code == 200 and "text/html" in r.headers["content-type"]
    return r.text


async def test_interstitial_page_shape_and_correct_answer(
    http: httpx.AsyncClient, mod: ProofOfWork, make_ctx: Callable[..., RequestContext]
) -> None:
    page = await get_interstitial(http)
    assert "var i = " in page and BASIC_RE.search(page)
    assert "/_sec/verify?provider=interstitial" in page
    assert 'location.replace("/")' in page  # the on-demand route never reloads itself
    tok = token_of(page)
    assert tok.startswith("AAQ")  # the observed token prefix
    assert f"content=\"{REFRESH_SECONDS}; URL='/?bm-verify={tok}'\"" in page  # no-JS path
    r = await http.post(
        "/_sec/verify?provider=interstitial", json={"bm-verify": tok, "pow": basic_answer(page)}
    )
    assert r.status_code == 200 and r.json()["ok"] and r.json()["provider"] == "interstitial"
    assert "location" not in r.json()  # LOW flag pow_interstitial_location is off
    assert {"_abck", "ak_bmsc"} <= set(r.cookies)  # lab cookie issuance (bm_sz already sent)
    sig = await mod.evaluate(ctx_for(http, make_ctx))
    # a regex solves the basic page without JavaScript: WARN in the cautious band, never PASS
    assert sig.verdict == Verdict.WARN and sig.score == INTERSTITIAL_SCORE == 20
    assert "regex" in sig.reason
    assert await mod.challenge_satisfied(ctx_for(http, make_ctx), "interstitial")
    assert not await mod.challenge_satisfied(ctx_for(http, make_ctx), "crypto")


async def test_interstitial_failures_replay_session_expiry(
    http: httpx.AsyncClient, clock: Clock
) -> None:
    page = await get_interstitial(http)
    ans, tok = basic_answer(page), token_of(page)
    wrong = await http.post("/_sec/verify", json={"bm-verify": tok, "pow": ans + 1})
    assert wrong.status_code == 403 and wrong.json()["error"] == "wrong_answer"
    again = await http.post("/_sec/verify", json={"bm-verify": tok, "pow": ans})
    assert again.json()["error"] == "unknown_or_replayed"  # consumed by the failed attempt

    page = await get_interstitial(http)
    ok = await http.post(
        "/akam/proof_of_work/interstitial/verify",  # lab alias
        json={"bm-verify": token_of(page), "pow": basic_answer(page)},
    )
    assert ok.status_code == 200
    replay = await http.post(
        "/akam/proof_of_work/interstitial/verify",
        json={"bm-verify": token_of(page), "pow": basic_answer(page)},
    )
    assert replay.json()["error"] == "unknown_or_replayed"

    page = await get_interstitial(http)
    clock.t += 61
    exp = await http.post(
        "/_sec/verify?provider=interstitial",
        json={"bm-verify": token_of(page), "pow": basic_answer(page)},
    )
    assert exp.json()["error"] == "expired"

    page = await get_interstitial(http)
    http.cookies.set("bm_sz", "b" * 32 + "~00000000")
    other = await http.post(
        "/_sec/verify", json={"bm-verify": token_of(page), "pow": basic_answer(page)}
    )
    assert other.json()["error"] == "wrong_session"
    bad = await http.post("/_sec/verify", json={"bm-verify": "x", "pow": "nan"})
    assert bad.json()["error"] == "unknown_or_replayed"
    # provider mismatch: an interstitial token cannot be redeemed as crypto
    http.cookies.set("bm_sz", SID)
    page = await get_interstitial(http)
    mism = await http.post(
        "/_sec/verify?provider=crypto",
        json={"bm-verify": token_of(page), "pow": basic_answer(page)},
    )
    assert mism.json()["error"] == "wrong_provider"


async def test_interstitial_precedence_hard_beats_interstitial(
    http: httpx.AsyncClient, mod: ProofOfWork, clock: Clock, make_ctx: Callable[..., RequestContext]
) -> None:
    page = await get_interstitial(http)
    await http.post(
        "/_sec/verify?provider=interstitial",
        json={"bm-verify": token_of(page), "pow": basic_answer(page)},
    )
    assert (await mod.evaluate(ctx_for(http, make_ctx))).verdict == Verdict.WARN
    ch = await issue(http)
    clock.t += 2
    cookie = (await verify(http, ch)).cookies["sec_cpt"]
    sig = await mod.evaluate(ctx_for(http, make_ctx, cookies={"sec_cpt": cookie}))
    assert sig.verdict == Verdict.PASS  # hard > interstitial > none
    # a stale interstitial token never downgrades a solved hard challenge
    page = await get_interstitial(http)
    await http.post(
        "/_sec/verify?provider=interstitial",
        json={"bm-verify": token_of(page), "pow": basic_answer(page)},
    )
    sig = await mod.evaluate(ctx_for(http, make_ctx, cookies={"sec_cpt": cookie}))
    assert sig.verdict == Verdict.PASS


def test_safe_location_guard() -> None:
    from app.modules.proof_of_work import safe_location

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


async def test_basic_interstitial_numbers_follow_the_observed_shape(
    http: httpx.AsyncClient, clock: Clock
) -> None:
    """Observed: ``var i = 1789910678; var j = i + Number("3886" + "11036");`` where i is the
    issuing Unix time (2026-09-20 UTC) and the answer no longer fits a 32-bit int."""
    clock.t = 1789910678.4
    page = await get_interstitial(http)
    i = int(re.search(r"var i = (\d+);", page).group(1))  # type: ignore[union-attr]
    a, b = BASIC_RE.search(page).groups()  # type: ignore[union-attr]
    assert i == 1789910678 and (len(a), len(b)) == (4, 5)
    r = await http.post("/_sec/verify", json={"bm-verify": token_of(page), "pow": i + int(a + b)})
    assert r.status_code == 200


async def test_location_only_with_the_low_flag_and_same_origin(http: httpx.AsyncClient) -> None:
    page = await get_interstitial(http, return_to="/protected/all?x=1")
    r = await http.post(
        "/_sec/verify", json={"bm-verify": token_of(page), "pow": basic_answer(page)}
    )
    assert "location" not in r.json()  # off by default: the observed flow reloads
    await http.put("/api/flags/pow_interstitial_location", json={"value": True})
    page = await get_interstitial(http, return_to="/protected/all?x=1")
    r = await http.post(
        "/_sec/verify", json={"bm-verify": token_of(page), "pow": basic_answer(page)}
    )
    assert r.json()["location"] == "/protected/all?x=1"
    for evil in ("//evil.example/x", "https://evil.example/", "/\\evil.example"):
        page = await get_interstitial(http, return_to=evil)
        r = await http.post(
            "/_sec/verify", json={"bm-verify": token_of(page), "pow": basic_answer(page)}
        )
        assert r.status_code == 200 and "location" not in r.json()


async def test_cookieless_gate_serves_the_page_and_solving_clears_it(
    http: httpx.AsyncClient,
) -> None:
    assert "Protected Storefront" in (await http.get("/", headers={"accept": "text/html"})).text
    await http.put("/api/flags/pow_cookieless_gate", json={"value": True})
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
        v = await c.post(
            "/_sec/verify?provider=interstitial",
            json={"bm-verify": token_of(again.text), "pow": basic_answer(again.text)},
        )
        assert v.json()["ok"] and "location" not in v.json()  # the page just reloads
        after = await c.get("/", headers=HTML)  # the page's reload
        assert "Protected Storefront" in after.text
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        assert "Protected Storefront" in (await c.get("/")).text  # no text/html accept: not gated



async def test_solved_interstitial_is_monitored_not_rechallenged(http: httpx.AsyncClient) -> None:
    """WARN 20 sits in the cautious band: the protected page is served under monitoring (the
    captures show a cleared session getting the real page), but the signal never PASSes."""
    before = (await http.get("/protected/proof_of_work")).json()
    assert before["report"]["action"] == "challenge"  # unsolved: FAIL 45, strict band
    page = await get_interstitial(http)
    await http.post("/_sec/verify", json={"bm-verify": token_of(page), "pow": basic_answer(page)})
    report = (await http.get("/protected/proof_of_work")).json()["report"]
    sig = next(s for s in report["signals"] if s["module"] == "proof_of_work")
    assert (sig["verdict"], sig["score"]) == ("warn", INTERSTITIAL_SCORE)
    assert (report["segment"], report["action"]) == ("cautious", "monitor")


async def test_cookieless_gate_cleared_by_sec_cpt_or_validated_abck(
    http: httpx.AsyncClient, clock: Clock
) -> None:
    """Server-side proof clears the gate: a valid sec_cpt (hard proof of work) or an _abck the
    sensor flow validated, as well as a solved interstitial."""
    await http.put("/api/flags/pow_cookieless_gate", json={"value": True})
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
    await http.put("/api/flags/pow_cookieless_gate", json={"value": True})
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
    assert j["token"] == j["bm-verify"] and BASIC_RE.search(j["expression"])
    page = await http.get("/protected/all", headers={"x-score": "40", "accept": "text/html"})
    assert page.status_code == 200 and '"bm-verify"' in page.text
    r = await http.post(
        "/_sec/verify?provider=interstitial",
        json={"bm-verify": token_of(page.text), "pow": basic_answer(page.text)},
    )
    assert r.json()["ok"]
    after = await http.get("/protected/all", headers={"x-score": "40"})
    assert after.json()["report"]["action"] == "monitor"  # satisfied for the interstitial provider


async def test_hardened_breaks_fixed_regex_but_not_a_parser(http: httpx.AsyncClient) -> None:
    await http.put("/api/flags/pow_interstitial_hardened", json={"value": True})
    shapes = set()
    for _ in range(40):
        page = await get_interstitial(http)
        assert USER_RE.search(page) is None  # the user's pattern no longer matches
        js = script_of(page)
        shapes.add(re.sub(r"\d+", "N", re.split(r"fetch\(", js)[0]))
        r = await http.post(
            "/_sec/verify?provider=interstitial",
            json={"bm-verify": token_of(page), "pow": robust_answer(js.split("fetch(")[0])},
        )
        assert r.status_code == 200, (page, r.text)  # a parser-based solver still succeeds
    assert len(shapes) > 15  # genuinely varied shapes
    await http.put("/api/flags/pow_interstitial_hardened", json={"value": False})
    assert USER_RE.search(await get_interstitial(http))  # and the basic page matches again


async def test_hardened_stale_regex_answer_is_wrong(http: httpx.AsyncClient) -> None:
    """A solver that falls back to the basic shape's regex on hardened output has no match,
    and answering with a stale/basic value is rejected."""
    basic = await get_interstitial(http)
    stale = basic_answer(basic)
    await http.put("/api/flags/pow_interstitial_hardened", json={"value": True})
    page = await get_interstitial(http)
    assert BASIC_RE.search(page) is None
    r = await http.post("/_sec/verify", json={"bm-verify": token_of(page), "pow": stale})
    assert r.status_code == 403 and r.json()["error"] == "wrong_answer"


async def test_legacy_challenge_route_serves_interstitial_json(http: httpx.AsyncClient) -> None:
    j = (await http.get("/akam/proof_of_work/challenge?variant=interstitial")).json()
    assert (
        j["provider"] == "interstitial" and j["bm-verify"] == j["token"] and j["hardened"] is False
    )
    no_sid = httpx.AsyncClient(transport=httpx.ASGITransport(app=http.app), base_url="http://t")  # type: ignore[attr-defined]
    async with no_sid:
        assert (await no_sid.get("/akam/proof_of_work/interstitial")).status_code == 400


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
        await http.put("/api/flags/pow_interstitial_hardened", json={"value": True})
    pages = [await get_interstitial(http) for _ in range(6 if hardened else 1)]
    first = run_in_node(script_of(pages[0]))
    if first is None:
        pytest.skip("docker with node:20-alpine is not available")
    for page in pages:
        cap = run_in_node(script_of(page))
        assert cap is not None and cap["bm-verify"] == token_of(page)
        r = await http.post("/_sec/verify?provider=interstitial", json=cap)
        assert r.status_code == 200 and r.json()["ok"], (page, cap, r.text)


async def test_challenge_satisfied_is_scoped_to_own_providers(
    mod: ProofOfWork, make_ctx: Callable[..., RequestContext], memory_store: MemoryStore
) -> None:
    """A valid crypto sec_cpt must not waive another module's challenge (e.g. interactive)."""
    cookie = "f" * 32 + "~3~1000"
    await memory_store.set(f"pow:{SID}", json.dumps({"cookie": cookie, "solved_at": 1000.0}))
    ctx = make_ctx(session_id=SID, cookies={"sec_cpt": cookie})
    assert await mod.challenge_satisfied(ctx, "crypto")
    assert await mod.challenge_satisfied(ctx, "interstitial")  # hard PoW is stronger
    assert await mod.challenge_satisfied(ctx, None)
    assert not await mod.challenge_satisfied(ctx, "interactive")


ARITH = 'var i = 1; var j = i + Number("2" + "3");'


def test_interstitial_script_reloads_except_on_the_on_demand_route() -> None:
    """The gate's page reloads (as observed); reloading /akam/proof_of_work/interstitial would
    mint a fresh page forever, so that route's page goes to its return path instead."""
    from app.modules.proof_of_work import render_interstitial

    gate = render_interstitial("TOK", ARITH, "j", refresh_url="/x?bm-verify=TOK")
    assert "location.reload()" in gate and "location.replace(l)" in gate  # location: LOW flag
    assert "content=\"5; URL='/x?bm-verify=TOK'\"" in gate
    demand = render_interstitial("TOK", ARITH, "j", refresh_url="/?bm-verify=TOK", after="/x")
    assert 'location.replace("/x")' in demand and "location.reload()" not in demand


def test_interstitial_page_escapes_the_challenged_url() -> None:
    from app.modules.proof_of_work import render_interstitial, with_token

    evil = "/p\"><script>alert(1)</script>?q='x"
    page = render_interstitial("TOK", ARITH, "j", refresh_url=with_token(evil, "TOK"), after=evil)
    assert "<script>alert(1)" not in page and page.count("</script>") == 1
    assert with_token("/a?bm-verify=old&x=1", "NEW") == "/a?x=1&bm-verify=NEW"
