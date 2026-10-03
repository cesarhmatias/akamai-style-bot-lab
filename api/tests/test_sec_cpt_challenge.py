"""sec_cpt challenge providers: crypto / behavioral / adaptive, 428 JSON vs iframe page,
chlg_duration, sec_cpt validation, re-challenge interval and safeguard interplay."""

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
from app.modules.sec_cpt_challenge import SecCptChallenge, sec_cpt_state, sub_nonce
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
def mod(clock: Clock) -> SecCptChallenge:
    return SecCptChallenge(
        rng=random.Random(1), clock=clock, difficulty=DIFF, duration=2, interval=600
    )


@pytest_asyncio.fixture
async def http(mod: SecCptChallenge) -> AsyncIterator[httpx.AsyncClient]:
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


async def issue(http: httpx.AsyncClient, provider: str = "crypto") -> dict:
    r = await http.get("/akam/sec_cpt_challenge/challenge", params={"provider": provider})
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
    http: httpx.AsyncClient,
    mod: SecCptChallenge,
    clock: Clock,
    make_ctx: Callable[..., RequestContext],
) -> None:
    ch = await issue(http)
    assert ch["provider"] == "crypto" and ch["chlg_duration"] == 2 and ch["difficulty"] == DIFF
    assert "count" not in ch and "variant" not in ch
    early = await verify(http, ch)  # correct answer, but no waiting
    assert early.status_code == 403 and early.json()["error"] == "too_early"
    assert early.json()["retry_after"] > 0
    ch = await issue(http)
    clock.t += 2
    ok = await verify(http, ch)
    assert ok.status_code == 200 and ok.json() == {"ok": True, "provider": "crypto"}
    cookie = ok.cookies["sec_cpt"]
    assert "~3~" in cookie
    sig = await mod.evaluate(ctx_for(http, make_ctx, cookies={"sec_cpt": cookie}))
    assert sig.verdict == Verdict.PASS and "sec_cpt" in sig.reason


async def test_sec_cpt_is_validated_and_forgery_fails(
    http: httpx.AsyncClient,
    mod: SecCptChallenge,
    clock: Clock,
    make_ctx: Callable[..., RequestContext],
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
    assert other.verdict == Verdict.FAIL and "no sec_cpt challenge solved" in other.reason


async def test_rechallenge_after_interval(
    http: httpx.AsyncClient,
    mod: SecCptChallenge,
    clock: Clock,
    make_ctx: Callable[..., RequestContext],
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
    no_session = await http.post("/_sec/verify", json={"token": "x"})
    assert no_session.status_code == 400 and no_session.json()["error"] == "no_session"
    assert (await http.get("/akam/sec_cpt_challenge/challenge")).status_code == 400


async def test_bad_requests(http: httpx.AsyncClient) -> None:
    for body in ({"json": {"x": 1}}, {"json": [1]}, {"content": b"not json"}):
        r = await http.post("/_sec/verify", **body)  # type: ignore[arg-type]
        assert r.status_code == 400 and r.json()["error"] == "bad_request"
    assert (await http.get("/akam/sec_cpt_challenge/challenge?provider=nope")).status_code == 400
    ch = await issue(http)
    r = await http.post("/_sec/verify", json={"token": ch["token"], "answers": ["x"]})
    assert r.json()["error"] == "bad_answer"


async def test_unknown_token_is_answered_like_a_replay(http: httpx.AsyncClient) -> None:
    for url in ("/_sec/verify", "/_sec/verify?provider=crypto", "/_sec/cp_challenge/verify"):
        r = await http.post(url, json={"token": "f" * 32, "answer": 1})
        assert r.status_code == 403 and r.json()["error"] == "unknown_or_replayed"


async def test_unsolved_fails(
    mod: SecCptChallenge, make_ctx: Callable[..., RequestContext]
) -> None:
    sig = await mod.evaluate(make_ctx(session_id=SID))
    assert sig.verdict == Verdict.FAIL and sig.score == 45
    assert mod.confidence.value == "medium"


async def test_js_served_everywhere(http: httpx.AsyncClient) -> None:
    for url in ("/akam/sec_cpt_challenge/sec-cpt.js", "/_sec/cp_challenge/sec-cpt-1.0.js"):
        r = await http.get(url)
        assert "__akSecCptDone" in r.text and "sec-cpt-if" in r.text
    assert "Checking" in (await http.get("/_sec/cp_challenge/message.htm")).text


async def test_sec_cpt_state_reads_the_policy_interval(
    http: httpx.AsyncClient, clock: Clock, make_ctx: Callable[..., RequestContext]
) -> None:
    """The helper other modules use: without an explicit interval it takes the policy's."""
    assert (await sec_cpt_state(make_ctx(), clock()))[0] == "none"  # no session at all
    ch = await issue(http)
    clock.t += 2
    cookie = (await verify(http, ch)).cookies["sec_cpt"]
    ctx = ctx_for(http, make_ctx, cookies={"sec_cpt": cookie})
    assert (await sec_cpt_state(ctx, clock()))[0] == "ok"
    await http.put("/api/policy", json={"params": {"challenge_interval": 5}})
    state, details = await sec_cpt_state(ctx, clock() + 6)
    assert state == "expired" and details["interval"] == 5


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


async def test_challenge_action_428_json_vs_iframe_page(
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
    # forged cookie: back to the challenge (module fails 80 -> aggressive deny for the case)
    forged = await http.get(
        "/protected/sec_cpt_challenge", headers={"cookie": f"bm_sz={SID}; sec_cpt={'f' * 32}~3~1"}
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
    app = create_app(store=MemoryStore(), modules=[Scored(), SecCptChallenge()])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        await c.put("/api/policy", json={"params": {"chlg_duration": 7}})
        j = (await c.get("/protected/all", headers={"x-score": "40"})).json()
        assert j["chlg_duration"] == 7


async def test_challenge_satisfied_is_scoped_to_own_providers(
    mod: SecCptChallenge, make_ctx: Callable[..., RequestContext], memory_store: MemoryStore
) -> None:
    """A valid sec_cpt must not waive another module's challenge (tile game, interstitial):
    the module that serves a provider decides what satisfies it."""
    cookie = "f" * 32 + "~3~1000"
    await memory_store.set(f"sec_cpt:{SID}", json.dumps({"cookie": cookie, "solved_at": 1000.0}))
    ctx = make_ctx(session_id=SID, cookies={"sec_cpt": cookie})
    for provider in ("crypto", "behavioral", "adaptive", None):
        assert await mod.challenge_satisfied(ctx, provider)
    for provider in ("interactive", "interstitial"):
        assert not await mod.challenge_satisfied(ctx, provider)


@pytest.mark.parametrize("provider", ["crypto", "adaptive"])
async def test_a_solve_clears_the_safeguard_counter(
    http: httpx.AsyncClient, clock: Clock, provider: str
) -> None:
    store = http.app.state.store  # type: ignore[attr-defined]
    await store.set(f"sensor:n:{SID}", "1")
    await http.put("/api/policy", json={"params": {"challenge_provider": provider}})
    for _ in range(2):  # two unsolved challenges are counted
        assert (await http.get("/protected/all", headers={"x-score": "40"})).status_code == 428
    ch = await issue(http, provider)
    clock.t += 2
    assert (await verify(http, ch)).status_code == 200
    for _ in range(3):  # the counter restarted: still challenged, not safeguarded yet
        http.cookies.delete("sec_cpt")
        r = await http.get("/protected/all", headers={"x-score": "40"})
        assert r.json()["report"]["action"] == "challenge"
