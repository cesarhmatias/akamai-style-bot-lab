from __future__ import annotations

import hashlib
import random
from collections.abc import AsyncIterator, Callable

import httpx
import pytest
import pytest_asyncio
from app.contract import RequestContext, Verdict
from app.modules.proof_of_work import ProofOfWork, eval_expression
from app.store import MemoryStore
from fastapi import FastAPI

SID = "a" * 32 + "~deadbeef"


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
    return ProofOfWork(rng=random.Random(1), clock=clock, difficulty=3)


@pytest_asyncio.fixture
async def http(mod: ProofOfWork, memory_store: MemoryStore) -> AsyncIterator[httpx.AsyncClient]:
    app = FastAPI()
    app.state.store = memory_store
    app.include_router(mod.router(), prefix="/akam/proof_of_work")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://t", cookies={"bm_sz": SID}
    ) as c:
        yield c


def solve_hard(nonce: str, difficulty: int) -> int:
    i = 0
    while not hashlib.sha256(f"{nonce}{i}".encode()).hexdigest().startswith("0" * difficulty):
        i += 1
    return i


async def get(http: httpx.AsyncClient, variant: str) -> dict:
    r = await http.get(f"/akam/proof_of_work/challenge?variant={variant}")
    assert r.status_code == 200
    return r.json()


def test_eval_expression() -> None:
    assert eval_expression("2 + 3 * 4") == 14
    assert eval_expression("10 - 3 - 2") == 5
    assert eval_expression("2 * 3 - 4 * 5") == -14


async def test_hard_flow_pass(
    http: httpx.AsyncClient, mod: ProofOfWork, make_ctx: Callable[..., RequestContext]
) -> None:
    ch = await get(http, "hard")
    assert ch["variant"] == "hard" and ch["difficulty"] == 3
    r = await http.post(
        "/akam/proof_of_work/verify",
        json={"challenge_id": ch["challenge_id"], "answer": solve_hard(ch["nonce"], 3)},
    )
    assert r.status_code == 200 and r.json()["ok"]
    cookie = r.cookies["sec_cpt"]
    assert cookie.split("~")[1] == "3" and cookie.split("~")[2] == "1000"
    sig = await mod.evaluate(make_ctx(session_id=SID))
    assert sig.verdict == Verdict.PASS


async def test_default_variant_is_hard(http: httpx.AsyncClient) -> None:
    r = await http.get("/akam/proof_of_work/challenge")
    assert r.json()["variant"] == "hard"


async def test_no_session(http: httpx.AsyncClient) -> None:
    http.cookies.clear()
    assert (await http.get("/akam/proof_of_work/challenge")).status_code == 400


async def test_wrong_answer_and_replay(http: httpx.AsyncClient, mod: ProofOfWork) -> None:
    ch = await get(http, "hard")
    bad = solve_hard(ch["nonce"], 3) + 1
    while hashlib.sha256(f"{ch['nonce']}{bad}".encode()).hexdigest().startswith("000"):
        bad += 1
    r = await http.post(
        "/akam/proof_of_work/verify", json={"challenge_id": ch["challenge_id"], "answer": bad}
    )
    assert r.status_code == 403
    good = await http.post(
        "/akam/proof_of_work/verify",
        json={"challenge_id": ch["challenge_id"], "answer": solve_hard(ch["nonce"], 3)},
    )
    assert good.status_code == 403  # consumed by the failed attempt


async def test_replay_after_success(http: httpx.AsyncClient) -> None:
    ch = await get(http, "hard")
    body = {"challenge_id": ch["challenge_id"], "answer": solve_hard(ch["nonce"], 3)}
    assert (await http.post("/akam/proof_of_work/verify", json=body)).status_code == 200
    r = await http.post("/akam/proof_of_work/verify", json=body)
    assert r.status_code == 403 and r.json()["error"] == "unknown_or_replayed"


async def test_expired(http: httpx.AsyncClient, clock: Clock) -> None:
    ch = await get(http, "hard")
    clock.t += 61
    r = await http.post(
        "/akam/proof_of_work/verify",
        json={"challenge_id": ch["challenge_id"], "answer": solve_hard(ch["nonce"], 3)},
    )
    assert r.status_code == 403 and r.json()["error"] == "expired"


async def test_other_session_rejected(http: httpx.AsyncClient) -> None:
    ch = await get(http, "hard")
    http.cookies.set("bm_sz", "b" * 32 + "~00000000")
    r = await http.post(
        "/akam/proof_of_work/verify",
        json={"challenge_id": ch["challenge_id"], "answer": solve_hard(ch["nonce"], 3)},
    )
    assert r.status_code == 403 and r.json()["error"] == "wrong_session"


async def test_simple_only_warns(
    http: httpx.AsyncClient, mod: ProofOfWork, make_ctx: Callable[..., RequestContext]
) -> None:
    ch = await get(http, "simple")
    r = await http.post(
        "/akam/proof_of_work/verify",
        json={"challenge_id": ch["challenge_id"], "answer": eval_expression(ch["expression"])},
    )
    assert r.json()["ok"] and "sec_cpt" in r.cookies
    sig = await mod.evaluate(make_ctx(session_id=SID))
    assert sig.verdict == Verdict.WARN and sig.score < 50


async def test_unsolved_fails(mod: ProofOfWork, make_ctx: Callable[..., RequestContext]) -> None:
    sig = await mod.evaluate(make_ctx(session_id=SID))
    assert sig.verdict == Verdict.FAIL and sig.score == 80


async def test_bad_body(http: httpx.AsyncClient) -> None:
    assert (await http.post("/akam/proof_of_work/verify", json={"x": 1})).status_code == 400


async def test_js_served(http: httpx.AsyncClient) -> None:
    r = await http.get("/akam/proof_of_work/pow.js")
    assert "__akPowDone" in r.text and "ak:pow" in r.text
