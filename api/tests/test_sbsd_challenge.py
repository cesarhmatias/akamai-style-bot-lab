from __future__ import annotations

import json
import random
import re
import shutil
import subprocess
from collections.abc import AsyncIterator, Callable

import httpx
import pytest
import pytest_asyncio
from app.contract import RequestContext, Verdict
from app.modules.sbsd_challenge import (
    M32,
    SbsdChallenge,
    apply_op,
    expected_answer,
    generate_spec,
    render_js,
)
from app.store import MemoryStore
from fastapi import FastAPI

SID = "f" * 32 + "~abcdef01"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36"
P = "/akam/sbsd_challenge"

NODE = shutil.which("node")
DOCKER_NODE = False
if not NODE and shutil.which("docker"):
    DOCKER_NODE = (
        subprocess.run(
            ["docker", "image", "inspect", "node:20-alpine"], capture_output=True
        ).returncode
        == 0
    )

HARNESS = r"""
const fs = require('fs');
const code = fs.readFileSync(0, 'utf8');
const ua = process.argv[1];
let captured = null;
const mkEl = () => { const a = {}; return {
  setAttribute(k, v) { a[k] = String(v); }, getAttribute(k) { return a[k]; }, textContent: '' }; };
const doc = { title: 'orig', createElement: mkEl };
const win = { dispatchEvent() {} };
global.CustomEvent = function () {};
new Function('document', 'navigator', 'window', 'fetch', 'CustomEvent', code)(
  doc, { userAgent: ua }, win,
  (u, o) => { captured = JSON.parse(o.body); return Promise.resolve({ ok: true }); },
  global.CustomEvent);
console.log(JSON.stringify(captured));
"""


def run_js(code: str, ua: str) -> dict:
    if NODE:
        cmd = [NODE, "-e", HARNESS, ua]
    else:
        cmd = ["docker", "run", "--rm", "-i", "node:20-alpine", "node", "-e", HARNESS, ua]
    out = subprocess.run(cmd, input=code, capture_output=True, text=True, timeout=60, check=True)
    return json.loads(out.stdout.strip().splitlines()[-1])


@pytest_asyncio.fixture
async def mod() -> SbsdChallenge:
    return SbsdChallenge(rng=random.Random(7), clock=lambda: 1234.0)


@pytest_asyncio.fixture
async def http(mod: SbsdChallenge, memory_store: MemoryStore) -> AsyncIterator[httpx.AsyncClient]:
    app = FastAPI()
    app.state.store = memory_store
    app.include_router(mod.router(), prefix=P)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://t",
        cookies={"bm_sz": SID},
        headers={"user-agent": UA},
    ) as c:
        yield c


def spec_of(seed: int, v: str = "x") -> dict:
    return generate_spec(random.Random(seed), v)


def test_ops_wrap_32bit() -> None:
    assert apply_op("add", M32, 1, 0) == 0
    assert apply_op("sub", 0, 1, 0) == M32
    assert apply_op("imul", 0x80000001, 3, 0) == (0x80000001 * 3) & M32
    assert apply_op("rotl", 0x80000000, 1, 1) == 1
    assert apply_op("xorshr", 0xF0, 4, 4) == 0xF0 ^ 0x0F
    assert apply_op("and", 0xFF, 0x0F, 0) == 0x0F
    assert apply_op("or", 0xF0, 0x0F, 0) == 0xFF
    assert apply_op("xor", 0xFF, 0x0F, 0) == 0xF0


def test_spec_deterministic_and_rotates() -> None:
    assert spec_of(1) == spec_of(1)
    assert spec_of(1) != spec_of(2)
    assert expected_answer(spec_of(1), UA) != expected_answer(spec_of(2), UA)


def test_answer_depends_on_ua() -> None:
    s = spec_of(3)
    answers = {expected_answer(s, UA + "a" * n) for n in range(20)}
    assert len(answers) > 1


def test_js_randomised() -> None:
    a, b = render_js(spec_of(1), "/v"), render_js(spec_of(2), "/v")
    assert a != b
    assert "__akSbsdDone" in a and "ak:sbsd" in a


async def solve(http: httpx.AsyncClient, v: str = "") -> tuple[dict, str]:
    r = await http.get(f"{P}/sbsd.js", params={"v": v} if v else {})
    assert r.status_code == 200
    src = r.text
    # recover the spec through the store the server uses
    app = http._transport.app  # type: ignore[attr-defined]
    spec = json.loads(await app.state.store.get(f"sbsd:spec:{SID}"))
    return spec, src


async def test_verify_success(
    http: httpx.AsyncClient, mod: SbsdChallenge, make_ctx: Callable[..., RequestContext]
) -> None:
    spec, _ = await solve(http)
    r = await http.post(f"{P}/verify", json={"t": expected_answer(spec, UA), "v": spec["v"]})
    assert r.status_code == 200 and "sbsd_o" in r.cookies
    assert (await mod.evaluate(make_ctx(session_id=SID))).verdict == Verdict.PASS
    # single use
    r = await http.post(f"{P}/verify", json={"t": expected_answer(spec, UA), "v": spec["v"]})
    assert r.status_code == 403


async def test_wrong_answer_and_unsolved(
    http: httpx.AsyncClient, mod: SbsdChallenge, make_ctx: Callable[..., RequestContext]
) -> None:
    spec, _ = await solve(http)
    r = await http.post(f"{P}/verify", json={"t": expected_answer(spec, UA) ^ 1, "v": spec["v"]})
    assert r.status_code == 403
    sig = await mod.evaluate(make_ctx(session_id=SID))
    assert sig.verdict == Verdict.FAIL and sig.score == 80


async def test_old_v_rejected_and_rotation(http: httpx.AsyncClient) -> None:
    spec1, src1 = await solve(http)
    spec2, src2 = await solve(http)
    assert spec1["v"] != spec2["v"] and src1 != src2
    r = await http.post(f"{P}/verify", json={"t": expected_answer(spec1, UA), "v": spec1["v"]})
    assert r.status_code == 403 and r.json()["error"] == "stale_v"
    r = await http.post(f"{P}/verify", json={"t": expected_answer(spec2, UA), "v": spec2["v"]})
    assert r.status_code == 200


async def test_per_session_rotation(http: httpx.AsyncClient) -> None:
    _, src1 = await solve(http)
    http.cookies.set("bm_sz", "9" * 32 + "~11111111")
    r = await http.get(f"{P}/sbsd.js")
    assert r.text != src1


async def test_client_v_honoured_and_bad_body(http: httpx.AsyncClient) -> None:
    v = "12345678-1234-4234-8234-123456789abc"
    spec, src = await solve(http, v)
    assert spec["v"] == v and v in src
    assert (await http.post(f"{P}/verify", json={"t": "x"})).status_code == 400
    http.cookies.clear()
    assert (await http.get(f"{P}/sbsd.js")).status_code == 400


@pytest.mark.skipif(not (NODE or DOCKER_NODE), reason="node not available")
@pytest.mark.parametrize("seed", range(8))
def test_generated_js_matches_python(seed: int) -> None:
    spec = spec_of(seed, "11111111-1111-4111-8111-111111111111")
    out = run_js(render_js(spec, "/akam/sbsd_challenge/verify"), UA)
    assert out["v"] == spec["v"]
    assert out["t"] == expected_answer(spec, UA)
    assert re.fullmatch(r"\d+", str(out["t"]))
