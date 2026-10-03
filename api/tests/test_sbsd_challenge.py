from __future__ import annotations

import json
import random
import re
import shutil
import subprocess
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager

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


# -- vendor-described flow (flag sbsd_vendor_flow, LOW) ------------------------------------------

import base64  # noqa: E402

from app.main import create_app  # noqa: E402
from app.modules.sbsd_challenge import (  # noqa: E402
    VENDOR_COOKIES,
    encode_body,
    random_path,
    render_vendor_js,
)

VUA = {"user-agent": UA}


@asynccontextmanager
async def vendor_client() -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(store=MemoryStore(), modules=[SbsdChallenge(rng=random.Random(5))])
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://t",
        headers=VUA,
        cookies={"bm_sz": SID},
    ) as c:
        await c.put("/api/flags/sbsd_vendor_flow", json={"value": True})
        yield c


def snippet(page: str) -> tuple[str, str]:
    m = re.search(r'<script src="(/[\w/]+)\?v=([0-9a-f-]{36})(?:&t=(\w+))?"', page)
    assert m, page
    return m.group(1), m.group(2)


def client_body(store_rec: dict, ua: str, o: str, v: str, i: int) -> dict:
    t = expected_answer(store_rec["spec"], ua)
    return {"body": encode_body({"t": t, "v": v, "o": o, "i": i})}


async def fetch_script(c: httpx.AsyncClient, path: str, v: str, **q: str) -> httpx.Response:
    return await c.get(path, params={"v": v, **q})


async def test_flag_off_keeps_the_lab_device_and_declares_the_flag() -> None:
    app = create_app(store=MemoryStore(), modules=[SbsdChallenge()])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        page = await c.get("/")
        assert '<script src="/akam/sbsd_challenge/sbsd.js" defer></script>' in page.text
        flag = next(
            f for f in (await c.get("/api/flags")).json() if f["name"] == "sbsd_vendor_flow"
        )
        assert flag["default"] is False and flag["confidence"] == "low" and flag["value"] is False
        mod = next(m for m in (await c.get("/api/modules")).json() if m["slug"] == "sbsd_challenge")
        assert mod["confidence"] == "low"
        assert (await c.get("/akam/sbsd_challenge/blocking")).status_code == 404


async def test_vendor_passive_flow_two_posts_and_cookies() -> None:
    async with vendor_client() as c:
        store = c._transport.app.state.store  # type: ignore[attr-defined]
        page = await c.get("/")
        path, v = snippet(page.text)
        assert "sbsd.js" not in page.text and path.count("/") >= 3
        script = await fetch_script(c, path, v)
        assert script.status_code == 200 and "javascript" in script.headers["content-type"]
        o = script.cookies["sbsd_o"]  # issued FIRST, with the script response
        assert await store.get(f"sbsd:{SID}") is None
        rec = json.loads(await store.get(f"sbsd:vspec:{SID}"))
        assert rec["mode"] == "passive"
        # index 1 before index 0 is rejected and restarts the issuance
        early = await c.post(path, json=client_body(rec, UA, o, v, 1))
        assert early.status_code == 403 and early.json()["error"] == "bad_index"
        await fetch_script(c, path, v)
        rec = json.loads(await store.get(f"sbsd:vspec:{SID}"))
        o = c.cookies["sbsd_o"]
        r0 = await c.post(path, json=client_body(rec, UA, o, v, 0))
        assert r0.status_code == 200 and r0.json() == {"ok": True, "next": 1}
        assert not any(k in r0.cookies for k in VENDOR_COOKIES)
        r1 = await c.post(path, json=client_body(rec, UA, o, v, 1))
        assert r1.status_code == 200 and r1.json()["ok"]
        assert set(VENDOR_COOKIES) <= set(r1.cookies)
        assert "Max-Age=3600" in next(
            h for h in r1.headers.get_list("set-cookie") if h.startswith("bm_ss=")
        )
        assert await store.get(f"sbsd:{SID}") == "ok"
        sig = (await c.get("/protected/sbsd_challenge")).json()["report"]["signals"][0]
        assert sig["verdict"] == "pass" and sig["confidence"] == "low"


async def test_vendor_rejects_wrong_input() -> None:
    async with vendor_client() as c:
        store = c._transport.app.state.store  # type: ignore[attr-defined]
        path, v = snippet((await c.get("/")).text)

        async def issue() -> tuple[dict, str]:
            await fetch_script(c, path, v)
            return json.loads(await store.get(f"sbsd:vspec:{SID}")), c.cookies["sbsd_o"]

        rec, o = await issue()
        bad_o = await c.post(path, json=client_body(rec, UA, "forged~1", v, 0))
        assert bad_o.json()["error"] == "sbsd_o_mismatch"
        rec, o = await issue()
        wrong = {"body": encode_body({"t": 1, "v": v, "o": o, "i": 0})}
        assert (await c.post(path, json=wrong)).json()["error"] == "wrong_answer"
        rec, o = await issue()
        stale = await c.post(path, json=client_body(rec, UA, o, "0" * 8 + v[8:], 0))
        assert stale.json()["error"] == "stale_v"
        rec, o = await issue()
        c.cookies.delete("sbsd_o")  # cookie not kept: the payload cannot be tied to it
        assert (await c.post(path, json=client_body(rec, UA, o, v, 0))).json()[
            "error"
        ] == "sbsd_o_mismatch"
        assert (await c.post(path, json={"body": "!!"})).status_code == 400
        assert (await c.post(path, json={"x": 1})).status_code == 400
        assert (await c.post(path, json=client_body(rec, UA, o, v, 0))).json()[
            "error"
        ] == "no_challenge"
        # an unrelated path is not claimed
        assert (await c.get("/some/other/path")).status_code == 404
        # unverified answer never passed
        assert await store.get(f"sbsd:{SID}") is None


async def test_vendor_blocking_mode_single_post_with_token() -> None:
    async with vendor_client() as c:
        store = c._transport.app.state.store  # type: ignore[attr-defined]
        page = await c.get("/akam/sbsd_challenge/blocking")
        assert page.status_code == 200 and "&t=" in page.text
        path, v = snippet(page.text)
        token = re.search(r"&t=(\w+)", page.text).group(1)  # type: ignore[union-attr]
        assert (await fetch_script(c, path, v, t="wrong")).status_code == 403
        script = await fetch_script(c, path, v, t=token)
        assert script.status_code == 200 and f"?t={token}" in script.text
        o = script.cookies["sbsd_o"]
        rec = json.loads(await store.get(f"sbsd:vspec:{SID}"))
        assert rec["mode"] == "blocking"
        bad = await c.post(path, params={"t": "nope"}, json=client_body(rec, UA, o, v, 0))
        assert bad.json()["error"] == "bad_token"
        await fetch_script(c, path, v, t=token)
        rec = json.loads(await store.get(f"sbsd:vspec:{SID}"))
        ok = await c.post(
            path, params={"t": token}, json=client_body(rec, UA, c.cookies["sbsd_o"], v, 0)
        )
        assert ok.status_code == 200 and set(VENDOR_COOKIES) <= set(ok.cookies)
        assert await store.get(f"sbsd:{SID}") == "ok"


async def test_vendor_blocking_via_challenge_provider_hook(
    make_ctx: Callable[..., RequestContext], memory_store: MemoryStore
) -> None:
    mod = SbsdChallenge(rng=random.Random(1))
    assert mod.challenge_providers == frozenset({"sbsd"})
    off = make_ctx(session_id=SID, flags={})
    assert await mod.issue_challenge(None, off, "sbsd", html=True) is None  # flag off
    on = make_ctx(session_id=SID, flags={"sbsd_vendor_flow": True})
    assert await mod.issue_challenge(None, on, "sbsd", html=False) is None  # HTML only
    assert await mod.issue_challenge(None, on, "crypto", html=True) is None
    resp = await mod.issue_challenge(None, on, "sbsd", html=True)
    assert resp is not None and b"&t=" in bytes(resp.body)


def test_vendor_js_shape_and_helpers() -> None:
    spec = generate_spec(random.Random(2), "11111111-2222-4333-8444-555555555555")
    passive = render_vendor_js(spec, "/a/b/c", "passive")
    assert "send(0).then(function(){return send(1)})" in passive and "sbsd_o" in passive
    assert '"/a/b/c"' in passive and "bm_so" in passive
    blocking = render_vendor_js(spec, "/a/b/c", "blocking", "tok123")
    assert '"/a/b/c?t=tok123"' in blocking and "location.reload()" in blocking
    assert json.loads(base64.b64decode(encode_body({"t": 1}))) == {"t": 1}
    p = random_path(random.Random(1))
    assert p.startswith("/") and 3 <= p.count("/") <= 5


VENDOR_HARNESS = r"""
const fs = require('fs');
const code = fs.readFileSync(0, 'utf8');
const ua = process.argv[1];
const sent = [];
const mkEl = () => { const a = {}; return {
  setAttribute(k, v) { a[k] = String(v); }, getAttribute(k) { return a[k]; }, textContent: '' }; };
const doc = { title: 'orig', createElement: mkEl, cookie: 'x=1; sbsd_o=abc123~99' };
const win = { dispatchEvent() {} };
global.CustomEvent = function () {};
global.btoa = (s) => Buffer.from(s, 'binary').toString('base64');
global.location = { reload() {} };
new Function('document', 'navigator', 'window', 'fetch', 'CustomEvent', code)(
  doc, { userAgent: ua }, win,
  (u, o) => { sent.push({ url: u, body: JSON.parse(o.body) });
              return Promise.resolve({ json: () => Promise.resolve({ ok: true }) }); },
  global.CustomEvent);
setTimeout(() => console.log(JSON.stringify(sent)), 50);
"""


@pytest.mark.skipif(not (NODE or DOCKER_NODE), reason="node (or docker node:20-alpine) unavailable")
@pytest.mark.parametrize("mode", ["passive", "blocking"])
def test_vendor_js_runs_and_sends_the_expected_payload(mode: str) -> None:
    spec = generate_spec(random.Random(9), "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
    js = render_vendor_js(spec, "/p/q/r", mode, "TOK")
    cmd = (
        [NODE, "-e", VENDOR_HARNESS, UA]
        if NODE
        else [
            "docker",
            "run",
            "--rm",
            "-i",
            "--network",
            "none",
            "node:20-alpine",
            "node",
            "-e",
            VENDOR_HARNESS,
            UA,
        ]
    )
    proc = subprocess.run(cmd, input=js, capture_output=True, text=True, timeout=90)
    out = proc.stdout.strip() if proc.returncode == 0 else ""
    assert out
    sent = json.loads(out)
    expect_n = 2 if mode == "passive" else 1
    assert len(sent) == expect_n
    assert sent[0]["url"] == ("/p/q/r" if mode == "passive" else "/p/q/r?t=TOK")
    for i, s in enumerate(sent):
        payload = json.loads(base64.b64decode(s["body"]["body"]))
        assert payload == {
            "t": expected_answer(spec, UA),
            "v": spec["v"],
            "o": "abc123~99",
            "i": i,
        }
