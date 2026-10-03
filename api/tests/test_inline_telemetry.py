from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
from app.contract import EndpointClass, RequestContext, Verdict
from app.main import create_app
from app.modules.inline_telemetry import (
    HEADER_NAME,
    MAX_AGE_MS,
    InlineTelemetryModule,
    build_header,
    parse_header,
    request_hash,
    telemetry_key,
    verify_header,
)
from app.store import MemoryStore
from browser_stub import run_js

SID = "E" * 32 + "~YAAQIT~1~2"
NOW = 1_800_000_000.0
BODY = b'{"user":"alice","password":"hunter2"}'
PAYLOAD = {
    "v": 1,
    "t0": 10.0,
    "t1": 900.0,
    "mouse": [],
    "keys": [[100.0, 80.0]],
    "counts": {"key": 1},
}


def clock_at(t: float) -> Callable[[], float]:
    return lambda: t


def mk(clock: float = NOW) -> InlineTelemetryModule:
    return InlineTelemetryModule(clock=clock_at(clock))


def ctx_with(
    make_ctx: Callable[..., RequestContext],
    header: str | None,
    *,
    sid: str = SID,
    method: str = "POST",
    path: str = "/api/login",
    body: bytes = BODY,
) -> RequestContext:
    headers = [("user-agent", "UA")] + ([(HEADER_NAME, header)] if header is not None else [])
    return make_ctx(
        session_id=sid,
        method=method,
        path=path,
        headers=headers,
        endpoint_class=EndpointClass.TRANSACTIONAL,
        body_sha256=hashlib.sha256(body).hexdigest() if body else "",
    )


def header_for(ts_ms: int | None = None, **kw: Any) -> str:
    args: dict[str, Any] = {
        "sid": SID,
        "method": "POST",
        "path": "/api/login",
        "body": BODY,
        "payload": PAYLOAD,
        "ts_ms": int(NOW * 1000) if ts_ms is None else ts_ms,
    }
    args.update(kw)
    return build_header(**args)


def test_wire_format_is_vendor_shaped() -> None:
    h = header_for(nonce="0123456789abcdef")
    assert h.count("&&&") == 5
    fields = parse_header(h)
    assert fields and list(fields) == ["a", "t", "n", "h", "e", "sensor_data"]
    assert fields["a"] == "lab1" and fields["n"] == "0123456789abcdef"
    assert re.fullmatch(r"[0-9a-f]{64}", fields["h"]) and re.fullmatch(r"[0-9a-f]{64}", fields["e"])
    assert parse_header("a=1&&&nonsense") is None and parse_header("a=lab1") is None


def test_request_hash_binds_method_path_and_body() -> None:
    body_hash = hashlib.sha256(BODY).hexdigest()
    base = request_hash("POST", "/api/login", body_hash)
    assert request_hash("post", "/api/login", body_hash) == base
    assert base != request_hash("PUT", "/api/login", body_hash)
    assert base != request_hash("POST", "/api/checkout", body_hash)
    assert base != request_hash("POST", "/api/login", hashlib.sha256(b"x").hexdigest())
    assert request_hash("POST", "/api/login", "") == request_hash(
        "POST", "/api/login", hashlib.sha256(b"").hexdigest()
    )


def test_keys_are_per_session() -> None:
    assert telemetry_key("a") == telemetry_key("a") != telemetry_key("b")
    assert len(telemetry_key("a")) == 32


async def test_fresh_telemetry_passes_and_is_stored(
    make_ctx: Callable[..., RequestContext], memory_store: MemoryStore
) -> None:
    sig = await mk().evaluate(ctx_with(make_ctx, header_for()))
    assert sig.verdict == Verdict.PASS and sig.score == 0
    assert sig.details["telemetry_type"] == "inline" and sig.details["kind"] == "ok"
    assert json.loads(await memory_store.get(f"inline:last:{SID}") or "")["keys"] == [[100.0, 80.0]]


async def test_missing_and_malformed_are_rejected(make_ctx: Callable[..., RequestContext]) -> None:
    mod = mk()
    sig = await mod.evaluate(ctx_with(make_ctx, None))
    assert sig.verdict == Verdict.FAIL and sig.score >= 90 and sig.details["kind"] == "missing"
    for junk in (
        "garbage",
        "a=lab1&&&t=x&&&n=1&&&h=2&&&e=3&&&sensor_data=4",
        "a=v9&&&t=1&&&n=1&&&h=1&&&e=1&&&sensor_data=1",
    ):
        sig = await mod.evaluate(ctx_with(make_ctx, junk))
        assert sig.verdict == Verdict.FAIL and sig.details["kind"] == "malformed", junk
    huge = header_for() + "x" * 70_000
    assert (await mod.evaluate(ctx_with(make_ctx, huge))).details["kind"] == "malformed"
    assert sig.details["telemetry_type"] == "inline"


async def test_stale_and_future_telemetry_rejected(make_ctx: Callable[..., RequestContext]) -> None:
    mod = mk()
    old = header_for(ts_ms=int(NOW * 1000) - MAX_AGE_MS - 1000)
    sig = await mod.evaluate(ctx_with(make_ctx, old))
    assert sig.verdict == Verdict.FAIL and sig.details["kind"] == "stale"
    just_ok = header_for(ts_ms=int(NOW * 1000) - MAX_AGE_MS + 1000)
    assert (await mod.evaluate(ctx_with(make_ctx, just_ok))).verdict == Verdict.PASS
    future = header_for(ts_ms=int(NOW * 1000) + 60_000)
    assert (await mod.evaluate(ctx_with(make_ctx, future))).details["kind"] == "stale"


async def test_replayed_telemetry_is_blocked(make_ctx: Callable[..., RequestContext]) -> None:
    mod = mk()
    h = header_for(nonce="aaaaaaaaaaaaaaaa")
    first = await mod.evaluate(ctx_with(make_ctx, h))
    assert first.verdict == Verdict.PASS
    second = await mod.evaluate(ctx_with(make_ctx, h))
    assert second.verdict == Verdict.BLOCK and second.details["kind"] == "replay"
    assert "replay" in second.reason
    # a new nonce is fine
    assert (
        await mod.evaluate(ctx_with(make_ctx, header_for(nonce="bbbbbbbbbbbbbbbb")))
    ).verdict == Verdict.PASS


async def test_telemetry_for_another_request_is_blocked(
    make_ctx: Callable[..., RequestContext],
) -> None:
    mod = mk()
    h = header_for()
    for kwargs in (
        {"path": "/api/checkout"},
        {"method": "PUT"},
        {"body": b'{"user":"mallory"}'},
    ):
        sig = await mod.evaluate(ctx_with(make_ctx, h, **kwargs))
        assert sig.verdict == Verdict.BLOCK and sig.details["kind"] == "hash_mismatch", kwargs
    # a rejected attempt must not burn the nonce of the genuine request
    assert (await mod.evaluate(ctx_with(make_ctx, h))).verdict == Verdict.PASS


async def test_telemetry_from_another_session_or_tampered_is_blocked(
    make_ctx: Callable[..., RequestContext],
) -> None:
    mod = mk()
    other = header_for(sid="another-session")
    sig = await mod.evaluate(ctx_with(make_ctx, other))  # solved session B's telemetry in A
    assert sig.verdict == Verdict.BLOCK and sig.details["kind"] == "bad_mac"
    fields = parse_header(header_for()) or {}
    fields["sensor_data"] = fields["sensor_data"][:-4] + "AAAA"
    tampered = "&&&".join(f"{k}={v}" for k, v in fields.items())
    assert (await mod.evaluate(ctx_with(make_ctx, tampered))).details["kind"] == "bad_mac"
    # a cookie-only replay (no telemetry at all) is what stops working
    assert (await mod.evaluate(ctx_with(make_ctx, None))).verdict == Verdict.FAIL


def test_verify_header_returns_payload_whenever_the_mac_verifies() -> None:
    body_hash = hashlib.sha256(BODY).hexdigest()
    now = int(NOW * 1000)
    kw: dict[str, Any] = {"sid": SID, "method": "POST", "path": "/x", "body_sha256": body_hash}
    res = verify_header(header_for(), now_ms=now, **kw)
    assert res.kind == "hash_mismatch" and res.mac_ok and res.payload == PAYLOAD
    assert verify_header(header_for(), now_ms=now, **{**kw, "sid": "zzz"}).payload is None
    ok = verify_header(header_for(), now_ms=now, **{**kw, "path": "/api/login"})
    assert ok.ok and ok.kind == "ok"


def test_module_metadata() -> None:
    m = InlineTelemetryModule()
    assert m.applies_to == frozenset({EndpointClass.TRANSACTIONAL})
    assert m.confidence.value == "high" and m.default_enabled and m.category == "js"


async def test_page_snippets_deliver_key_and_script(
    make_ctx: Callable[..., RequestContext],
) -> None:
    mod = mk()
    assert await mod.page_snippets(make_ctx(session_id="")) == []
    cfg_tag, script = await mod.page_snippets(make_ctx(session_id=SID))
    cfg = json.loads(re.search(r"window.__akInline=(\{.*\});", cfg_tag).group(1))  # type: ignore[union-attr]
    assert cfg["k"] == telemetry_key(SID) and cfg["p"] == ["/api/login", "/api/checkout"]
    assert cfg["v"] == "lab1" and cfg["s"] == int(NOW * 1000)
    assert "akamai-bm-telemetry" in script and "labCrypto" in script


async def test_landing_page_includes_the_snippets() -> None:
    app = create_app(store=MemoryStore(), modules=[InlineTelemetryModule()])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        html = (await c.get("/", headers={"accept": "text/html"})).text
        sid = c.cookies["bm_sz"]
    assert telemetry_key(sid) in html and "window.__akInline" in html


# ---- the real page script, executed in node ---------------------------------------------

DRIVER = """
var t = 500;
'alice'.split('').forEach(function (ch, i) {
  t += 140 + i * 17;
  ev('keydown', {code: 'Key' + ch.toUpperCase(), repeat: false, timeStamp: t});
  ev('keyup', {code: 'Key' + ch.toUpperCase(), timeStamp: t + 80});
});
for (var i = 0; i < 12; i++) { ev('mousemove', {clientX: 10 + i * 9, clientY: 20 + i * 4}); }
window.__inputs = [{type: 'text', value: 'alice'}, {type: 'password', value: 'hunter2hunter2'},
                   {type: 'hidden', value: 'x'.repeat(50)}, {type: 'checkbox', value: 'on'}];
fetch('/api/login', {method: 'POST', headers: {'Content-Type': 'application/json'},
                     body: BODY_TEXT});
fetch('/akam/other', {method: 'POST', body: 'x'});
fetch('/api/login');
var x = new XMLHttpRequest();
x.open('POST', '/api/checkout?x=1');
x.send(BODY_TEXT);
var gx = new XMLHttpRequest();
gx.open('GET', '/api/login');
gx.send();
var f = calls.filter(function (c) { return c.fetch; });
var xs = calls.filter(function (c) { return c.xhr; });
result = {
  login: f[0].init.headers.get('akamai-bm-telemetry'),
  ct: f[0].init.headers.get('content-type'),
  other: f[1].init && f[1].init.headers ? 'has headers' : 'untouched',
  get: f[2].init === undefined ? 'untouched' : 'touched',
  checkout: xs[0].xhr.headers['akamai-bm-telemetry'],
  getXhr: xs[1].xhr.headers['akamai-bm-telemetry'] || null
};
"""


def _js_of(tag: str) -> str:
    m = re.fullmatch(r"<script[^>]*>(.*)</script>", tag, re.S)
    assert m
    return m.group(1)


async def test_page_script_attaches_verifiable_telemetry(
    make_ctx: Callable[..., RequestContext], tmp_path: Path
) -> None:
    mod = mk()  # the lab's clock is far from the browser's: the markup carries the server time
    cfg_tag, script_tag = await mod.page_snippets(make_ctx(session_id=SID))
    body_text = '{"user":"\u00e5lice","n":1}'
    out = run_js(
        tmp_path,
        [_js_of(cfg_tag), _js_of(script_tag)],
        DRIVER.replace("BODY_TEXT", json.dumps(body_text)),
    )
    assert out["ct"] == "application/json"  # caller headers are preserved
    assert out["other"] == "untouched" and out["get"] == "untouched" and out["getXhr"] is None
    body = body_text.encode()
    body_hash = hashlib.sha256(body).hexdigest()
    fields = parse_header(out["login"]) or {}
    assert abs(int(fields["t"]) - int(NOW * 1000)) < 5_000  # server clock, not the browser's
    now_ms = int(fields["t"])
    res = verify_header(
        out["login"],
        sid=SID,
        method="POST",
        path="/api/login",
        body_sha256=body_hash,
        now_ms=now_ms,
    )
    assert res.ok, res.reason
    sig = await mod.evaluate(ctx_with(make_ctx, out["login"], body=body))
    assert sig.verdict == Verdict.PASS, sig.reason
    payload = res.payload or {}
    assert payload["counts"]["key"] == 5 and len(payload["keys"]) == 5
    assert len(payload["mouse"]) == 12 and payload["fill"] == {"chars": 19, "inputs": 0}
    assert "KeyA" not in json.dumps(payload)  # timings only, never key identities
    # the XHR wrapper binds to /api/checkout (query string excluded)
    xfields = parse_header(out["checkout"]) or {}
    kw: dict[str, Any] = {"sid": SID, "method": "POST", "body_sha256": body_hash}
    assert verify_header(out["checkout"], path="/api/checkout", now_ms=int(xfields["t"]), **kw).ok
    # the same header presented on /api/login is a different request
    swapped = verify_header(out["checkout"], path="/api/login", now_ms=int(xfields["t"]), **kw)
    assert swapped.kind == "hash_mismatch"
