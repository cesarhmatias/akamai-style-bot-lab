from __future__ import annotations

import base64
import json
from collections.abc import Callable
from typing import Any

from app.contract import EndpointClass, RequestContext, Verdict
from app.modules.native_app import (
    DEFAULT_APP_KEY,
    HEADER_NAME,
    MAX_AGE_MS,
    NativeAppModule,
    build_acf_header,
    stream_problem,
    verify_acf_header,
)

NOW = 1_800_000_000.0
DEVICE = "a1b2c3d4e5f60718"
PATH = "/mobile/api/items"


def stream(n: int = 12) -> list[list[float]]:
    return [
        [i * 20.0, 0.1 * i % 1.7, 9.8 + 0.05 * (i % 4), 0.2, 0.01 * i, 0.0, 0.003 * (i % 5)]
        for i in range(n)
    ]


def header(**over: Any) -> str:
    args: dict[str, Any] = {
        "device_id": DEVICE,
        "app_version": "5.2.1",
        "sdk_version": "3.4.0",
        "sensor": stream(),
        "path": PATH,
        "ts_ms": int(NOW * 1000),
        "nonce": "n0nce0000000001",
    }
    args.update(over)
    return build_acf_header(**args)


mod = NativeAppModule(clock=lambda: NOW)


def ctx_for(
    make_ctx: Callable[..., RequestContext], value: str | None, path: str = PATH
) -> RequestContext:
    headers = [("user-agent", "okhttp/4.12")] + ([(HEADER_NAME, value)] if value else [])
    return make_ctx(path=path, headers=headers, endpoint_class=EndpointClass.MOBILE)


def test_header_layout() -> None:
    v, body, mac = header().split(";")
    assert v == "lab1" and len(mac) == 64
    doc = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    assert set(doc) == {"d", "av", "sv", "t", "n", "p", "s"} and doc["d"] == DEVICE


def test_verify_kinds() -> None:
    now = int(NOW * 1000)
    assert verify_acf_header(header(), path=PATH, now_ms=now)[0] == "ok"
    assert verify_acf_header(None, path=PATH, now_ms=now)[0] == "missing"
    assert verify_acf_header("junk", path=PATH, now_ms=now)[0] == "malformed"
    assert verify_acf_header(header(key="other"), path=PATH, now_ms=now)[0] == "bad_mac"
    assert verify_acf_header(header(key=DEFAULT_APP_KEY), path=PATH, now_ms=now)[0] == "ok"
    assert verify_acf_header(header(), path="/mobile/api/x", now_ms=now)[0] == "path"
    stale = verify_acf_header(header(), path=PATH, now_ms=now + MAX_AGE_MS + 1)
    assert stale[0] == "stale"
    assert verify_acf_header(header(), path=PATH, now_ms=now - 60_000)[0] == "stale"
    for bad in (
        {"device_id": "XYZ"},
        {"app_version": "5.2"},
        {"sdk_version": "v3"},
    ):
        assert verify_acf_header(header(**bad), path=PATH, now_ms=now)[0] == "malformed", bad


async def test_valid_header_passes(make_ctx: Callable[..., RequestContext]) -> None:
    sig = await mod.evaluate(ctx_for(make_ctx, header()))
    assert sig.verdict == Verdict.PASS and sig.score == 0
    assert sig.details["telemetry_type"] == "native" and sig.details["app_version"] == "5.2.1"
    assert sig.details["device"] == DEVICE


async def test_missing_malformed_stale_fail(make_ctx: Callable[..., RequestContext]) -> None:
    for value, kind in (
        (None, "missing"),
        ("lab1;a;b;c", "malformed"),
        (header(ts_ms=int(NOW * 1000) - 120_000), "stale"),
    ):
        sig = await mod.evaluate(ctx_for(make_ctx, value))
        assert sig.verdict == Verdict.FAIL and sig.score >= 90, kind
        assert sig.details["kind"] == kind and sig.details["telemetry_type"] == "native"


async def test_forged_wrong_path_and_replay_block(make_ctx: Callable[..., RequestContext]) -> None:
    assert (await mod.evaluate(ctx_for(make_ctx, header(key="guess")))).verdict == Verdict.BLOCK
    other_path = await mod.evaluate(ctx_for(make_ctx, header(), path="/mobile/api/other"))
    assert other_path.verdict == Verdict.BLOCK
    first = await mod.evaluate(ctx_for(make_ctx, header()))
    assert first.verdict == Verdict.PASS
    again = await mod.evaluate(ctx_for(make_ctx, header()))
    assert again.verdict == Verdict.BLOCK and again.details["kind"] == "replay"
    fresh = await mod.evaluate(ctx_for(make_ctx, header(nonce="another-nonce-01")))
    assert fresh.verdict == Verdict.PASS


async def test_emulator_streams_fail(make_ctx: Callable[..., RequestContext]) -> None:
    flat = [[i * 20.0, 0.0, 9.8, 0.0, 0.0, 0.0, 0.0] for i in range(12)]
    sig = await mod.evaluate(ctx_for(make_ctx, header(sensor=flat, nonce="flat-stream-0001")))
    assert sig.verdict == Verdict.FAIL and "never change" in sig.reason


def test_stream_problem_cases() -> None:
    assert stream_problem(stream()) is None
    assert "needs" in (stream_problem(stream(3)) or "")
    assert "numeric" in (stream_problem([["a"] * 7] * 8) or "")
    assert "numeric" in (stream_problem(["x"] * 8) or "")
    backwards = stream()
    backwards[5][0] = 0.0
    assert "increasing" in (stream_problem(backwards) or "")
    huge = stream()
    huge[3][2] = 5000.0
    assert "implausible" in (stream_problem(huge) or "")
    assert "7 values" in (stream_problem([[1.0, 2.0]] * 8) or "")


def test_module_metadata() -> None:
    assert NativeAppModule.applies_to == frozenset({EndpointClass.MOBILE})
    assert NativeAppModule.confidence.value == "medium" and NativeAppModule().default_enabled
