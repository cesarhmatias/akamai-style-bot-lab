from __future__ import annotations

import hashlib
import json
import math
import random
from collections.abc import Callable
from typing import Any

from app.contract import EndpointClass, RequestContext, Verdict
from app.modules.behavioral import (
    BehavioralModule,
    analyze,
    analyze_mouse,
    key_modality,
    segment_hint,
    soft_signals,
    touch_modality,
)
from app.modules.inline_telemetry import HEADER_NAME, build_header
from app.store import MemoryStore

SID = "C" * 32 + "~01234567"


def bezier(
    p0: tuple[float, float], p3: tuple[float, float], rnd: random.Random, n: int
) -> list[tuple[float, float]]:
    """Curved path with randomised control points, ease-in-out speed and pixel rounding."""
    c1 = (p0[0] + rnd.uniform(-80, 80) + (p3[0] - p0[0]) / 3, p0[1] + rnd.uniform(-80, 80))
    c2 = (p3[0] - rnd.uniform(-80, 80) - (p3[0] - p0[0]) / 3, p3[1] + rnd.uniform(-80, 80))
    out = []
    for i in range(1, n + 1):
        u = i / n
        t = u * u * (3 - 2 * u)
        x = (1 - t) ** 3 * p0[0] + 3 * (1 - t) ** 2 * t * c1[0] + 3 * (1 - t) * t**2 * c2[0]
        y = (1 - t) ** 3 * p0[1] + 3 * (1 - t) ** 2 * t * c1[1] + 3 * (1 - t) * t**2 * c2[1]
        out.append((x + t**3 * p3[0], y + t**3 * p3[1]))
    return out


def human_sensor(seed: int = 0) -> dict[str, Any]:
    rnd = random.Random(seed)
    t, pos, pts = 300.0, (50.0, 60.0), []
    for _ in range(4):
        dst = (rnd.uniform(100, 900), rnd.uniform(100, 600))
        for x, y in bezier(pos, dst, rnd, 25):
            t += rnd.uniform(2, 14)
            pts.append([round(x), round(y), round(t, 2)])
        pos = dst
        t += rnd.uniform(150, 300)  # small wait between moves
    return {"t0": 5.0, "t1": t + 100, "mouse": pts, "counts": {"mouse": len(pts)}}


def linear_sensor(n: int = 30, dt: float = 16.0, jitter: float = 0.0) -> dict[str, Any]:
    rnd = random.Random(3)
    pts = [[i * 10.0, i * 6.0, 400 + i * dt + rnd.uniform(0, jitter)] for i in range(n)]
    return {"t0": 5.0, "t1": 400 + n * dt + 600, "mouse": pts, "counts": {"mouse": n}}


def test_human_passes() -> None:
    for seed in range(10):
        score, reasons, m = analyze(human_sensor(seed))
        assert score < 20, (seed, reasons, m)


def test_perfect_line_fails() -> None:
    score, reasons, _ = analyze(linear_sensor())
    assert score >= 50 and any("straight" in r for r in reasons)
    assert any("cadence" in r for r in reasons)


def test_straight_with_timing_jitter_still_fails() -> None:
    assert analyze(linear_sensor(jitter=6.0))[0] >= 50


def test_teleport_fails() -> None:
    s = {"t0": 0, "t1": 2000, "mouse": [[500, 400, 1000.0]], "counts": {"mouse": 1}}
    score, reasons, _ = analyze(s)
    assert score >= 50 and "teleport" in reasons[0]


def test_no_events_fails() -> None:
    assert analyze({"t0": 0, "t1": 4000, "mouse": [], "counts": {}})[0] >= 50


def test_burst_fails() -> None:
    pts = [[i * 3.0, math.sin(i) * 20 + i, 500.0 + i * 0.01] for i in range(40)]
    assert analyze({"t0": 0, "t1": 3000, "mouse": pts, "counts": {}})[0] >= 40


def test_instant_submit_penalised() -> None:
    s = human_sensor()
    s["t1"] = s["mouse"][0][2] + 50
    assert any("immediately" in r for r in analyze(s)[1])


async def test_evaluate(make_ctx: Callable[..., RequestContext], memory_store: MemoryStore) -> None:
    mod = BehavioralModule()
    sig = await mod.evaluate(make_ctx(session_id=SID))
    assert sig.verdict == Verdict.FAIL and sig.score == 90
    await memory_store.set(f"sensor:{SID}", json.dumps(linear_sensor()))
    assert (await mod.evaluate(make_ctx(session_id=SID))).verdict == Verdict.FAIL
    await memory_store.set(f"sensor:{SID}", json.dumps(human_sensor()))
    sig = await mod.evaluate(make_ctx(session_id=SID))
    assert sig.verdict == Verdict.PASS
    await memory_store.set(f"sensor:{SID}", "not json")
    assert (await mod.evaluate(make_ctx(session_id=SID))).score == 90


# ---- v2: keyboard, touch, motion, scroll, focus, segments, inline telemetry ---------------


def human_keys(seed: int = 0, n: int = 28) -> list[list[float]]:
    """Touch-typist-ish: log-normal inter-key gaps (~150 ms, CV ~0.5), dwell 60-130 ms."""
    rnd = random.Random(seed)
    t, out = 5000.0, []
    for i in range(n):
        t += rnd.lognormvariate(math.log(150), 0.45) + (700 if i in (9, 18) else 0)
        out.append([round(t, 1), round(rnd.gauss(95, 22), 1)])
    return out


def keyboard_only_sensor(seed: int = 0) -> dict[str, Any]:
    keys = human_keys(seed)
    return {
        "t0": 5.0,
        "t1": keys[-1][0] + 400,
        "mouse": [],
        "keys": keys,
        "counts": {"key": len(keys), "mouse": 0},
    }


def test_keyboard_only_human_passes() -> None:
    for seed in range(10):
        score, reasons, metrics = analyze(keyboard_only_sensor(seed))
        assert score < 20, (seed, reasons, metrics)
        assert metrics["modalities"]["keys"]["state"] == "human"
        assert metrics["modalities"]["mouse"]["state"] == "none"


def test_mouse_only_human_still_passes_and_has_no_key_evidence() -> None:
    score, _, metrics = analyze(human_sensor(2))
    assert score < 20 and metrics["modalities"]["keys"]["state"] == "none"


def test_scripted_typing_is_robotic() -> None:
    n = 20
    burst = {"t0": 0, "t1": 9000, "mouse": [], "keys": [[1000 + i * 1.0, 0.5] for i in range(n)]}
    s, reasons, _ = analyze(burst)
    assert s >= 50 and any("burst" in r for r in reasons)
    delayed = {
        "t0": 0,
        "t1": 9000,
        "mouse": [],
        "keys": [[1000 + i * 100.0, 2.0] for i in range(n)],
    }
    s, reasons, _ = analyze(delayed)
    assert s >= 50 and any("cadence" in r for r in reasons) and any("dwell" in r for r in reasons)
    constant_dwell = human_keys(1)
    for k in constant_dwell:
        k[1] = 80.0
    assert analyze({"t0": 0, "t1": 9000, "mouse": [], "keys": constant_dwell})[0] >= 35


def test_robotic_keys_beat_a_human_looking_mouse() -> None:
    s = human_sensor(3)
    s["keys"] = [[1000 + i * 100.0, 1.0] for i in range(20)]
    score, reasons, _ = analyze(s)
    assert score >= 50 and any("keystroke" in r or "dwell" in r for r in reasons)


def test_thin_mouse_does_not_fail_a_keyboard_user() -> None:
    s = keyboard_only_sensor(4)
    s["mouse"] = [[10, 10, 20.0], [12, 11, 30.0]]  # a nudge of the mouse
    assert analyze(s)[0] < 20
    teleport_only = {"t0": 0, "t1": 2000, "mouse": [[500, 400, 1000.0]], "counts": {}}
    assert analyze(teleport_only)[0] >= 50


def test_too_few_keys_is_not_human_evidence() -> None:
    s = {"t0": 0, "t1": 9000, "mouse": [], "keys": human_keys(0, 5)}
    score, reasons, _ = analyze(s)
    assert score >= 50 and "key presses" in reasons[0]
    assert key_modality({"keys": []}).state == "none"


def test_zero_interaction_fails() -> None:
    score, reasons, _ = analyze({"t0": 0, "t1": 5000, "mouse": [], "keys": [], "touch": []})
    assert score >= 50 and "no interaction" in reasons[0]


def swipe(seed: int, kind: int = 1) -> list[list[float]]:
    rnd = random.Random(seed)
    pts = [[0, 100, 100, 1000.0]]
    x, y, t = 100.0, 100.0, 1000.0
    for i in range(30):
        t += rnd.uniform(8, 20)
        x += 6 + 2 * math.sin(i / 4) + rnd.uniform(-1, 1)
        y += 3 + 4 * math.cos(i / 3) + rnd.uniform(-1, 1)
        pts.append([kind, round(x), round(y), round(t, 1)])
    pts.append([2, round(x), round(y), round(t + 5, 1)])
    return pts


def test_touch_swipes_pass_and_taps_are_thin() -> None:
    sensor = {"t0": 5.0, "t1": 4000.0, "mouse": [], "touch": swipe(1)}
    assert analyze(sensor)[0] < 20 and touch_modality(sensor).state == "human"
    taps = {"t0": 5.0, "t1": 4000.0, "mouse": [], "touch": [[0, 5, 5, 100.0], [2, 5, 5, 140.0]]}
    assert touch_modality(taps).state == "thin" and analyze(taps)[0] >= 50
    assert touch_modality({}).state == "none"
    straight = [[1, 10 + i * 6, 10 + i * 4, 1000.0 + i * 16] for i in range(30)]
    robotic = {"t0": 5.0, "t1": 4000.0, "mouse": [], "touch": straight}
    assert touch_modality(robotic).state == "robotic" and analyze(robotic)[0] >= 50


def test_soft_signals_never_pass_a_session_alone() -> None:
    score, reasons = soft_signals({"scroll": [100.0 + i * 50 for i in range(8)]})
    assert score == 20 and "scroll" in reasons[0]
    varied = [100.0, 130.0, 210.0, 240.0, 400.0, 420.0]
    assert soft_signals({"scroll": varied})[0] == 0
    iphone = {"navigator": {"userAgent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)"}}
    assert soft_signals({**iphone, "motion": {"dm": False}})[0] == 25
    nav = {"userAgent": "Mozilla/5.0 (Linux; Android 14) Mobile", "maxTouchPoints": 0}
    assert soft_signals({"navigator": nav, "motion": {"dm": True}})[0] == 25
    assert soft_signals({"motion": {"dm": True, "n": 10, "spread": 0}})[0] == 20
    assert soft_signals({"focus": {"has": False}})[0] == 10
    desktop = {
        "navigator": {"userAgent": "Mozilla/5.0 (X11; Linux x86_64)"},
        "motion": {"dm": False},
    }
    assert soft_signals(desktop)[0] == 0
    # a scroll-only session is not enough: no mouse/keys/touch means no evidence
    scrolly = {"t0": 0, "t1": 5000, "mouse": [], "scroll": varied}
    assert analyze(scrolly)[0] >= 50
    # soft penalties add to a real modality's score
    s = keyboard_only_sensor(5)
    s["focus"] = {"has": False}
    assert 0 < analyze(s)[0] < 20


def test_form_filled_without_key_events_is_robotic() -> None:
    s = keyboard_only_sensor(6)
    s["fill"] = {"chars": 20, "inputs": 2}
    s["counts"] = {"key": 0, "paste": 0}
    score, reasons, metrics = analyze(s)
    assert score >= 45 and any("without key events" in r for r in reasons)
    assert metrics["fill_chars"] == 20
    s["counts"] = {"key": 0, "paste": 2}  # password manager / paste is legitimate
    assert analyze(s)[0] < 20
    s["fill"] = {"chars": 3}
    s["counts"] = {"key": 0}
    assert analyze(s)[0] < 20


def test_playwright_bezier_mouse_path_still_passes() -> None:
    """Recipe of clients/playwright_client.py: a mouse.move per Bezier point, 8-25 ms apart."""
    rng = random.Random(1337)
    pos = (rng.uniform(80, 200), rng.uniform(80, 200))
    pts, t = [[round(pos[0]), round(pos[1]), 100.0]], 100.0
    for target in [(620, 340), (260, 520), (840, 180)]:
        dx, dy = target[0] - pos[0], target[1] - pos[1]
        norm = math.hypot(dx, dy) or 1.0
        nx, ny = -dy / norm, dx / norm
        b1, b2 = rng.uniform(-0.35, 0.35) * norm, rng.uniform(-0.35, 0.35) * norm
        c1 = (pos[0] + dx * 0.3 + nx * b1, pos[1] + dy * 0.3 + ny * b1)
        c2 = (pos[0] + dx * 0.7 + nx * b2, pos[1] + dy * 0.7 + ny * b2)
        for i in range(1, 71):
            u = i / 70
            e = u * u * (3 - 2 * u)
            a, b, c, d = (1 - e) ** 3, 3 * (1 - e) ** 2 * e, 3 * (1 - e) * e**2, e**3
            x = a * pos[0] + b * c1[0] + c * c2[0] + d * target[0] + rng.gauss(0, 0.8)
            y = a * pos[1] + b * c1[1] + c * c2[1] + d * target[1] + rng.gauss(0, 0.8)
            t += rng.uniform(8, 25) + 1
            pts.append([x, y, round(t, 2)])
        pos = target
    sensor = {"t0": 5.0, "t1": t + 2000, "mouse": pts, "counts": {"mouse": len(pts)}}
    score, reasons, _ = analyze(sensor)
    assert score < 20, reasons


def test_analyze_mouse_is_the_old_analysis() -> None:
    assert analyze_mouse(human_sensor(0))[0] < 20
    assert analyze_mouse(linear_sensor())[0] >= 50


def test_segment_hint_bands() -> None:
    assert [segment_hint(s) for s in (0, 1, 20, 21, 60, 61, 100)] == [
        "human", "cautious", "cautious", "strict", "strict", "aggressive", "aggressive",
    ]  # fmt: skip
    assert [segment_hint(s, "inline") for s in (0, 28, 29, 80, 81)] == [
        "human", "cautious", "strict", "strict", "aggressive",
    ]  # fmt: skip


async def test_evaluate_details_carry_segment_hint_and_telemetry_type(
    make_ctx: Callable[..., RequestContext], memory_store: MemoryStore
) -> None:
    mod = BehavioralModule()
    await memory_store.set(f"sensor:{SID}", json.dumps(keyboard_only_sensor(1)))
    sig = await mod.evaluate(make_ctx(session_id=SID))
    assert sig.verdict == Verdict.PASS and sig.details["segment_hint"] == "human"
    assert sig.details["telemetry_type"] == "standard" and sig.details["source"] == "sensor"
    await memory_store.set(f"sensor:{SID}", json.dumps(linear_sensor()))
    sig = await mod.evaluate(make_ctx(session_id=SID))
    assert sig.verdict == Verdict.FAIL and sig.details["segment_hint"] in {"strict", "aggressive"}
    assert mod.applies_to >= {EndpointClass.PAGE, EndpointClass.TRANSACTIONAL}


def inline_ctx(
    make_ctx: Callable[..., RequestContext], payload: dict[str, Any], sid: str = SID
) -> RequestContext:
    body = b'{"user":"a"}'
    header = build_header(sid, "POST", "/api/login", body, payload)
    return make_ctx(
        session_id=sid,
        method="POST",
        path="/api/login",
        endpoint_class=EndpointClass.TRANSACTIONAL,
        body_sha256=hashlib.sha256(body).hexdigest(),
        headers=[("user-agent", "UA"), (HEADER_NAME, header)],
    )


async def test_transactional_prefers_inline_telemetry(
    make_ctx: Callable[..., RequestContext], memory_store: MemoryStore
) -> None:
    mod = BehavioralModule()
    # the stored sensor looks robotic, the inline telemetry captured during the form fill is human
    await memory_store.set(f"sensor:{SID}", json.dumps(linear_sensor()))
    payload = {**keyboard_only_sensor(2), "fill": {"chars": 14, "inputs": 14}}
    sig = await mod.evaluate(inline_ctx(make_ctx, payload))
    assert sig.verdict == Verdict.PASS
    assert sig.details["source"] == "inline" and sig.details["telemetry_type"] == "inline"
    # robotic inline telemetry fails even when the stored sensor is fine
    await memory_store.set(f"sensor:{SID}", json.dumps(human_sensor()))
    bot = {"t0": 0, "t1": 9000, "mouse": [], "keys": [[1000 + i * 1.0, 0.4] for i in range(20)]}
    sig = await mod.evaluate(inline_ctx(make_ctx, bot))
    assert sig.verdict == Verdict.FAIL and sig.details["telemetry_type"] == "inline"
    assert sig.details["segment_hint"] in {"strict", "aggressive"}


async def test_transactional_falls_back_to_the_sensor_without_valid_inline(
    make_ctx: Callable[..., RequestContext], memory_store: MemoryStore
) -> None:
    mod = BehavioralModule()
    await memory_store.set(f"sensor:{SID}", json.dumps(human_sensor()))
    ctx = make_ctx(session_id=SID, endpoint_class=EndpointClass.TRANSACTIONAL)
    sig = await mod.evaluate(ctx)
    assert sig.details["source"] == "sensor" and sig.verdict == Verdict.PASS
    # inline telemetry minted for another session does not count
    other = inline_ctx(make_ctx, keyboard_only_sensor(3), sid="other-session")
    other.session_id = SID
    sig = await mod.evaluate(other)
    assert sig.details["source"] == "sensor"
    empty = make_ctx(session_id="sid-without-anything", endpoint_class=EndpointClass.TRANSACTIONAL)
    assert (await mod.evaluate(empty)).score == 90
