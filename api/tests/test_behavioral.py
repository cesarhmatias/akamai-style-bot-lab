from __future__ import annotations

import json
import math
import random
from collections.abc import Callable
from typing import Any

from app.contract import RequestContext, Verdict
from app.modules.behavioral import BehavioralModule, analyze
from app.store import MemoryStore

SID = "C" * 32 + "~01234567"


def bezier(p0: tuple[float, float], p3: tuple[float, float], rnd: random.Random, n: int):
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
