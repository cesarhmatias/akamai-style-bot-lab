"""Case 9 - ``behavioral``: judge the mouse/keyboard telemetry captured by the sensor.

Reads ``sensor:{session_id}`` (written by ``sensor_data``). Mouse points are
``[x, y, t_ms]``. The path is split into *strokes* at pauses > ``STROKE_GAP_MS``
(a human or harness waits between movements); metrics are computed per stroke so
pauses do not pollute cadence statistics.

Scores are additive penalties (capped at 100); see the constants below.
"""

from __future__ import annotations

import json
import math
import statistics
from collections import Counter
from itertools import pairwise
from typing import Any, ClassVar

from app.contract import DetectionModule, RequestContext, Signal, Verdict

# --- thresholds ---------------------------------------------------------------
STROKE_GAP_MS = 120.0  # pause that separates two strokes
MIN_STROKE_POINTS = 4  # strokes shorter than this are ignored for shape metrics
MIN_STROKE_LEN_PX = 30.0  # ... and so are strokes shorter than this
MIN_POINTS = 8  # fewer mouse points overall = teleport / synthetic jump
STRAIGHT_DEV_PX = 1.5  # max perpendicular deviation (px) still considered a straight line
STRAIGHT_DEV_REL = 0.01  # ... or this fraction of the chord, whichever is larger
STRAIGHT_FRACTION = 0.8  # share of strokes that are straight => robotic
MIN_CADENCE_CV = 0.08  # coefficient of variation of inter-event dt below this is robotic
MIN_SPEED_CV = 0.05  # same for point-to-point speed
BURST_MEDIAN_DT_MS = 0.2  # median dt below this = events injected in a burst
MIN_DIR_ENTROPY = 0.5  # bits over 16 direction bins
MIN_TURN_ENTROPY = 0.2  # bits over 24 angle-change bins
MIN_DWELL_MS = 150.0  # first event -> submit

# --- penalty weights (>= 50 FAIL, >= 20 WARN) -----------------------------------
W_NO_EVENTS = 70
W_FEW_POINTS = 60
W_STRAIGHT = 50
W_CADENCE = 35
W_SPEED = 25
W_BURST = 40
W_DIR_ENTROPY = 20
W_TURN_ENTROPY = 20
W_DWELL = 30
FAIL_AT = 50
WARN_AT = 20


def shannon(counts: Counter[int]) -> float:
    total = sum(counts.values())
    if total == 0:
        return 0.0
    return -sum(c / total * math.log2(c / total) for c in counts.values())


def _cv(xs: list[float]) -> float | None:
    if len(xs) < 3:
        return None
    m = statistics.fmean(xs)
    return statistics.pstdev(xs) / m if m > 0 else 0.0


def split_strokes(pts: list[tuple[float, float, float]]) -> list[list[tuple[float, float, float]]]:
    strokes: list[list[tuple[float, float, float]]] = []
    cur: list[tuple[float, float, float]] = []
    for p in pts:
        if cur and p[2] - cur[-1][2] > STROKE_GAP_MS:
            strokes.append(cur)
            cur = []
        cur.append(p)
    if cur:
        strokes.append(cur)
    return strokes


def _is_straight(s: list[tuple[float, float, float]]) -> bool:
    (x0, y0, _), (x1, y1, _) = s[0], s[-1]
    chord = math.hypot(x1 - x0, y1 - y0)
    if chord == 0:
        return False
    dev = max(abs((x1 - x0) * (y0 - y) - (x0 - x) * (y1 - y0)) / chord for x, y, _ in s)
    return dev <= max(STRAIGHT_DEV_PX, STRAIGHT_DEV_REL * chord)


def analyze(sensor: dict[str, Any]) -> tuple[int, list[str], dict[str, Any]]:
    """Return (score, reasons, metrics) for a decoded sensor payload."""
    pts = [(float(p[0]), float(p[1]), float(p[2])) for p in sensor.get("mouse", [])]
    counts = sensor.get("counts", {})
    t0, t1 = float(sensor.get("t0", 0)), float(sensor.get("t1", 0))
    metrics: dict[str, Any] = {"points": len(pts), "counts": counts}
    score = 0
    reasons: list[str] = []
    if not pts:
        metrics["dwell_ms"] = round(t1 - t0, 1)
        return W_NO_EVENTS, ["no mouse events"], metrics
    if len(pts) < MIN_POINTS:
        score += W_FEW_POINTS
        reasons.append(f"only {len(pts)} mouse points (teleporting pointer)")

    strokes = split_strokes(pts)
    shape = [
        s
        for s in strokes
        if len(s) >= MIN_STROKE_POINTS and math.dist(s[0][:2], s[-1][:2]) >= MIN_STROKE_LEN_PX
    ]
    metrics["strokes"] = len(strokes)
    if shape:
        straight = sum(_is_straight(s) for s in shape) / len(shape)
        metrics["straight_fraction"] = round(straight, 3)
        if straight >= STRAIGHT_FRACTION:
            score += W_STRAIGHT
            reasons.append("mouse strokes are perfectly straight lines")

    dts: list[float] = []
    speeds: list[float] = []
    dirs: Counter[int] = Counter()
    turns: Counter[int] = Counter()
    for s in strokes:
        prev_ang: float | None = None
        for a, b in pairwise(s):
            dt = b[2] - a[2]
            dts.append(dt)
            d = math.dist(a[:2], b[:2])
            if dt > 0 and d > 0:
                speeds.append(d / dt)
            if d > 0:
                ang = math.atan2(b[1] - a[1], b[0] - a[0])
                dirs[int((ang + math.pi) / (2 * math.pi) * 16) % 16] += 1
                if prev_ang is not None:
                    dang = (ang - prev_ang + math.pi) % (2 * math.pi) - math.pi
                    turns[int((dang + math.pi) / (2 * math.pi) * 24) % 24] += 1
                prev_ang = ang
    if len(dts) >= 5:
        med = statistics.median(dts)
        metrics["median_dt_ms"] = round(med, 3)
        cad = _cv(dts)
        if med < BURST_MEDIAN_DT_MS:
            score += W_BURST
            reasons.append("mouse events injected in a burst (no inter-event time)")
        elif cad is not None and cad < MIN_CADENCE_CV:
            score += W_CADENCE
            reasons.append("constant event cadence")
        metrics["cadence_cv"] = None if cad is None else round(cad, 3)
        spd = _cv(speeds)
        metrics["speed_cv"] = None if spd is None else round(spd, 3)
        if spd is not None and spd < MIN_SPEED_CV and med >= BURST_MEDIAN_DT_MS:
            score += W_SPEED
            reasons.append("constant pointer speed")
    if sum(dirs.values()) >= 5:
        de = shannon(dirs)
        metrics["direction_entropy"] = round(de, 3)
        if de < MIN_DIR_ENTROPY:
            score += W_DIR_ENTROPY
            reasons.append("low direction entropy")
    if sum(turns.values()) >= 5:
        te = shannon(turns)
        metrics["turn_entropy"] = round(te, 3)
        if te < MIN_TURN_ENTROPY:
            score += W_TURN_ENTROPY
            reasons.append("pointer never changes direction")

    dwell = t1 - min(pts[0][2], t1) if t1 else 0.0
    metrics["dwell_ms"] = round(dwell, 1)
    if t1 and dwell < MIN_DWELL_MS:
        score += W_DWELL
        reasons.append("sensor submitted immediately after first event")
    return min(score, 100), reasons, metrics


class BehavioralModule(DetectionModule):
    slug: ClassVar[str] = "behavioral"
    title: ClassVar[str] = "Behavioral biometrics"
    description: ClassVar[str] = (
        "Scores mouse-path entropy, speed/cadence variance and straightness from the sensor."
    )
    category: ClassVar[str] = "behavioral"

    async def evaluate(self, ctx: RequestContext) -> Signal:
        raw = await ctx.store.get(f"sensor:{ctx.session_id}") if ctx.session_id else None
        if not raw:
            return self.signal(Verdict.FAIL, 90, "no sensor_data posted (no behavioral telemetry)")
        try:
            sensor = json.loads(raw)
            score, reasons, metrics = analyze(sensor)
        except (ValueError, TypeError, IndexError, KeyError):
            return self.signal(Verdict.FAIL, 90, "unreadable behavioral telemetry")
        if score >= FAIL_AT:
            return self.signal(Verdict.FAIL, score, "; ".join(reasons), **metrics)
        if score >= WARN_AT:
            return self.signal(Verdict.WARN, score, "; ".join(reasons), **metrics)
        return self.signal(Verdict.PASS, score, "human-like behavior", **metrics)
