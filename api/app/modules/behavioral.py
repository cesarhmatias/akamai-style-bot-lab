"""Case 9 - ``behavioral``: judge the interaction telemetry the client captured.

Mechanism and real-world basis (report §1.2 case 9, tier HIGH for the concept)
-------------------------------------------------------------------------------
Akamai's behavioral detection evaluates "movement patterns and other interaction details
unique to humans" and is a Bot Manager Premier feature ([P], detection methods 2026-03-01).
Content Protector analyses user interaction (touchscreen, keyboard, mouse) and behaviour across
the site ([P], press release 2024-02-06); Akamai's mobile SDK docs list device characteristics,
orientation and accelerometer data ([S]). Results feed the Bot Score (0-100) and its response
segments. All THRESHOLDS below are lab-defined, not Akamai's.

How the lab simulates it
------------------------
Telemetry comes from ``sensor:{sid}`` (standard telemetry, written by ``sensor_data``) and, on
TRANSACTIONAL endpoints, preferably from the inline telemetry captured while the form was
filled (``inline_telemetry`` header; same field names). Modalities are scored independently:

* mouse: stroke straightness, cadence and speed variance, direction entropy, teleporting;
* keyboard: inter-key intervals (burst, constant cadence) and dwell (keyup - keydown), timings
  only, key identities are never collected;
* touch: touchmove strokes through the same path analysis as the mouse;
* soft signals (never sufficient alone): scroll cadence, DeviceMotion/touch availability for
  mobile user agents, static motion sensor, window focus;
* form fill (inline telemetry only): fields filled with no key events and no paste.

A session needs ONE modality with enough data that looks human; a robotic modality always
wins (a bot cannot offset a scripted keyboard with a pretty mouse path). Mouse-only humans and
keyboard-only humans both pass; zero interaction fails.

``details["segment_hint"]`` maps the score onto the report's example Bot Score bands (standard
telemetry 1-20 / 21-60 / 61-100, inline 1-28 / 29-80 / 81-100; 0 = ``human``); the response
agent owns the real segments.

How a client passes
-------------------
Produce human-like timing for at least one modality (a patient mouse path with varying speed,
or typing with variable intervals and dwell) before the telemetry is sent.

Limits
------
Synthetic Bezier paths with jitter, or replayed recordings, can pass; this is a lab teaching
model, not a research-grade classifier.
"""

from __future__ import annotations

import json
import math
import re
import statistics
from collections import Counter
from dataclasses import dataclass, field
from itertools import pairwise
from typing import Any, ClassVar

from app.contract import (
    Confidence,
    DetectionModule,
    EndpointClass,
    RequestContext,
    Signal,
    Verdict,
)
from app.modules.inline_telemetry import payload_from_ctx

# --- mouse thresholds -----------------------------------------------------------
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

# --- keyboard thresholds ------------------------------------------------------------
MIN_KEYS = 8  # completed key presses needed before keystroke dynamics are judged
KEY_GAP_MS = 1500.0  # pauses longer than this (between fields/words) are not cadence
KEY_BURST_MEDIAN_MS = 8.0  # median inter-key interval below this = injected keystrokes
MIN_KEY_CV = 0.10  # inter-key interval CV below this = constant cadence
MIN_KEY_DWELL_MS = 5.0  # median keydown->keyup below this = synthetic events
MIN_DWELL_CV = 0.05  # dwell CV below this = constant dwell

# --- soft signals ---------------------------------------------------------------------
MIN_SCROLL_EVENTS = 5
MIN_SCROLL_CV = 0.05
MOBILE_UA = re.compile(r"Mobile|Android|iPhone|iPad")
FILL_MIN_CHARS = 8

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
W_KEY_BURST = 55
W_KEY_CADENCE = 45
W_KEY_DWELL = 40
W_FILL = 45
W_SCROLL = 20
W_MOTION = 25
W_STATIC_MOTION = 20
W_FOCUS = 10
FAIL_AT = 50
WARN_AT = 20

# Bot Score example bands (report §2.1): upper bounds of cautious / strict.
BANDS_STANDARD = (20, 60)
BANDS_INLINE = (28, 80)


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


def analyze_mouse(sensor: dict[str, Any]) -> tuple[int, list[str], dict[str, Any]]:
    """Mouse-path analysis: ``(score, reasons, metrics)`` for a decoded sensor payload."""
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


# --- other modalities -------------------------------------------------------------------


@dataclass
class Modality:
    """One input channel's verdict. ``state``: human | suspicious | robotic | thin | none."""

    name: str
    state: str
    score: int
    reasons: list[str] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)

    @property
    def active(self) -> bool:
        return self.state in {"human", "suspicious", "robotic"}


def _state(score: int) -> str:
    return "robotic" if score >= FAIL_AT else "suspicious" if score >= WARN_AT else "human"


def mouse_modality(sensor: dict[str, Any]) -> Modality:
    score, reasons, metrics = analyze_mouse(sensor)
    pts = int(metrics.get("points", 0))
    if pts == 0:
        return Modality("mouse", "none", score, reasons, metrics)
    if pts < MIN_POINTS:
        return Modality("mouse", "thin", score, reasons, metrics)
    return Modality("mouse", _state(score), score, reasons, metrics)


def touch_modality(sensor: dict[str, Any]) -> Modality:
    """Touchmove strokes ``[kind, x, y, t]`` (kind 1 = move) through the mouse path analysis."""
    touch = [p for p in sensor.get("touch") or [] if isinstance(p, list) and len(p) == 4]
    moves = [[p[1], p[2], p[3]] for p in touch if p[0] == 1]
    if not touch:
        return Modality("touch", "none", 0)
    if len(moves) < MIN_POINTS:
        return Modality("touch", "thin", W_FEW_POINTS, [f"only {len(moves)} touch-move points"])
    sub = {"mouse": moves, "counts": {}, "t0": sensor.get("t0", 0), "t1": sensor.get("t1", 0)}
    score, reasons, metrics = analyze_mouse(sub)
    return Modality("touch", _state(score), score, [f"touch: {r}" for r in reasons], metrics)


def key_modality(sensor: dict[str, Any]) -> Modality:
    """Keystroke dynamics from ``[down_t, dwell]`` pairs (timings only)."""
    keys = [k for k in sensor.get("keys") or [] if isinstance(k, list) and len(k) == 2]
    if not keys:
        return Modality("keys", "none", 0)
    metrics: dict[str, Any] = {"key_presses": len(keys)}
    if len(keys) < MIN_KEYS:
        return Modality("keys", "thin", W_FEW_POINTS, [f"only {len(keys)} key presses"], metrics)
    downs = sorted(float(k[0]) for k in keys)
    gaps = [b - a for a, b in pairwise(downs) if b - a <= KEY_GAP_MS]
    dwell = [float(k[1]) for k in keys if float(k[1]) >= 0]
    if len(gaps) < 5:
        return Modality("keys", "thin", W_FEW_POINTS, ["keystrokes too sparse to judge"], metrics)
    med = statistics.median(gaps)
    cv = _cv(gaps)
    metrics["median_interkey_ms"] = round(med, 2)
    metrics["interkey_cv"] = None if cv is None else round(cv, 3)
    score = 0
    reasons: list[str] = []
    if med < KEY_BURST_MEDIAN_MS:
        score += W_KEY_BURST
        reasons.append("keystrokes injected in a burst (no inter-key time)")
    elif cv is not None and cv < MIN_KEY_CV:
        score += W_KEY_CADENCE
        reasons.append("constant keystroke cadence")
    if len(dwell) >= 5:
        dmed, dcv = statistics.median(dwell), _cv(dwell)
        metrics["median_dwell_ms"] = round(dmed, 2)
        metrics["dwell_cv"] = None if dcv is None else round(dcv, 3)
        if dmed < MIN_KEY_DWELL_MS:
            score += W_KEY_DWELL
            reasons.append("key dwell (keyup - keydown) is ~0: synthetic key events")
        elif dcv is not None and dcv < MIN_DWELL_CV:
            score += W_KEY_DWELL
            reasons.append("constant key dwell")
    score = min(score, 100)
    return Modality("keys", _state(score), score, reasons, metrics)


def _is_mobile(sensor: dict[str, Any]) -> bool:
    nav = sensor.get("navigator") or {}
    return bool(nav.get("mobile") is True or MOBILE_UA.search(str(nav.get("userAgent", ""))))


def soft_signals(sensor: dict[str, Any]) -> tuple[int, list[str]]:
    """Extra penalties that never count as human evidence on their own."""
    score, reasons = 0, []
    scroll = [float(t) for t in sensor.get("scroll") or []]
    if len(scroll) >= MIN_SCROLL_EVENTS:
        cv = _cv([b - a for a, b in pairwise(scroll)])
        if cv is not None and cv < MIN_SCROLL_CV:
            score += W_SCROLL
            reasons.append("constant scroll cadence")
    nav = sensor.get("navigator") or {}
    motion = sensor.get("motion") or {}
    if motion and _is_mobile(sensor):
        if motion.get("dm") is False:
            score += W_MOTION
            reasons.append("mobile user agent without DeviceMotion support")
        elif nav.get("maxTouchPoints") == 0:
            score += W_MOTION
            reasons.append("mobile user agent without touch points")
    if int(motion.get("n", 0) or 0) >= 5 and float(motion.get("spread", 1) or 0) == 0:
        score += W_STATIC_MOTION
        reasons.append("device motion readings never change")
    if (sensor.get("focus") or {}).get("has") is False:
        score += W_FOCUS
        reasons.append("interaction while the page reports no focus")
    return score, reasons


def fill_modality(sensor: dict[str, Any]) -> Modality | None:
    """Inline telemetry only: fields filled with neither key events nor paste."""
    fill, counts = sensor.get("fill"), sensor.get("counts") or {}
    if not isinstance(fill, dict):
        return None
    chars = int(fill.get("chars", 0) or 0)
    if chars >= FILL_MIN_CHARS and not counts.get("key") and not counts.get("paste"):
        return Modality(
            "form_fill",
            "robotic",
            W_FILL,
            ["form fields filled without key events or paste"],
            {"fill_chars": chars},
        )
    return None


def segment_hint(score: int, telemetry_type: str = "standard") -> str:
    """Bot Score band name for ``score`` (``human`` = nothing detected)."""
    cautious, strict = BANDS_INLINE if telemetry_type == "inline" else BANDS_STANDARD
    if score <= 0:
        return "human"
    if score <= cautious:
        return "cautious"
    return "strict" if score <= strict else "aggressive"


def analyze(sensor: dict[str, Any]) -> tuple[int, list[str], dict[str, Any]]:
    """Return (score, reasons, metrics) for a decoded sensor / inline payload."""
    mods = [mouse_modality(sensor), key_modality(sensor), touch_modality(sensor)]
    metrics: dict[str, Any] = dict(mods[0].metrics)
    metrics["modalities"] = {m.name: {"state": m.state, "score": m.score} for m in mods}
    for m in mods[1:]:
        if m.metrics:
            metrics[m.name] = m.metrics
    robotic = [m for m in mods if m.state == "robotic"]
    fill = fill_modality(sensor)
    if fill is not None:
        robotic.append(fill)
        metrics["modalities"]["form_fill"] = {"state": "robotic", "score": fill.score}
        metrics.update(fill.metrics)
    active = [m for m in mods if m.active]
    if not active and not robotic:
        thin = [m for m in mods if m.state == "thin"]
        if not thin:
            metrics.setdefault("dwell_ms", mods[0].metrics.get("dwell_ms", 0))
            return W_NO_EVENTS, ["no interaction events (mouse, keyboard or touch)"], metrics
        worst = max(thin, key=lambda m: m.score)
        return worst.score, worst.reasons, metrics
    if robotic:
        base = max(m.score for m in robotic)
        reasons = [r for m in robotic for r in m.reasons]
    else:
        best = min(active, key=lambda m: m.score)
        base, reasons = best.score, list(best.reasons)
    extra, extra_reasons = soft_signals(sensor)
    metrics["soft_penalty"] = extra
    return min(100, base + extra), reasons + extra_reasons, metrics


class BehavioralModule(DetectionModule):
    slug: ClassVar[str] = "behavioral"
    title: ClassVar[str] = "Behavioral biometrics"
    description: ClassVar[str] = (
        "Scores mouse, keystroke, touch and motion telemetry from the sensor (and from the "
        "inline telemetry on transactional endpoints)."
    )
    category: ClassVar[str] = "behavioral"
    confidence: ClassVar[Confidence] = Confidence.HIGH  # concept; thresholds are lab-defined
    applies_to: ClassVar[frozenset[EndpointClass]] = frozenset(
        {EndpointClass.PAGE, EndpointClass.PROTECTED, EndpointClass.TRANSACTIONAL}
    )

    async def evaluate(self, ctx: RequestContext) -> Signal:
        sensor: dict[str, Any] | None = None
        telemetry_type, source = "standard", "sensor"
        if ctx.endpoint_class == EndpointClass.TRANSACTIONAL:
            sensor = payload_from_ctx(ctx)
            if sensor is not None:
                telemetry_type, source = "inline", "inline"
        if sensor is None:
            raw = await ctx.store.get(f"sensor:{ctx.session_id}") if ctx.session_id else None
            if not raw:
                return self.signal(
                    Verdict.FAIL, 90, "no sensor_data posted (no behavioral telemetry)"
                )
            try:
                sensor = json.loads(raw)
            except ValueError:
                return self.signal(Verdict.FAIL, 90, "unreadable behavioral telemetry")
        try:
            score, reasons, metrics = analyze(sensor)
        except (ValueError, TypeError, IndexError, KeyError, AttributeError):
            return self.signal(Verdict.FAIL, 90, "unreadable behavioral telemetry")
        extra = {
            "telemetry_type": telemetry_type,
            "source": source,
            "segment_hint": segment_hint(score, telemetry_type),
        }
        if score >= FAIL_AT:
            return self.signal(Verdict.FAIL, score, "; ".join(reasons), **metrics, **extra)
        if score >= WARN_AT:
            return self.signal(Verdict.WARN, score, "; ".join(reasons), **metrics, **extra)
        return self.signal(Verdict.PASS, score, "human-like behavior", **metrics, **extra)
