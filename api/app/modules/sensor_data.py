"""Case 5 - ``sensor_data``: browser telemetry posted by an obfuscated JS sensor.

Real Akamai Bot Manager ships a heavily obfuscated script that gathers device and
behaviour telemetry and POSTs it as ``{"sensor_data": "<opaque string>"}``. The
server decodes it, scores it, and on success upgrades the ``_abck`` cookie from
``~-1~`` to ``~0~``. This module mirrors that flow (no real Akamai code).

Client protocol
---------------
1. ``GET /akam/sensor_data/sensor.js`` (with the ``bm_sz`` cookie) -> JS with a
   per-session XOR key baked in. Readable source: ``static/sensor.src.js``.
2. The script collects mouse path / event counts / timing / screen / navigator /
   timezone / canvas hash, then ``POST /akam/sensor_data/sensor`` with
   ``{"sensor_data": base64(xor(utf8(json), key))}``; ``key`` = first 32 hex chars of
   ``sha256("sensor-key:" + bm_sz)`` repeated cyclically.
3. 200 ``{"success": true}`` + ``Set-Cookie: _abck=<...~0~...>``; 400 otherwise.
4. The script sets ``window.__akSensorDone = true`` (``__akSensorOk`` = success) and
   dispatches ``ak:sensor`` on ``window``. ``window.__akSensorFlush()`` sends early.

Caveat: Playwright/Selenium expose ``navigator.webdriver === true`` by default.
This lab rejects such sensors (realistic); the Playwright client must mask it with
an init script (``Object.defineProperty(navigator, 'webdriver', {get: () => false})``).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from pathlib import Path
from typing import Any, ClassVar

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from app.contract import DetectionModule, RequestContext, Signal, Verdict
from app.session import abck_cookie_value, mark_abck_validated

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
SRC_PATH = STATIC_DIR / "sensor.src.js"
TTL = 3600
MAX_BODY = 512_000

_STR_RE = re.compile(r"'([^'\\\n]*)'")
_ID_RE = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*")
_COMMENT_RE = re.compile(r"/\*.*?\*/|^\s*//.*$", re.S | re.M)


def sensor_key(session_id: str) -> str:
    """Per-session XOR key (32 hex chars) derived from bm_sz."""
    return hashlib.sha256(f"sensor-key:{session_id}".encode()).hexdigest()[:32]


def encode_payload(obj: Any, session_id: str) -> str:
    """Python mirror of the JS encoder (used by tests and non-browser tooling)."""
    key = sensor_key(session_id).encode()
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.b64encode(bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))).decode()


def decode_payload(payload: str, session_id: str) -> dict[str, Any]:
    key = sensor_key(session_id).encode()
    raw = base64.b64decode(payload, validate=True)
    data = json.loads(bytes(b ^ key[i % len(key)] for i, b in enumerate(raw)).decode())
    if not isinstance(data, dict):
        raise ValueError("payload is not an object")
    return data


def obfuscate(src: str, session_id: str) -> str:
    """String-array rotation + hex identifiers + per-session key. Deterministic."""
    seed = hashlib.sha256(f"obf:{session_id}".encode()).digest()
    src = _COMMENT_RE.sub("", src).replace("@KEY@", sensor_key(session_id))
    strings: list[str] = []

    def str_repl(m: re.Match[str]) -> str:
        s = m.group(1)
        if s not in strings:
            strings.append(s)
        return f"{dec}({strings.index(s)})"

    names: dict[str, str] = {}
    used: set[str] = set()

    def mk(tag: str) -> str:
        i = 0
        while True:
            n = "_0x" + hashlib.sha256(seed + f"{tag}{i}".encode()).hexdigest()[:6]
            if n not in used:
                used.add(n)
                return n
            i += 1

    arr, dec = mk("arr"), mk("dec")

    def id_repl(m: re.Match[str]) -> str:
        return names.setdefault(m.group(0), mk(m.group(0)))

    body = _ID_RE.sub(id_repl, _STR_RE.sub(str_repl, src))
    n = len(strings)
    rot = (seed[0] % (n - 1) + 1) if n > 1 else 0
    enc = [base64.b64encode(s.encode()).decode() for s in strings]
    stored = enc[-rot:] + enc[:-rot] if rot else enc  # rotated right by rot
    lit = ",".join(json.dumps(x) for x in stored)
    shim = (
        f"var {arr}=[{lit}];(function(a,n){{while(n--)a.push(a.shift());}})({arr},{rot});"
        f"function {dec}(i){{return atob({arr}[i]);}}"
    )
    return f"(function(){{{shim}{body}}})();"


def validate_sensor(data: dict[str, Any], request_ua: str) -> str | None:
    """Return a rejection reason, or None when the sensor is structurally valid and plausible."""
    try:
        nav, scr, tm = data["navigator"], data["screen"], data["timing"]
        mouse, counts = data["mouse"], data["counts"]
        t0, t1 = float(data["t0"]), float(data["t1"])
        if not all(isinstance(x, dict) for x in (nav, scr, tm, counts)):
            return "malformed sections"
        if not isinstance(mouse, list):
            return "malformed mouse"
        if nav["webdriver"] is not False:
            return "navigator.webdriver is set (automation)"
        if nav["userAgent"] != request_ua:
            return "navigator.userAgent differs from request User-Agent"
        hc = nav["hardwareConcurrency"]
        if not isinstance(hc, int) or isinstance(hc, bool) or not 1 <= hc <= 256:
            return "implausible hardwareConcurrency"
        w, h = scr["width"], scr["height"]
        if not (isinstance(w, int | float) and isinstance(h, int | float)):
            return "malformed screen"
        if not (200 <= w <= 16000 and 200 <= h <= 16000):
            return "implausible screen size"
        if scr["availWidth"] > w or not 8 <= scr["colorDepth"] <= 48:
            return "implausible screen"
        if not 0.5 <= float(scr["pixelRatio"]) <= 8:
            return "implausible pixelRatio"
        if not data.get("tz") or not data.get("canvas"):
            return "missing timezone/canvas"
        deltas = tm["deltas"]
        if not isinstance(deltas, list) or len(deltas) < 5:
            return "missing timing samples"
        if len({round(float(d), 3) for d in deltas}) < 2:
            return "no timing jitter"
        if t1 < t0:
            return "non monotonic session clock"
        last = -1.0
        for p in mouse:
            if not (isinstance(p, list) and len(p) == 3):
                return "malformed mouse point"
            if float(p[2]) < last:
                return "non monotonic mouse timestamps"
            last = float(p[2])
    except (KeyError, TypeError, ValueError):
        return "malformed sensor structure"
    return None


def _store_of(request: Any) -> Any:
    return request.app.state.store


class SensorDataModule(DetectionModule):
    slug: ClassVar[str] = "sensor_data"
    title: ClassVar[str] = "Sensor data (JS telemetry)"
    description: ClassVar[str] = (
        "Requires a valid obfuscated-JS telemetry POST (sensor_data) for the session."
    )
    category: ClassVar[str] = "js"
    client_scripts: ClassVar[list[str]] = ["sensor.js"]

    async def evaluate(self, ctx: RequestContext) -> Signal:
        sid = ctx.session_id
        if sid and ctx.store is not None:
            if await ctx.store.get(f"sensor:{sid}"):
                return self.signal(Verdict.PASS, 0, "valid sensor_data received")
            rej = await ctx.store.get(f"sensor_rejected:{sid}")
            if rej:
                return self.signal(Verdict.FAIL, 90, f"sensor_data rejected: {rej}")
        return self.signal(Verdict.FAIL, 90, "no sensor_data posted (JS not executed)")

    def router(self) -> Any:
        r = APIRouter()
        src = SRC_PATH.read_text(encoding="utf-8")

        @r.get("/sensor.js")
        async def sensor_js(request: Request) -> Response:
            sid = request.cookies.get("bm_sz", "")
            return Response(
                obfuscate(src, sid),
                media_type="application/javascript",
                headers={"Cache-Control": "no-store"},
            )

        @r.post("/sensor")
        async def sensor_post(request: Request) -> Response:
            sid = request.cookies.get("bm_sz", "")

            def bad(reason: str, status: int = 400) -> Response:
                return JSONResponse({"success": False, "reason": reason}, status_code=status)

            if not sid:
                return bad("no session (bm_sz cookie missing)")
            raw = await request.body()
            if len(raw) > MAX_BODY:
                return bad("payload too large", 413)
            store = _store_of(request)
            try:
                payload = json.loads(raw)["sensor_data"]
                data = decode_payload(payload, sid)
            except (ValueError, KeyError, TypeError, binascii.Error, UnicodeDecodeError):
                await store.set(f"sensor_rejected:{sid}", "undecodable payload", TTL)
                return bad("undecodable payload")
            reason = validate_sensor(data, request.headers.get("user-agent", ""))
            if reason:
                await store.set(f"sensor_rejected:{sid}", reason, TTL)
                return bad(reason)
            await store.set(f"sensor:{sid}", json.dumps(data, separators=(",", ":")), TTL)
            await mark_abck_validated(store, sid)
            await store.delete(f"sensor_rejected:{sid}")
            resp = JSONResponse({"success": True})
            resp.set_cookie("_abck", abck_cookie_value(True), path="/", max_age=TTL)
            return resp

        return r
