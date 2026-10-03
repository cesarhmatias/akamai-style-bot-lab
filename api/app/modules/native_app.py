"""``native_app``: native-app telemetry on ``/mobile/api/*`` (audit report §2.8).

Mechanism and tiers
-------------------
The Bot Manager Premier mobile SDK sends sensor data in the ``X-acf-sensor-data`` request
header, "ONLY on HTTP requests to URLs configured for protection" ([S], OutSystems plugin
README); Content Protector now has a Native App Traffic Protection SDK ([P], WSA changelog
2025-08-11) and the API lists an ``AKAMAI_MOBILE_CRYPTO`` challenge type ([P]). The header NAME
is MEDIUM (one integrator README, consistent with many repos); Akamai's SDK documentation is
login-gated, so the layout below is LAB-DEFINED and reproduces no real SDK format or key.

Lab header (LAB-DEFINED)
------------------------
::

    X-acf-sensor-data: lab1;<base64url(json)>;<hmac_sha256_hex(app_key, "lab1;" + base64url)>
    json = {"d": device id (16-64 hex), "av": app version "x.y.z", "sv": SDK version "x.y.z",
            "t": ts ms, "n": nonce, "p": request path, "s": sensor stream}
    sensor stream = list of samples [t_ms, ax, ay, az, gx, gy, gz]  (>= 8, t increasing)

Checks (``applies_to`` MOBILE only; ``details["telemetry_type"] = "native"``): missing /
malformed / wrong version formats (FAIL), stale > 60 s (FAIL), MAC mismatch or bound to another
path (BLOCK), replayed nonce (BLOCK), a sensor stream whose readings never change (FAIL, an
emulator tell). The lab app key is ``LAB_APP_KEY`` (env) or a documented constant shared with
the harness; it is NOT a secret, it only models the integrity of the SDK-to-server channel.

Client helper: :func:`build_acf_header`. The ``AKAMAI_MOBILE_CRYPTO`` JSON crypto challenge is a
challenge provider handled by the response agent's ``proof_of_work``, not by this module.

Limits
------
Real SDKs derive device attestation and keys in ways the public sources do not document.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import time
from collections.abc import Callable
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

HEADER_NAME = "x-acf-sensor-data"
VERSION = "lab1"
DEFAULT_APP_KEY = "lab-native-app-key-v1"
MAX_AGE_MS = 60_000
MAX_SKEW_MS = 5_000
NONCE_TTL = 180
MIN_SAMPLES = 8
TELEMETRY_TYPE = "native"
_DEVICE_RE = re.compile(r"^[0-9a-f]{16,64}$")
_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")


def app_key() -> str:
    return os.environ.get("LAB_APP_KEY", DEFAULT_APP_KEY)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _sign(key: str, body: str) -> str:
    return hmac.new(key.encode(), f"{VERSION};{body}".encode(), hashlib.sha256).hexdigest()


def build_acf_header(
    device_id: str,
    app_version: str,
    sdk_version: str,
    sensor: list[list[float]],
    *,
    path: str,
    ts_ms: int | None = None,
    nonce: str | None = None,
    key: str | None = None,
) -> str:
    """Build a lab ``X-acf-sensor-data`` value (for tests and the harness)."""
    ts = ts_ms if ts_ms is not None else int(time.time() * 1000)
    nonce = (
        nonce
        or hashlib.sha256(f"{device_id}{ts}{time.perf_counter_ns()}".encode()).hexdigest()[:16]
    )
    doc = {
        "d": device_id,
        "av": app_version,
        "sv": sdk_version,
        "t": ts,
        "n": nonce,
        "p": path,
        "s": sensor,
    }
    body = _b64url(json.dumps(doc, separators=(",", ":")).encode())
    return f"{VERSION};{body};{_sign(key or app_key(), body)}"


def verify_acf_header(
    value: str | None, *, path: str, now_ms: int, key: str | None = None
) -> tuple[str, str, dict[str, Any]]:
    """Return ``(kind, reason, doc)``; kind is ``ok`` or missing/malformed/stale/bad_mac/path."""
    if not value:
        return "missing", f"no {HEADER_NAME} header", {}
    parts = value.split(";")
    if len(parts) != 3 or parts[0] != VERSION:
        return "malformed", "malformed native sensor header", {}
    body, mac = parts[1], parts[2]
    if not hmac.compare_digest(_sign(key or app_key(), body), mac):
        return "bad_mac", "native sensor MAC invalid", {}
    try:
        doc = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        if not isinstance(doc, dict):
            raise ValueError("not an object")
        ok = (
            _DEVICE_RE.match(str(doc["d"]))
            and _SEMVER_RE.match(str(doc["av"]))
            and _SEMVER_RE.match(str(doc["sv"]))
            and isinstance(doc["s"], list)
            and isinstance(doc["n"], str)
            and doc["n"]
        )
        ts = int(doc["t"])
    except (ValueError, KeyError, TypeError, UnicodeDecodeError):
        return "malformed", "malformed native sensor payload", {}
    if not ok:
        return "malformed", "invalid device id / versions / stream in native sensor", {}
    age = now_ms - ts
    if age > MAX_AGE_MS or age < -MAX_SKEW_MS:
        return "stale", f"native sensor stale ({age} ms old)", doc
    if doc.get("p") != path:
        return "path", "native sensor bound to a different path", doc
    return "ok", "", doc


def stream_problem(stream: list[Any]) -> str | None:
    """Reason the sensor stream is not plausible device motion data, else None."""
    try:
        rows = [[float(x) for x in row] for row in stream]
    except (TypeError, ValueError):
        return "sensor stream is not numeric"
    if len(rows) < MIN_SAMPLES or any(len(r) != 7 for r in rows):
        return f"sensor stream needs >= {MIN_SAMPLES} samples of 7 values"
    if any(b[0] <= a[0] for a, b in pairwise(rows)):
        return "sensor stream timestamps are not increasing"
    if any(abs(v) > 1000 for r in rows for v in r[1:]):
        return "implausible sensor readings"
    if all(len({r[i] for r in rows}) == 1 for i in range(1, 7)):
        return "sensor readings never change (emulator)"
    return None


class NativeAppModule(DetectionModule):
    slug: ClassVar[str] = "native_app"
    title: ClassVar[str] = "Native app telemetry (mobile API)"
    description: ClassVar[str] = (
        "Requires a fresh, MAC'ed X-acf-sensor-data header with device id, versions and a "
        "sensor stream on /mobile/api/*."
    )
    category: ClassVar[str] = "js"
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    applies_to: ClassVar[frozenset[EndpointClass]] = frozenset({EndpointClass.MOBILE})

    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self.clock = clock

    async def evaluate(self, ctx: RequestContext) -> Signal:
        kind, reason, doc = verify_acf_header(
            ctx.header(HEADER_NAME), path=ctx.path, now_ms=int(self.clock() * 1000)
        )
        extra: dict[str, Any] = {"telemetry_type": TELEMETRY_TYPE, "kind": kind}
        if kind in {"missing", "malformed", "stale"}:
            return self.signal(Verdict.FAIL, 90, reason, **extra)
        if kind in {"bad_mac", "path"}:
            return self.signal(Verdict.BLOCK, 100, reason, **extra)
        problem = stream_problem(doc["s"])
        if problem:
            return self.signal(Verdict.FAIL, 80, problem, **extra)
        if await ctx.store.incr(f"acf:nonce:{doc['d']}:{doc['n']}", NONCE_TTL) > 1:
            return self.signal(
                Verdict.BLOCK,
                100,
                "native sensor nonce already used (replay)",
                **{**extra, "kind": "replay"},
            )
        return self.signal(
            Verdict.PASS,
            0,
            "fresh native-app sensor",
            device=doc["d"],
            app_version=doc["av"],
            sdk_version=doc["sv"],
            **extra,
        )
