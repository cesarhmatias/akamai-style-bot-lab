"""``inline_telemetry``: per-request telemetry attached to transactional calls (audit report §2.5).

Mechanism
---------
Akamai separates "Web client - standard telemetry" (first-party cookies) from "Web client -
inline telemetry" (requests "to which Bot Manager attaches user telemetry directly") and
native apps ([P], WSA dimensions 2026-09-30). Account Protector protected operations take
per-type thresholds for ``standard``, ``inline``, ``nativeSdkIos`` and ``nativeSdkAndroid``
([P], Terraform docs 2026-03-01); Bot Manager has a transactional-endpoint resource keyed to API
operations ([P]). This is where replaying a cookie from a solved session stops working.

Tiers
-----
* HIGH: the concept (a fresh telemetry blob bound to the protected request itself) and the
  three telemetry types. Inline thresholds in the report's UI example are 1-28 / 29-80 /
  81-100 (cautious / strict / aggressive); standard is 1-20 / 21-60 / 61-100.
* MEDIUM (vendor-observed, report §3.1): the header name ``akamai-bm-telemetry`` and its
  ``&&&``-separated segments including ``e=`` and ``sensor_data=``. The layout below is
  LAB-DEFINED around that shape; no real Akamai encoding, key or MAC is reproduced.

Wire format (LAB-DEFINED)
-------------------------
::

    akamai-bm-telemetry: a=lab1&&&t=<ts ms>&&&n=<nonce 16 hex>&&&h=<request hash>
                         &&&e=<mac>&&&sensor_data=<payload>     (one line on the wire)

    h = sha256( METHOD + " " + path + "\\n" + sha256_hex(body) )      body "" -> sha256 of empty
    e = hmac_sha256( key, "a\\nt\\nn\\nh\\nsensor_data" )             hex
    key = HMAC(server secret, bm_sz)[:32 hex], delivered in the page markup (window.__akInline)
    sensor_data = base64url( JSON of keystroke / mouse / touch / scroll telemetry captured while
                  the form was filled; key identities are never recorded, only timings )

A page script (``page_snippets``) wraps ``fetch`` and ``XMLHttpRequest`` for ``/api/login`` and
``/api/checkout`` and attaches a fresh header to every request (string bodies only). Markup also
carries the server time so a skewed client clock does not break the staleness check.

Server checks (``applies_to`` TRANSACTIONAL only)
-------------------------------------------------
missing (FAIL) / malformed (FAIL) / wrong MAC, i.e. another session's or tampered telemetry
(BLOCK) / stale > 30 s or from the future (FAIL) / request hash mismatch, i.e. telemetry lifted
from another request (BLOCK) / nonce already seen, i.e. replay (BLOCK). ``details`` always
carries ``telemetry_type = "inline"`` so the engine can use the inline thresholds. The decoded
payload is kept at ``inline:last:{sid}``; nonces at ``inline:nonce:{sid}:{nonce}``.

How a client passes
-------------------
A browser gets it from the page script for free. A pure-HTTP client must parse ``window.__akInline``
from the HTML, build the payload itself (fabricating plausible interaction data, which
``behavioral`` then judges on this endpoint) and compute ``h``/``e`` per request.

Limits
------
Any client that can read the markup can compute the MAC: the lab models replay and staleness
resistance, not secrecy of the key.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

from app.contract import (
    Confidence,
    DetectionModule,
    EndpointClass,
    RequestContext,
    Signal,
    Verdict,
)
from app.session import SESSION_TTL, server_secret

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
HEADER_NAME = "akamai-bm-telemetry"
VERSION = "lab1"
PROTECTED_PATHS = ("/api/login", "/api/checkout")
MAX_AGE_MS = 30_000
MAX_SKEW_MS = 5_000
NONCE_TTL = 120
MAX_PAYLOAD = 64_000
TELEMETRY_TYPE = "inline"
_SEP = "&&&"


def telemetry_key(sid: str, secret: bytes | None = None) -> str:
    """Per-session MAC key (32 hex chars) handed to the page in markup."""
    key = secret or server_secret("inline")
    return hmac.new(key, f"key:{sid}".encode(), hashlib.sha256).hexdigest()[:32]


def request_hash(method: str, path: str, body_sha256: str) -> str:
    """Hash binding the telemetry to one request (``body_sha256`` "" = empty body)."""
    body = body_sha256 or hashlib.sha256(b"").hexdigest()
    return hashlib.sha256(f"{method.upper()} {path}\n{body}".encode()).hexdigest()


def _mac(key: str, ver: str, ts: str, nonce: str, rhash: str, sensor: str) -> str:
    msg = "\n".join([ver, ts, nonce, rhash, sensor])
    return hmac.new(key.encode(), msg.encode(), hashlib.sha256).hexdigest()


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def build_header(
    sid: str,
    method: str,
    path: str,
    body: bytes,
    payload: dict[str, Any],
    *,
    ts_ms: int | None = None,
    nonce: str | None = None,
    secret: bytes | None = None,
) -> str:
    """Python mirror of the page script (tests and, later, the harness's pure-HTTP client)."""
    ts = str(ts_ms if ts_ms is not None else int(time.time() * 1000))
    nonce = nonce or hashlib.sha256(f"{sid}{ts}{time.perf_counter_ns()}".encode()).hexdigest()[:16]
    rhash = request_hash(method, path, hashlib.sha256(body).hexdigest())
    sensor = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    mac = _mac(telemetry_key(sid, secret), VERSION, ts, nonce, rhash, sensor)
    return _SEP.join(
        [f"a={VERSION}", f"t={ts}", f"n={nonce}", f"h={rhash}", f"e={mac}", f"sensor_data={sensor}"]
    )


@dataclass
class TelemetryResult:
    """Outcome of verifying one header. ``kind`` is ``ok`` or the failure class."""

    kind: str
    reason: str = ""
    nonce: str = ""
    age_ms: int = 0
    mac_ok: bool = False
    payload: dict[str, Any] | None = None

    @property
    def ok(self) -> bool:
        return self.kind == "ok"


def parse_header(value: str) -> dict[str, str] | None:
    fields: dict[str, str] = {}
    for part in value.split(_SEP):
        k, sep, v = part.partition("=")
        if not sep or not k:
            return None
        fields[k] = v
    need = {"a", "t", "n", "h", "e", "sensor_data"}
    return fields if need <= fields.keys() else None


def verify_header(
    value: str | None,
    *,
    sid: str,
    method: str,
    path: str,
    body_sha256: str,
    now_ms: int,
    secret: bytes | None = None,
) -> TelemetryResult:
    """Stateless checks (everything except nonce replay). The decoded payload is returned
    whenever the MAC verifies, even if the timestamp or request hash is wrong."""
    if not value:
        return TelemetryResult("missing", "no akamai-bm-telemetry header")
    fields = parse_header(value) if len(value) <= MAX_PAYLOAD else None
    if fields is None or fields["a"] != VERSION or not fields["t"].isdigit():
        return TelemetryResult("malformed", "malformed telemetry header")
    want = _mac(
        telemetry_key(sid, secret),
        fields["a"],
        fields["t"],
        fields["n"],
        fields["h"],
        fields["sensor_data"],
    )
    if not hmac.compare_digest(want, fields["e"]):
        return TelemetryResult("bad_mac", "telemetry MAC invalid (other session or tampered)")
    payload: dict[str, Any] | None
    try:
        raw = fields["sensor_data"]
        data = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
        payload = data if isinstance(data, dict) else None
    except (ValueError, UnicodeDecodeError):
        payload = None
    if payload is None:
        return TelemetryResult("malformed", "telemetry payload undecodable", mac_ok=True)
    age = now_ms - int(fields["t"])

    def result(kind: str, reason: str = "") -> TelemetryResult:
        return TelemetryResult(
            kind, reason, nonce=fields["n"], age_ms=age, mac_ok=True, payload=payload
        )

    if age > MAX_AGE_MS or age < -MAX_SKEW_MS:
        return result("stale", f"telemetry stale ({age} ms old)")
    if fields["h"] != request_hash(method, path, body_sha256):
        return result("hash_mismatch", "telemetry bound to a different request")
    return result("ok")


def payload_from_ctx(ctx: RequestContext, now_ms: int | None = None) -> dict[str, Any] | None:
    """The decoded inline payload of this request when its MAC verifies (used by behavioral)."""
    res = verify_header(
        ctx.header(HEADER_NAME),
        sid=ctx.session_id,
        method=ctx.method,
        path=ctx.path,
        body_sha256=ctx.body_sha256,
        now_ms=now_ms if now_ms is not None else int(time.time() * 1000),
    )
    return res.payload if res.mac_ok else None


class InlineTelemetryModule(DetectionModule):
    slug: ClassVar[str] = "inline_telemetry"
    title: ClassVar[str] = "Inline telemetry (transactional)"
    description: ClassVar[str] = (
        "Requires a fresh, request-bound akamai-bm-telemetry header on /api/login and "
        "/api/checkout; rejects missing, stale, replayed or re-targeted telemetry."
    )
    category: ClassVar[str] = "js"
    confidence: ClassVar[Confidence] = Confidence.HIGH  # concept; header name is MEDIUM
    applies_to: ClassVar[frozenset[EndpointClass]] = frozenset({EndpointClass.TRANSACTIONAL})

    def __init__(self, secret: bytes | None = None, clock: Callable[[], float] = time.time) -> None:
        self.secret = secret
        self.clock = clock
        self.src = (STATIC_DIR / "labcrypto.js").read_text(encoding="utf-8") + (
            STATIC_DIR / "inline.src.js"
        ).read_text(encoding="utf-8")

    async def page_snippets(self, ctx: RequestContext) -> list[str]:
        if not ctx.session_id:
            return []
        cfg = {
            "k": telemetry_key(ctx.session_id, self.secret),
            "v": VERSION,
            "p": list(PROTECTED_PATHS),
            "s": int(self.clock() * 1000),
        }
        return [
            f'<script type="text/javascript">window.__akInline={json.dumps(cfg)};</script>',
            f'<script type="text/javascript">{self.src}</script>',
        ]

    async def evaluate(self, ctx: RequestContext) -> Signal:
        sid, store = ctx.session_id, ctx.store
        res = verify_header(
            ctx.header(HEADER_NAME),
            sid=sid,
            method=ctx.method,
            path=ctx.path,
            body_sha256=ctx.body_sha256,
            now_ms=int(self.clock() * 1000),
            secret=self.secret,
        )
        extra: dict[str, Any] = {"telemetry_type": TELEMETRY_TYPE, "kind": res.kind}
        if res.kind in {"missing", "malformed"}:
            return self.signal(Verdict.FAIL, 95, res.reason, **extra)
        if res.kind == "stale":
            return self.signal(Verdict.FAIL, 90, res.reason, age_ms=res.age_ms, **extra)
        if res.kind in {"bad_mac", "hash_mismatch"}:
            return self.signal(Verdict.BLOCK, 100, res.reason, **extra)
        if await store.incr(f"inline:nonce:{sid}:{res.nonce}", NONCE_TTL) > 1:
            extra["kind"] = "replay"
            return self.signal(Verdict.BLOCK, 100, "telemetry nonce already used (replay)", **extra)
        await store.set(f"inline:last:{sid}", json.dumps(res.payload), SESSION_TTL)
        return self.signal(
            Verdict.PASS, 0, "fresh request-bound telemetry", age_ms=res.age_ms, **extra
        )
