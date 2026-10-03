"""Case 5 - ``sensor_data``: browser telemetry posted by an obfuscated JS sensor.

Mechanism
---------
A ``<script>`` near the end of ``<body>`` collects device, interaction and integrity telemetry
and POSTs it as ``{"sensor_data": "<opaque string>"}``. The server decodes it, validates it and
refreshes the ``_abck`` cookie with ``Set-Cookie``.

How real Akamai uses it (report §1.2 case 5, tier MEDIUM; vendor-sourced details flagged)
------------------------------------------------------------------------------------------
* MEDIUM: the script is served from a long, random, multi-segment same-origin path that
  changes over time (example ``/yMOlMy/yS/3T/NVx6/...``); the client POSTs back to that SAME
  path; 1-3 posts are typical. Akamai itself says "dynamic obfuscation of code and telemetry
  protects against reverse engineering" ([P], 2023 brief).
* MEDIUM (a single reverse-engineering author, [V]): "v3" payloads start with
  ``3;0;1;0;<bm_sz-derived hash>;...`` and key the encoding to the script build and the
  session's ``bm_sz``, so a sensor made for one script or session cannot be reused.
* HIGH concept / telemetry categories: device fingerprint, interaction (mouse, keys, touch,
  scroll, focus, device motion), timing and integrity probes.

How the lab simulates it
------------------------
* Script path: ``/<6>/<2>/<2>/<4>/<14>/<14>/<10>/<8>/<3>`` characters, derived with an HMAC of
  (server secret, script build id, ``bm_sz``). It rotates per session and per script build and
  is injected through ``page_snippets``. ``handle_dynamic`` serves the script (GET) and accepts
  the POST at the same path.
* Payload, LAB-DEFINED (it imitates only the *shape* of community-described v3 payloads, it is
  not the real encoding)::

      lab3;0;1;<post index>;<hash8>;<base64( xor( json, key ) )>
      hash8 = HMAC(secret, build, bm_sz)[:8]      key = HMAC(secret, build, bm_sz) as hex

  A payload minted for session A, or for another script build, fails in session B because the
  hash8 and the xor key both differ.
* 1-3 valid posts per session; the post index must equal the number already accepted, so a
  verbatim replay of an earlier POST is rejected. The latest decoded JSON is stored at
  ``sensor:{sid}`` (consumed by ``behavioral``, ``js_integrity``, ``version_consistency``;
  ``navigator.brands`` is included), the count at ``sensor:n:{sid}``, and the integrity block
  of every decodable post at ``sensor:integrity:{sid}`` (so ``js_integrity`` can explain a
  rejection).
* ``_abck`` validation: the first valid post validates the session (default mode); with the
  LOW ``abck_n_posts`` flag, N valid posts are needed. The fingerprint binding (JA4 family,
  UA, /24) is recorded at validation; a later post from a different binding is rejected.
* Structural acceptance only: ``validate_sensor`` rejects ``navigator.webdriver === true`` (as
  before) but is not coupled to the integrity probes, which ``js_integrity`` scores.

How a client passes
-------------------
Run the page in a real browser, or from pure HTTP: parse the ``<script src>`` path from the
HTML, GET it, extract the per-session key and hash from the script, and POST a well-formed
``lab3`` payload. The harness's pure-HTTP client intentionally does not do this.
``window.__akSensorDone`` / ``ak:sensor`` / ``window.__akSensorFlush()`` keep their semantics.

Limits
------
Encoding, probes and thresholds are lab-defined; Akamai's current payload version prefix and
its real keying are unknown (report §3.2 item 3).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from pathlib import Path
from typing import Any, ClassVar

from fastapi import Request
from fastapi.responses import JSONResponse, Response

from app.contract import Confidence, DetectionModule, RequestContext, Signal, Verdict
from app.modules.abck_cookie import required_posts
from app.session import (
    COOKIE_ABCK,
    SESSION_TTL,
    abck_binding,
    abck_cookie_value,
    abck_ident,
    binding_from_ctx,
    binding_mismatch,
    cookie_attrs,
    mac_hex,
    mark_abck_validated,
    parse_abck,
    server_secret,
)

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
SRC_PATH = STATIC_DIR / "sensor.src.js"
TTL = SESSION_TTL
MAX_BODY = 512_000
MAX_POSTS = 3
PAYLOAD_VERSION = "lab3"
PATH_SEGMENTS = (6, 2, 2, 4, 14, 14, 10, 8, 3)
_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

_STR_RE = re.compile(r"'([^'\\\n]*)'")
_ID_RE = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*")
_COMMENT_RE = re.compile(r"/\*.*?\*/|^[ \t]*//[^\n]*$", re.S | re.M)


class PayloadError(ValueError):
    """The sensor payload cannot be accepted (the message is the rejection reason)."""


class SensorCodec:
    """LAB-DEFINED sensor encoding keyed to (server secret, script build id, bm_sz)."""

    def __init__(self, secret: bytes, build: str) -> None:
        self.secret = secret
        self.build = build

    def _mac(self, label: str, sid: str) -> str:
        return mac_hex(self.secret, label, self.build, sid)

    def key(self, sid: str) -> str:
        """Per-session xor key (32 hex chars)."""
        return self._mac("key", sid)[:32]

    def prefix_hash(self, sid: str) -> str:
        """The ``bm_sz``-derived hash8 carried in the payload prefix."""
        return self._mac("hash", sid)[:8]

    def path(self, sid: str) -> str:
        """Per-session random multi-segment same-origin script path."""
        stream = bytes.fromhex(self._mac("path-a", sid) + self._mac("path-b", sid))
        chars = "".join(_ALPHABET[b % len(_ALPHABET)] for b in stream)
        out, pos = [], 0
        for n in PATH_SEGMENTS:
            out.append(chars[pos : pos + n])
            pos += n
        return "/" + "/".join(out)

    def encode(self, obj: Any, sid: str, idx: int = 0) -> str:
        """Python mirror of the JS encoder (tests and non-browser tooling)."""
        key = self.key(sid).encode()
        raw = json.dumps(obj, separators=(",", ":")).encode()
        body = base64.b64encode(bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))).decode()
        return f"{PAYLOAD_VERSION};0;1;{idx};{self.prefix_hash(sid)};{body}"

    def decode(self, payload: str, sid: str) -> tuple[int, dict[str, Any]]:
        """Return ``(post index, decoded object)`` or raise :class:`PayloadError`."""
        parts = payload.split(";", 5)
        if len(parts) != 6 or parts[0] != PAYLOAD_VERSION or parts[1:3] != ["0", "1"]:
            raise PayloadError("unknown payload version")
        if not parts[3].isdigit() or int(parts[3]) >= MAX_POSTS:
            raise PayloadError("bad post index")
        if parts[4] != self.prefix_hash(sid):
            raise PayloadError("payload not minted for this session/script build")
        key = self.key(sid).encode()
        try:
            raw = base64.b64decode(parts[5], validate=True)
            data = json.loads(bytes(b ^ key[i % len(key)] for i, b in enumerate(raw)).decode())
        except (ValueError, binascii.Error, UnicodeDecodeError) as exc:
            raise PayloadError("undecodable payload") from exc
        if not isinstance(data, dict):
            raise PayloadError("payload is not an object")
        return int(parts[3]), data


def build_id(secret: bytes, src: str | None = None) -> str:
    """Script build id: changes with the server secret or the sensor source."""
    src = SRC_PATH.read_text(encoding="utf-8") if src is None else src
    return hashlib.sha256(secret + src.encode()).hexdigest()[:8]


def obfuscate(src: str, seed_material: str) -> str:
    """String-array rotation + hex identifiers. Deterministic for one ``seed_material``.

    Placeholders (``@KEY@`` ...) must already be substituted by the caller."""
    seed = hashlib.sha256(f"obf:{seed_material}".encode()).digest()
    src = _COMMENT_RE.sub("", src)
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
    """Return a rejection reason, or None when the sensor is structurally valid and plausible.

    Integrity (native getters, framework globals, ...) is NOT judged here: ``js_integrity``
    scores it, so ``_abck`` validation is not coupled to it. Only ``webdriver === true``
    (the sensor's own flag) rejects, as before."""
    try:
        nav, scr, tm = data["navigator"], data["screen"], data["timing"]
        mouse, counts = data["mouse"], data["counts"]
        t0, t1 = float(data["t0"]), float(data["t1"])
        if not all(isinstance(x, dict) for x in (nav, scr, tm, counts)):
            return "malformed sections"
        if not isinstance(mouse, list):
            return "malformed mouse"
        if any(not isinstance(data.get(k, []), list) for k in ("keys", "touch", "scroll")):
            return "malformed interaction lists"
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


class SensorDataModule(DetectionModule):
    slug: ClassVar[str] = "sensor_data"
    title: ClassVar[str] = "Sensor data (JS telemetry)"
    description: ClassVar[str] = (
        "Requires a valid obfuscated-JS telemetry POST (sensor_data) to the session's "
        "per-session random script path."
    )
    category: ClassVar[str] = "js"
    confidence: ClassVar[Confidence] = Confidence.MEDIUM

    def __init__(self, secret: bytes | None = None, build: str | None = None) -> None:
        self.secret = secret or server_secret("sensor")
        self.src = SRC_PATH.read_text(encoding="utf-8")
        self.codec = SensorCodec(self.secret, build or build_id(self.secret, self.src))

    # ---- scoring -------------------------------------------------------------------------

    async def evaluate(self, ctx: RequestContext) -> Signal:
        sid = ctx.session_id
        if sid and ctx.store is not None:
            if await ctx.store.get(f"sensor:{sid}"):
                posts = int(await ctx.store.get(f"sensor:n:{sid}") or 0)
                return self.signal(Verdict.PASS, 0, "valid sensor_data received", posts=posts)
            rej = await ctx.store.get(f"sensor_rejected:{sid}")
            if rej:
                return self.signal(Verdict.FAIL, 90, f"sensor_data rejected: {rej}")
        return self.signal(Verdict.FAIL, 90, "no sensor_data posted (JS not executed)")

    # ---- page integration ----------------------------------------------------------------

    async def page_snippets(self, ctx: RequestContext) -> list[str]:
        if not ctx.session_id:
            return []
        return [f'<script type="text/javascript" src="{self.codec.path(ctx.session_id)}"></script>']

    def render_script(self, sid: str, cdp: bool = False) -> str:
        """The per-session obfuscated sensor (deterministic for a session + build)."""
        src = (
            self.src.replace("@KEY@", self.codec.key(sid))
            .replace("@HASH@", self.codec.prefix_hash(sid))
            .replace("@PATH@", self.codec.path(sid))
            .replace("@CDP@", "1" if cdp else "0")
        )
        return obfuscate(src, f"{self.codec.build}:{sid}")

    async def handle_dynamic(self, request: Request, ctx: RequestContext) -> Response | None:
        sid = ctx.session_id
        if not sid or request.method not in {"GET", "POST"}:
            return None
        if request.url.path != self.codec.path(sid):
            return None
        if request.method == "GET":
            return Response(
                self.render_script(sid, ctx.flag("cdp_probes")),
                media_type="application/javascript",
                headers={"Cache-Control": "no-store"},
            )
        return await self._post(request, ctx)

    async def _post(self, request: Request, ctx: RequestContext) -> Response:
        sid, store = ctx.session_id, ctx.store

        def bad(reason: str, status: int = 400) -> Response:
            return JSONResponse({"success": False, "reason": reason}, status_code=status)

        async def reject(reason: str) -> Response:
            await store.set(f"sensor_rejected:{sid}", reason, TTL)
            return bad(reason)

        if "bm_sz" not in request.cookies:
            return bad("no session (bm_sz cookie missing)")
        raw = await request.body()
        if len(raw) > MAX_BODY:
            return bad("payload too large", 413)
        posts = int(await store.get(f"sensor:n:{sid}") or 0)
        if posts >= MAX_POSTS:
            return bad("too many sensor posts for this session", 429)
        try:
            idx, data = self.codec.decode(json.loads(raw)["sensor_data"], sid)
        except PayloadError as exc:
            return await reject(str(exc))
        except (ValueError, KeyError, TypeError, AttributeError):
            return await reject("undecodable payload")
        integrity = {
            "integrity": data.get("integrity"),
            "navigator": data.get("navigator"),
            "ua": request.headers.get("user-agent", ""),
        }
        await store.set(
            f"sensor:integrity:{sid}", json.dumps(integrity, separators=(",", ":")), TTL
        )
        if idx != posts:
            return await reject("unexpected post index (replayed or out-of-order sensor)")
        reason = validate_sensor(data, request.headers.get("user-agent", ""))
        if reason:
            return await reject(reason)
        binding = binding_from_ctx(ctx)
        bound = await abck_binding(store, sid)
        if bound is not None and [d for d in binding_mismatch(bound, binding) if d != "net"]:
            return await reject("client fingerprint changed since the session was validated")

        await store.set(f"sensor:{sid}", json.dumps(data, separators=(",", ":")), TTL)
        await store.delete(f"sensor_rejected:{sid}")
        n = await store.incr(f"sensor:n:{sid}", TTL)
        n_posts_mode = ctx.flag("abck_n_posts")
        required = required_posts() if n_posts_mode else 1
        validated = n >= required
        if validated and bound is None:
            await mark_abck_validated(store, sid, binding=binding)
        # Refresh _abck: keep the id, change the blob; flag ~0~ only in the LOW tilde0 mode.
        prev = parse_abck(request.cookies.get(COOKIE_ABCK, ""))
        value = abck_cookie_value(
            validated,
            tilde0=ctx.flag("abck_tilde0_mode") and not n_posts_mode,
            ident=prev[0] if prev else abck_ident(sid),
        )
        resp = JSONResponse({"success": True, "more": max(0, required - n)})
        resp.set_cookie(COOKIE_ABCK, value, **cookie_attrs(COOKIE_ABCK, ctx.flags))
        return resp
