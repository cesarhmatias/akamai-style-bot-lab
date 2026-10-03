"""Case 7 - ``pixel_challenge``: the ``/akam/<n>/pixel_<hex>`` beacon (and what ``bm_sz`` is not).

Mechanism and real-world artifacts (report §1.2 case 7, tier MEDIUM)
--------------------------------------------------------------------
``bm_sz`` is a *seed cookie* issued on the first response (about four hours; see
``app.session``); it is not a challenge. The pixel is separate: public captures show
``/akam/11/pixel_16cff819`` (2019) and ``/akam/11/pixel_49faa00b`` (2019), still matched as
``/akam/\\d+/pixel_`` in 2026 [S]. Vendor docs add [V]: the HTML assigns a value to the global
``bazadebezolkohpepadr``, a script loads from ``/akam/<n>/<hex>``, the client POSTs pixel data
to ``/akam/<n>/pixel_<hex>``.

How the lab simulates it
------------------------
* ``page_snippets`` embeds ``bazadebezolkohpepadr = <int>`` (value LAB-DERIVED from the
  session with an HMAC) and ``<script src="/akam/13/<hex>" defer>`` (``n`` is fixed at 13,
  ``hex`` is 8 hex chars per session).
* ``handle_dynamic`` serves the script at ``GET /akam/13/<hex>`` and accepts the beacon at
  ``POST /akam/13/pixel_<hex>``. No router and no ``/config`` token hand-out any more: routers
  are mounted under ``/akam/<slug>``, so these paths go through the catch-all.
* Pixel data is LAB-DEFINED: form body ``p=<ts_ms>.<digest>`` with
  ``digest = sha256("<value>.<hex>.<ts_ms>.<bm_sz>")[:32 hex]`` and a +-120 s clock window.
  Success stores ``pixel:{sid}`` = ``ok``.
* The optional ``<noscript><img>`` fallback seen in search snippets is NOT confirmed (report
  §1.2 case 7: "I did not fetch a page that confirms it"), so it is not built.

Flags (both LOW, vendor-only, default off)
------------------------------------------
``pixel_ties_ak_bmsc``  A successful beacon re-issues ``ak_bmsc`` (stored hash at
                        ``pixel:bmsc:{sid}``); scoring then requires the client to present that
                        new ``ak_bmsc``. Vendors say the result is tied to ``ak_bmsc``.
``ak_bmsc_httponly``    ``ak_bmsc`` is issued HttpOnly (vendors describe it so). Consumed by
                        ``app.session.cookie_attrs``; declared here because this module owns
                        the ``ak_bmsc`` linkage.

How a client passes
-------------------
A pure-HTTP client can pass, which is realistic: (1) GET the page with cookies, (2) parse the
integer from ``bazadebezolkohpepadr=<int>;`` and the hex from ``src="/akam/<n>/<hex>"``, (3) POST
``p=<ts_ms>.<digest>`` as above to ``/akam/<n>/pixel_<hex>`` with the same ``bm_sz`` cookie (and
keep any ``Set-Cookie`` it returns). A browser just runs the served script.

Limits
------
The lab does not know what the real pixel body contains, nor which cookie it changes.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import time
from collections.abc import Callable
from pathlib import Path
from typing import ClassVar
from urllib.parse import parse_qs

from fastapi import Request
from fastapi.responses import JSONResponse, Response

from app.contract import (
    Confidence,
    DetectionModule,
    FlagSpec,
    RequestContext,
    Signal,
    Verdict,
)
from app.session import (
    COOKIE_AK_BMSC,
    SESSION_TTL,
    cookie_attrs,
    mac_hex,
    new_ak_bmsc,
    server_secret,
)

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
PIXEL_N = 13
GLOBAL_NAME = "bazadebezolkohpepadr"  # public artifact name from the report
CLOCK_WINDOW_S = 120
_PATH_RE = re.compile(r"^/akam/(\d+)/(pixel_)?([0-9a-f]{8})$")


def pixel_digest(value: int | str, hex_id: str, ts_ms: int | str, sid: str) -> str:
    """Lab-defined pixel digest (the exact computation the served script performs)."""
    raw = f"{value}.{hex_id}.{ts_ms}.{sid}".encode()
    return hashlib.sha256(raw).hexdigest()[:32]


def _ak_bmsc_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class PixelChallenge(DetectionModule):
    slug: ClassVar[str] = "pixel_challenge"
    title: ClassVar[str] = "Pixel beacon challenge"
    description: ClassVar[str] = (
        "A value embedded in the page HTML (bazadebezolkohpepadr) must be turned into pixel "
        "data and POSTed to /akam/<n>/pixel_<hex>. Replicable from pure HTTP by parsing the HTML."
    )
    category: ClassVar[str] = "js"
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    flags: ClassVar[list[FlagSpec]] = [
        FlagSpec(
            name="pixel_ties_ak_bmsc",
            description="A solved pixel re-issues ak_bmsc and scoring requires the new value.",
            confidence=Confidence.LOW,
            source="report §1.2 case 7, §3.1 (ak_bmsc linkage: vendors only)",
        ),
        FlagSpec(
            name="ak_bmsc_httponly",
            description="Issue the ak_bmsc cookie HttpOnly (consumed by session.cookie_attrs).",
            confidence=Confidence.LOW,
            source="report §1.2 case 7, §3.1 (ak_bmsc HttpOnly: vendors only)",
        ),
    ]

    def __init__(self, secret: bytes | None = None, clock: Callable[[], float] = time.time) -> None:
        self.secret = secret or server_secret("pixel")
        self.clock = clock
        self.src = (STATIC_DIR / "labcrypto.js").read_text(encoding="utf-8") + (
            STATIC_DIR / "pixel.src.js"
        ).read_text(encoding="utf-8")

    # ---- per-session artifacts -----------------------------------------------------------

    def value(self, sid: str) -> int:
        """The integer embedded as ``bazadebezolkohpepadr`` (lab-derived, 10 digits)."""
        return int(mac_hex(self.secret, "value", sid)[:12], 16) % 9_000_000_000 + 1_000_000_000

    def hex_id(self, sid: str) -> str:
        return mac_hex(self.secret, "hex", sid)[:8]

    def script_path(self, sid: str) -> str:
        return f"/akam/{PIXEL_N}/{self.hex_id(sid)}"

    def beacon_path(self, sid: str) -> str:
        return f"/akam/{PIXEL_N}/pixel_{self.hex_id(sid)}"

    def render_script(self, sid: str) -> str:
        return self.src.replace("@HEX@", self.hex_id(sid)).replace("@N@", str(PIXEL_N))

    # ---- scoring -------------------------------------------------------------------------

    async def evaluate(self, ctx: RequestContext) -> Signal:
        sid = ctx.session_id
        if not (sid and await ctx.store.get(f"pixel:{sid}") == "ok"):
            return self.signal(Verdict.FAIL, 70, "pixel beacon not received for this session")
        if ctx.flag("pixel_ties_ak_bmsc"):
            want = await ctx.store.get(f"pixel:bmsc:{sid}")
            have = ctx.cookies.get(COOKIE_AK_BMSC, "")
            if want and not (have and hmac.compare_digest(_ak_bmsc_hash(have), want)):
                return self.signal(
                    Verdict.FAIL, 70, "pixel solved but ak_bmsc was not updated (not tied)"
                )
        return self.signal(Verdict.PASS, 0, "pixel beacon received")

    # ---- page integration ----------------------------------------------------------------

    async def page_snippets(self, ctx: RequestContext) -> list[str]:
        sid = ctx.session_id
        if not sid:
            return []
        return [
            f'<script type="text/javascript">{GLOBAL_NAME}={self.value(sid)};</script>',
            f'<script type="text/javascript" src="{self.script_path(sid)}" defer></script>',
        ]

    async def handle_dynamic(self, request: Request, ctx: RequestContext) -> Response | None:
        sid = ctx.session_id
        m = _PATH_RE.match(request.url.path)
        if not (sid and m and int(m.group(1)) == PIXEL_N and m.group(3) == self.hex_id(sid)):
            return None
        if request.method == "GET" and not m.group(2):
            return Response(
                self.render_script(sid),
                media_type="application/javascript",
                headers={"Cache-Control": "no-store"},
            )
        if request.method == "POST" and m.group(2):
            return await self._beacon(request, ctx)
        return None

    async def _beacon(self, request: Request, ctx: RequestContext) -> Response:
        sid, store = ctx.session_id, ctx.store
        if "bm_sz" not in request.cookies:
            return JSONResponse({"ok": False, "error": "no_session"}, status_code=400)
        try:
            form = parse_qs((await request.body()).decode(), strict_parsing=True)
            ts_text, digest = form["p"][0].split(".", 1)
            ts_ms = int(ts_text)
        except (ValueError, KeyError, IndexError, UnicodeDecodeError):
            return JSONResponse({"ok": False, "error": "bad_request"}, status_code=400)
        if abs(self.clock() * 1000 - ts_ms) > CLOCK_WINDOW_S * 1000:
            return JSONResponse({"ok": False, "error": "stale"}, status_code=403)
        want = pixel_digest(self.value(sid), self.hex_id(sid), ts_ms, sid)
        if not hmac.compare_digest(digest, want):
            return JSONResponse({"ok": False, "error": "bad_pixel"}, status_code=403)
        await store.set(f"pixel:{sid}", "ok", ttl=SESSION_TTL)
        resp = JSONResponse({"ok": True})
        if ctx.flag("pixel_ties_ak_bmsc"):
            fresh = new_ak_bmsc()
            await store.set(f"pixel:bmsc:{sid}", _ak_bmsc_hash(fresh), ttl=SESSION_TTL)
            resp.set_cookie(COOKIE_AK_BMSC, fresh, **cookie_attrs(COOKIE_AK_BMSC, ctx.flags))
        return resp
