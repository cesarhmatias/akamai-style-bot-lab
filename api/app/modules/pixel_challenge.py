"""bm_sz-era pixel beacon: GIF fetch + JSON beacon carrying a per-session HMAC token.

Intentionally cheap to replicate from pure HTTP (read /config, replay two calls).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from collections.abc import Callable
from typing import ClassVar

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from app.contract import DetectionModule, RequestContext, Signal, Verdict

GIF_1X1 = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")

PIXEL_JS = r"""(function () {
  'use strict';
  var base = '/akam/pixel_challenge';
  async function run() {
    try {
      var cfg = await (await fetch(base + '/config', {credentials: 'include'})).json();
      var q = '?ap=' + encodeURIComponent(cfg.pixel_id) + '&t=' + encodeURIComponent(cfg.token);
      await new Promise(function (res) {
        var img = new Image();
        img.onload = img.onerror = res;
        img.src = base + '/pixel.gif' + q + '&_=' + Date.now();
      });
      var r = await fetch(base + '/beacon', {
        method: 'POST', credentials: 'include',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ap: cfg.pixel_id, t: cfg.token, ts: Date.now()})
      });
      window.__akPixelOk = r.ok;
    } catch (e) { window.__akPixelOk = false; }
    window.__akPixelDone = true;
    window.dispatchEvent(new CustomEvent('ak:pixel'));
  }
  run();
})();
"""


class PixelChallenge(DetectionModule):
    slug: ClassVar[str] = "pixel_challenge"
    title: ClassVar[str] = "Pixel beacon challenge"
    description: ClassVar[str] = (
        "Per-session HMAC token must be sent via a 1x1 GIF request and then a JSON "
        "beacon, in that order. Cheap to replicate over plain HTTP."
    )
    category: ClassVar[str] = "js"
    client_scripts: ClassVar[list[str]] = ["pixel.js"]

    def __init__(self, secret: bytes | None = None, clock: Callable[[], float] = time.time) -> None:
        self.secret = secret or secrets.token_bytes(32)
        self.clock = clock

    def _mac(self, label: str, sid: str, n: int) -> str:
        return hmac.new(self.secret, f"{label}:{sid}".encode(), hashlib.sha256).hexdigest()[:n]

    def pixel_id(self, sid: str) -> str:
        return self._mac("id", sid, 12)

    def token(self, sid: str) -> str:
        return self._mac("tok", sid, 32)

    def valid(self, sid: str, ap: str, t: str) -> bool:
        return (
            bool(sid)
            and hmac.compare_digest(ap, self.pixel_id(sid))
            and hmac.compare_digest(t, self.token(sid))
        )

    async def evaluate(self, ctx: RequestContext) -> Signal:
        if ctx.session_id and await ctx.store.get(f"pixel:{ctx.session_id}") == "ok":
            return self.signal(Verdict.PASS, 0, "pixel gif and beacon received")
        return self.signal(Verdict.FAIL, 70, "pixel beacon not received for this session")

    def router(self) -> APIRouter:
        r = APIRouter()

        @r.get("/config")
        async def config(request: Request) -> Response:
            sid = request.cookies.get("bm_sz", "")
            if not sid:
                return JSONResponse({"error": "no_session"}, status_code=400)
            return JSONResponse(
                {"pixel_id": self.pixel_id(sid), "token": self.token(sid)},
                headers={"Cache-Control": "no-store"},
            )

        @r.get("/pixel.gif")
        async def gif(request: Request, ap: str = "", t: str = "") -> Response:
            sid = request.cookies.get("bm_sz", "")
            if self.valid(sid, ap, t):
                await request.app.state.store.set(f"pixel:gif:{sid}", "1", ttl=3600)
            # Always return a GIF (like a real tracking pixel), only record on valid token.
            return Response(GIF_1X1, media_type="image/gif", headers={"Cache-Control": "no-store"})

        @r.post("/beacon")
        async def beacon(request: Request) -> Response:
            sid = request.cookies.get("bm_sz", "")
            try:
                body = await request.json()
                ap, t = str(body["ap"]), str(body["t"])
                float(body["ts"])
            except (ValueError, KeyError, TypeError):
                return JSONResponse({"ok": False, "error": "bad_request"}, status_code=400)
            if not self.valid(sid, ap, t):
                return JSONResponse({"ok": False, "error": "bad_token"}, status_code=403)
            store = request.app.state.store
            if await store.get(f"pixel:gif:{sid}") != "1":
                return JSONResponse({"ok": False, "error": "gif_not_fetched"}, status_code=403)
            await store.set(f"pixel:{sid}", "ok", ttl=3600)
            return JSONResponse({"ok": True})

        @r.get("/pixel.js")
        async def pixel_js() -> Response:
            return Response(
                PIXEL_JS, media_type="application/javascript", headers={"Cache-Control": "no-store"}
            )

        return r
