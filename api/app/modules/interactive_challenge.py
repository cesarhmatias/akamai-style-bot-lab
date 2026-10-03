"""Interactive behavioral (tile) challenge and AJAX challenge injection (audit §2.4).

Mechanism
    A mini-game page: a grid of numbers or letters and a sequence the visitor must click in
    order. The page records pointer and key telemetry, the server checks the answer AND that
    the interaction is plausible for a person, then the page reloads the original request.
    A solved session is not challenged again for 50 minutes.

How real Akamai uses it
    * Tier HIGH (concept, Akamai blog 2026-03-10): Content Protector's opt-in interactive
      behavioral challenge uses "five mini-game types using grids of numbers or letters",
      records mouse, touch and key telemetry, reloads the original request when done and does
      not re-challenge for at least 50 minutes.
    * Tier MEDIUM (markup, one 2026 scraper PR): the page is recognizable by the classes
      ``sec-if-cpt-container``, ``scf-akamai-logo``, ``sec-bc-tile-parent`` and
      ``sec-bc-text-container``, answers HTTP 200, has no ``<title>`` and is about 2.7 KB.
    * Tier HIGH (concept): challenge injection rules let Akamai inject "AJAX challenge
      JavaScript" into HTML pages (``injectJavaScript``) so XHR/fetch calls can be challenged.
    The lab reproduces the observable shape only: one tile-grid game (not five), lab-styled
    ``scf-akamai-logo`` element (no real logo), lab-chosen verification rules.

How the lab simulates it
    * ``challenge_providers = {"interactive", "behavioral"}``. ``interactive`` serves this page
      for navigations and a 428 JSON (with ``challenge_url``) for XHR; ``behavioral`` serves the
      page for navigations only (the JSON form belongs to the sensor-based provider of
      ``proof_of_work``). Select it with ``challenge_provider`` in ``PUT /api/policy``.
    * ``POST /akam/interactive_challenge/verify`` with ``{token, clicks[], moves[], keys[],
      total}``. Checks: single-use token bound to ``bm_sz``; clicks match the sequence; every
      click ``isTrusted``; the first click comes after a human reaction time and clicks are not
      machine-regular; pointer clicks carry coordinates inside the tile and a path of at least
      3 distinct pointer positions (keyboard-only completion needs 3 key events instead).
    * Success sets ``sec_bc`` (lab-defined cookie name) and the store marker
      ``ichal:ok:{sid}`` for ``norechallenge_seconds`` (policy, default 3000 s = 50 minutes);
      while valid, the engine downgrades ``challenge`` actions to monitor.
    * AJAX injection: ``page_snippets`` adds ``/akam/interactive_challenge/ajax_inject.js`` to
      HTML pages while the flag ``ajax_challenge_injection`` is on (default on). It wraps fetch
      and XMLHttpRequest, renders a 428 challenge in an overlay iframe, and retries once.

How a client passes it
    A real browser: click the tiles like a person. A script must synthesize trusted input with
    human-like timing and a pointer path (the Playwright harness client can); calling
    ``element.click()`` or posting the answer directly is rejected.

Limits: the plausibility rules are simple lab heuristics, not Akamai's models. As a case
(``GET /protected/interactive_challenge``) it passes only for a session that solved the game.
It has no ``applies_to`` so it never joins ``/protected/all``.
"""

from __future__ import annotations

import html
import json
import random
import statistics
import time
import uuid
from collections.abc import Callable
from itertools import pairwise
from pathlib import Path
from typing import Any, ClassVar

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from app.contract import (
    Confidence,
    DetectionModule,
    FlagSpec,
    RequestContext,
    Signal,
    Verdict,
)
from app.policy import PolicyStore, clear_challenge_failures

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
BASE = "/akam/interactive_challenge"
COOKIE = "sec_bc"  # lab-defined; Akamai's real cookie for this challenge is not public
TOKEN_TTL = 180
GRID = 9
NEED = 3
MIN_FIRST_CLICK_MS = 250
MIN_GAP_MS = 80
LETTERS = "ABCDEFGHJKLMNPQRSTUVWXYZ"
UNSOLVED_SCORE = 45

STYLE = (
    "body{margin:0;font-family:system-ui,sans-serif;background:#fff;color:#222}"
    ".sec-if-cpt-container{max-width:360px;margin:0 auto;padding:16px;text-align:center}"
    ".scf-akamai-logo{display:inline-block;padding:2px 10px;border:1px solid #bbb;"
    "border-radius:4px;font-size:12px;color:#666}"
    ".sec-bc-text-container{margin:12px 0}.sec-bc-text-container b{font-size:20px}"
    ".sec-bc-tile-parent{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}"
    ".sec-bc-tile-parent button{height:72px;font-size:24px;border:1px solid #999;"
    "border-radius:8px;background:#f5f5f5;cursor:pointer}"
    ".sec-bc-picked{background:#cde!important;border-color:#47a!important}"
)


def check_interaction(
    rec: dict[str, Any], body: dict[str, Any]
) -> tuple[bool, str, dict[str, Any]]:
    """Verify the answer and the plausibility of the telemetry. Returns (ok, reason, details)."""
    clicks = body.get("clicks")
    moves = body.get("moves") or []
    keys = body.get("keys") or []
    if not isinstance(clicks, list) or not isinstance(moves, list) or not isinstance(keys, list):
        return False, "bad_request", {}
    seq = rec["sequence"]
    try:
        order = [int(c["i"]) for c in clicks]
        times = [float(c["t"]) for c in clicks]
    except (KeyError, TypeError, ValueError):
        return False, "bad_request", {}
    details: dict[str, Any] = {"clicks": len(clicks), "moves": len(moves), "keys": len(keys)}
    if order != seq:
        return False, "wrong_sequence", details
    if not all(isinstance(c, dict) and c.get("trusted") is True for c in clicks):
        return False, "untrusted_events", details
    if times[0] < MIN_FIRST_CLICK_MS:
        return False, "too_fast", details
    gaps = [b - a for a, b in pairwise(times)]
    if any(g < MIN_GAP_MS for g in gaps):
        return False, "too_fast", details
    if len(gaps) >= 2 and statistics.pstdev(gaps) < 2.0:
        return False, "machine_regular_timing", details
    pointer_clicks = [c for c in clicks if int(c.get("detail") or 0) >= 1]
    if pointer_clicks:
        if not all(c.get("inside") is True for c in pointer_clicks):
            return False, "click_outside_tile", details
        positions = {(m[0], m[1]) for m in moves if isinstance(m, list) and len(m) >= 2}
        if len(positions) < 3:
            return False, "no_pointer_path", details
    elif len(keys) < 3:  # no pointer clicks (detail 0): keyboard completion needs key events
        return False, "no_input_telemetry", details
    return True, "ok", details


class InteractiveChallenge(DetectionModule):
    slug: ClassVar[str] = "interactive_challenge"
    title: ClassVar[str] = "Interactive tile challenge + AJAX injection"
    description: ClassVar[str] = (
        "Content Protector-style behavioral mini-game (tile grid, pointer/key telemetry, 50 minute "
        "no-rechallenge marker) and an injected helper that challenges fetch/XHR calls. "
        "Concept HIGH, markup MEDIUM."
    )
    category: ClassVar[str] = "behavioral"
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    applies_to: ClassVar[frozenset[Any]] = frozenset()  # explicit /protected/<slug> only
    challenge_providers: ClassVar[frozenset[str]] = frozenset({"interactive", "behavioral"})
    flags: ClassVar[list[FlagSpec]] = [
        FlagSpec(
            name="ajax_challenge_injection",
            description="Inject ajax_inject.js into HTML pages: wraps fetch/XHR, renders 428 "
            "challenges in an overlay and retries (Akamai challenge injection rules concept).",
            confidence=Confidence.HIGH,
            default=True,
            source="audit §2.4",
        )
    ]

    def __init__(
        self, rng: random.Random | None = None, clock: Callable[[], float] = time.time
    ) -> None:
        self.rng = rng or random.Random()
        self.clock = clock

    # -- state ---------------------------------------------------------------------------
    async def _satisfied(self, ctx: RequestContext) -> bool:
        raw = await ctx.store.get(f"ichal:ok:{ctx.session_id}") if ctx.session_id else None
        if not raw:
            return False
        rec = json.loads(raw)
        cookie = ctx.cookies.get(COOKIE, "")
        ttl = (await PolicyStore(ctx.store).get()).params.norechallenge_seconds
        return bool(cookie) and cookie == rec["cookie"] and self.clock() - rec["solved_at"] <= ttl

    async def challenge_satisfied(self, ctx: RequestContext, provider: str | None = None) -> bool:
        # Only vouch for providers this module serves, so a solved tile game does not
        # waive a crypto/interstitial challenge the policy asked for (and vice versa).
        if provider is not None and provider not in self.challenge_providers:
            return False
        return await self._satisfied(ctx)

    async def evaluate(self, ctx: RequestContext) -> Signal:
        if await self._satisfied(ctx):
            return self.signal(Verdict.PASS, 0, "interactive challenge solved, no re-challenge yet")
        return self.signal(Verdict.FAIL, UNSOLVED_SCORE, "interactive challenge not completed")

    async def page_snippets(self, ctx: RequestContext) -> list[str]:
        if not ctx.flag("ajax_challenge_injection"):
            return []
        return [f'<script src="{BASE}/ajax_inject.js"></script>']

    # -- challenge generation ------------------------------------------------------------
    async def make_challenge(self, store: Any, sid: str) -> tuple[str, dict[str, Any]]:
        token = uuid.UUID(int=self.rng.getrandbits(128), version=4).hex
        letters = self.rng.random() < 0.5
        pool = list(LETTERS) if letters else [str(n) for n in range(1, 10)]
        labels = self.rng.sample(pool, GRID)
        sequence = self.rng.sample(range(GRID), NEED)
        rec = {
            "sid": sid,
            "labels": labels,
            "sequence": sequence,
            "issued_at": self.clock(),
            "kind": "letters" if letters else "numbers",
        }
        await store.set(f"ichal:{token}", json.dumps(rec), ttl=TOKEN_TTL)
        return token, rec

    def render_page(self, token: str, rec: dict[str, Any]) -> str:
        """The tile page: no <title>, the four marker classes, small."""
        order = " &rarr; ".join(html.escape(rec["labels"][i]) for i in rec["sequence"])
        tiles = "".join(
            f'<button type="button" data-i="{i}">{html.escape(lab)}</button>'
            for i, lab in enumerate(rec["labels"])
        )
        return (
            '<!doctype html><html><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            f"<style>{STYLE}</style></head><body>"
            '<div class="sec-if-cpt-container"><div class="scf-akamai-logo">lab</div>'
            '<div class="sec-bc-text-container"><p>Click the tiles in this order</p>'
            f"<b>{order}</b></div>"
            f'<div class="sec-bc-tile-parent" data-token="{token}" data-need="{NEED}" '
            f'data-verify="{BASE}/verify">{tiles}</div></div>'
            f'<script src="{BASE}/chlg_tiles.js"></script></body></html>'
        )

    async def issue_challenge(
        self, request: Request, ctx: RequestContext, provider: str, *, html: bool
    ) -> Response | None:
        if provider not in self.challenge_providers or (provider == "behavioral" and not html):
            return None  # JSON "behavioral" belongs to proof_of_work's sensor-based provider
        token, rec = await self.make_challenge(ctx.store, ctx.session_id)
        headers = {"Cache-Control": "no-store"}
        if html:
            return HTMLResponse(self.render_page(token, rec), headers=headers)
        public = {
            "provider": "interactive",
            "token": token,
            "timestamp": int(rec["issued_at"]),
            "timeout": TOKEN_TTL,
            "challenge_url": f"{BASE}/page?token={token}",
        }
        return JSONResponse(public, status_code=428, headers=headers)

    # -- routes --------------------------------------------------------------------------
    def router(self) -> APIRouter:
        r = APIRouter()

        @r.get("/page")
        async def page(request: Request, token: str = "") -> Response:
            """Same page as the navigation form; used as the AJAX overlay iframe source."""
            raw = await request.app.state.store.get(f"ichal:{token}")
            if not raw or json.loads(raw)["sid"] != request.cookies.get("bm_sz", ""):
                return JSONResponse({"error": "unknown_token"}, status_code=404)
            return HTMLResponse(self.render_page(token, json.loads(raw)))

        @r.post("/verify")
        async def verify(request: Request) -> Response:
            sid = request.cookies.get("bm_sz", "")
            store = request.app.state.store
            try:
                body = await request.json()
                token = str(body["token"])
                if not isinstance(body, dict):
                    raise TypeError
            except (ValueError, KeyError, TypeError):
                return JSONResponse({"ok": False, "error": "bad_request"}, status_code=400)
            raw = await store.get(f"ichal:{token}")
            if raw is None:
                return JSONResponse({"ok": False, "error": "unknown_or_replayed"}, status_code=403)
            await store.delete(f"ichal:{token}")  # single use, even on failure
            rec = json.loads(raw)
            if rec["sid"] != sid:
                return JSONResponse({"ok": False, "error": "wrong_session"}, status_code=403)
            ok, reason, details = check_interaction(rec, body)
            if not ok:
                return JSONResponse({"ok": False, "error": reason, **details}, status_code=403)
            now = self.clock()
            cookie = f"{self.rng.getrandbits(128):032X}~{int(now)}"
            ttl = (await PolicyStore(store).get()).params.norechallenge_seconds
            await store.set(
                f"ichal:ok:{sid}", json.dumps({"cookie": cookie, "solved_at": now}), ttl=ttl
            )
            await clear_challenge_failures(store, sid)
            resp = JSONResponse({"ok": True, "norechallenge_seconds": ttl})
            resp.set_cookie(COOKIE, cookie, path="/", samesite="lax", max_age=ttl)
            return resp

        def static_js(name: str) -> Response:
            return Response(
                (STATIC_DIR / name).read_text(encoding="utf-8"),
                media_type="application/javascript",
                headers={"Cache-Control": "no-store"},
            )

        @r.get("/chlg_tiles.js")
        async def tiles_js() -> Response:
            return static_js("chlg_tiles.js")

        @r.get("/ajax_inject.js")
        async def ajax_js() -> Response:
            return static_js("ajax_inject.js")

        return r
