r"""``sec_cpt`` challenge providers: ``crypto``, ``behavioral`` and ``adaptive`` (audit §1.2 case 6
and §2.4).

Mechanism
    A session the response policy challenges must solve a ``sec_cpt`` challenge before it may
    continue. The challenge is bound to the session (``bm_sz``), single use, and has a MINIMUM
    wall-clock duration: a correct answer that arrives before ``chlg_duration`` seconds have
    passed is rejected. Only ``crypto`` (and the hashing half of ``adaptive``) is a proof of work
    in the hashcash sense: a puzzle whose cost is tuned by a difficulty and whose answer is cheap
    to check. ``behavioral`` has nothing to compute, and the wait costs time, not work.

How real Akamai uses it (report §2.4 and §1.2 case 6)
    * Tier HIGH (concept): Akamai's challenge-action API lists ``AKAMAI_WEB_CRYPTO`` with
      ``cryptoChallengeDurationInSeconds`` (up to 120), ``challengeIntervalInSeconds``
      (1-7200) and the Bot Manager brief describes "minimum-time-to-solve cryptographic
      puzzles".
    * Tier MEDIUM (artifacts, vendor docs, one 2020 sandbox capture, one 2026 PR): scripts under
      ``/_sec/cp_challenge/`` (``sec-cpt-<ver>.js``), a 428 Precondition Required JSON body for
      API calls or an HTML page with an iframe ``id="sec-cpt-if"`` carrying ``provider``, a
      base64 ``challenge`` JSON and ``data-duration``; verification at
      ``/_sec/verify?provider=crypto|adaptive`` or ``/_sec/cp_challenge/verify``; a solved
      challenge leaves a ``sec_cpt`` cookie containing ``~3~``. Providers: ``crypto`` (proof of
      work plus wait), ``behavioral`` (sensor data) and ``adaptive`` (both, ``count`` solutions).
    The cookieless interstitial the brief describes separately is the ``bm_verify_interstitial``
    module. The puzzle algorithm, challenge field values and cookie value are LAB-DEFINED; none
    of this is Akamai's encoding.

How the lab simulates it
    * ``crypto``: find ``counter`` with ``sha256(nonce + str(counter))`` starting with
      ``difficulty`` hex zeros, then wait until ``chlg_duration`` seconds after issue.
    * ``adaptive``: ``count`` solutions (``nonce.i`` + counter, one lower difficulty each) AND the
      behavioral check AND the wait.
    * ``behavioral``: the session must have posted sensor data (``sensor:n:{sid}`` or
      ``sensor:{sid}`` written by ``sensor_data``) and waited ``chlg_duration``; the challenge
      page loads the other modules' scripts so the sensor can run.
    * ``evaluate()`` validates the ``sec_cpt`` cookie against the store (a forged or missing
      cookie fails even if the store says solved) and re-challenges after
      ``challenge_interval`` seconds. Settings live in the policy document (``chlg_duration``
      default 2 s for the lab, ``challenge_interval`` default 600 s, ``adaptive_count``).
    * Verification goes through the engine's shared ``/_sec/verify`` route (``verify_challenge``).
    * A proactive solver (``/akam/sec_cpt_challenge/sec-cpt.js``, included on the landing page)
      runs the ``crypto`` flow in the background so a real browser holds a valid ``sec_cpt``
      before it reaches a protected resource. Akamai does not do this; it is a LAB convenience
      that keeps the harness's browser case meaningful.

How a client passes it
    Challenge via the 428 JSON (or iframe attributes), solve, wait ``chlg_duration`` seconds,
    ``POST /_sec/verify?provider=<p>`` with ``{"token", "answer"|"answers"}``, keep the
    ``sec_cpt`` cookie. A pure-HTTP client can do all of this after sleeping, which is the
    intended lesson: the wait costs time, not identity.

Limits: the difficulty is a lab constant (4 hex zeros, about 65 000 hashes: milliseconds even in
pure Python), so the minimum wait, not the hashing, is what costs a client.
"""

from __future__ import annotations

import base64
import hashlib
import json
import random
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, ClassVar

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from app.contract import Confidence, DetectionModule, RequestContext, Signal, Verdict
from app.policy import PolicyStore, clear_challenge_failures

DEFAULT_DIFFICULTY = 4
SCRIPT_NAME = "sec-cpt-1.0.js"
SCRIPT_URL = f"/_sec/cp_challenge/{SCRIPT_NAME}"
PROVIDERS = ("crypto", "behavioral", "adaptive")
COOKIE = "sec_cpt"
STATE_TTL = 3600
# An unsolved challenge is a gray signal, not proof of automation: 45 lands in the "strict"
# segment (challenge) for standard telemetry. A forged sec_cpt cookie is hostile: 80.
UNSOLVED_SCORE = 45
FORGED_SCORE = 80

SEC_CPT_JS = r"""(function () {
  'use strict';
  // Lab-written solver (not Akamai code). Challenge-page mode reads the sec-cpt-if iframe;
  // proactive mode (landing page) fetches a crypto challenge itself.
  var t0 = Date.now();
  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }
  function hex(buf) {
    var a = new Uint8Array(buf), s = '';
    for (var i = 0; i < a.length; i++) s += (a[i] < 16 ? '0' : '') + a[i].toString(16);
    return s;
  }
  async function solve(nonce, difficulty) {
    var prefix = '0'.repeat(difficulty), enc = new TextEncoder(), start = 0, B = 256;
    for (;;) {
      var jobs = [];
      for (var i = 0; i < B; i++) {
        jobs.push(crypto.subtle.digest('SHA-256', enc.encode(nonce + (start + i))));
      }
      var res = await Promise.all(jobs);
      for (var k = 0; k < B; k++) if (hex(res[k]).indexOf(prefix) === 0) return start + k;
      start += B;
    }
  }
  async function run() {
    var iframe = document.getElementById('sec-cpt-if'), ch, provider, ok = false;
    try {
      if (iframe) {
        provider = iframe.getAttribute('provider');
        ch = JSON.parse(atob(iframe.getAttribute('challenge')));
      } else {
        provider = 'crypto';
        ch = await (await fetch('/akam/sec_cpt_challenge/challenge?provider=crypto',
          {credentials: 'include'})).json();
      }
      var answers = [];
      if (provider !== 'behavioral') {
        var n = ch.count || 1;
        for (var i = 0; i < n; i++) {
          answers.push(await solve(n > 1 ? ch.nonce + '.' + i : ch.nonce, ch.difficulty));
        }
      }
      var wait = ch.chlg_duration * 1000 + 300 - (Date.now() - t0);
      if (wait > 0) await sleep(wait);
      if (provider !== 'crypto') {  // let the sensor script post at least once
        for (var w = 0; w < 40 && window.__akSensorDone !== true; w++) await sleep(250);
      }
      var r = await fetch('/_sec/verify?provider=' + provider, {
        method: 'POST', credentials: 'include',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({token: ch.token, answers: answers})
      });
      ok = r.ok && (await r.json()).ok === true;
    } catch (e) { ok = false; }
    if (iframe) {
      var tries = +(sessionStorage.getItem('sec_cpt_tries') || 0);
      if (ok || tries < 3) {
        sessionStorage.setItem('sec_cpt_tries', ok ? 0 : tries + 1);
        location.reload();
      }
    } else {
      window.__akSecCptOk = ok;
      window.__akSecCptDone = true;
      window.dispatchEvent(new CustomEvent('ak:sec_cpt'));
    }
  }
  run();
})();
"""

MESSAGE_HTML = (
    "<!doctype html><html><head><meta charset=utf-8></head>"
    '<body style="font-family:system-ui,sans-serif;text-align:center;margin-top:3rem">'
    "<p>Checking your browser&hellip;</p></body></html>"
)


def hash_ok(nonce: str, counter: str, difficulty: int) -> bool:
    digest = hashlib.sha256((nonce + counter).encode()).hexdigest()
    return digest.startswith("0" * difficulty)


def sub_nonce(nonce: str, index: int, count: int) -> str:
    """Single solution uses the nonce as is; adaptive solution ``i`` uses ``nonce.i``."""
    return nonce if count == 1 else f"{nonce}.{index}"


async def sec_cpt_state(
    ctx: RequestContext, now: float, interval: int | None = None
) -> tuple[str, dict[str, Any]]:
    """(state, details) of the session's ``sec_cpt``: ok | forged | missing | expired | none.

    ``ok`` needs the store record AND the cookie it issued, younger than ``interval`` (the
    policy's ``challenge_interval`` when None). Other modules use it to treat a solved
    ``sec_cpt`` as server-side proof (``bm_verify_interstitial``)."""
    sid = ctx.session_id
    raw = await ctx.store.get(f"sec_cpt:{sid}") if sid else None
    if not raw:
        return "none", {}
    rec = json.loads(raw)
    cookie = ctx.cookies.get(COOKIE, "")
    if not cookie:
        return "missing", {}
    if "~3~" not in cookie or cookie != rec.get("cookie"):
        return "forged", {}
    if interval is None:
        interval = (await PolicyStore(ctx.store).get()).params.challenge_interval
    age = now - float(rec["solved_at"])
    if age > interval:
        return "expired", {"age": round(age, 1), "interval": interval}
    return "ok", {"provider": rec.get("provider"), "age": round(age, 1)}


@dataclass
class Settings:
    duration: float
    interval: int
    timeout: int
    adaptive_count: int
    difficulty: int


class SecCptChallenge(DetectionModule):
    slug: ClassVar[str] = "sec_cpt_challenge"
    title: ClassVar[str] = "sec_cpt challenge (crypto, behavioral, adaptive)"
    description: ClassVar[str] = (
        "sec_cpt-style challenge providers: crypto (sha256 proof of work), behavioral (sensor "
        "posts) and adaptive (both), each with a minimum solve duration (chlg_duration); 428 "
        "JSON or iframe page, validated sec_cpt cookie and a re-challenge interval. Artifacts "
        "are MEDIUM-confidence approximations."
    )
    category: ClassVar[str] = "js"
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    client_scripts: ClassVar[list[str]] = ["sec-cpt.js"]
    challenge_providers: ClassVar[frozenset[str]] = frozenset(PROVIDERS)

    def __init__(
        self,
        rng: random.Random | None = None,
        clock: Callable[[], float] = time.time,
        difficulty: int | None = None,
        duration: float | None = None,
        interval: int | None = None,
        timeout: int | None = None,
        adaptive_count: int | None = None,
    ) -> None:
        self.rng = rng or random.Random()
        self.clock = clock
        self._overrides: dict[str, Any] = {
            "difficulty": difficulty,
            "duration": duration,
            "interval": interval,
            "timeout": timeout,
            "adaptive_count": adaptive_count,
        }

    async def settings(self, store: Any) -> Settings:
        p = (await PolicyStore(store).get()).params
        base: dict[str, Any] = {
            "difficulty": DEFAULT_DIFFICULTY,
            "duration": p.chlg_duration,
            "interval": p.challenge_interval,
            "timeout": p.challenge_timeout,
            "adaptive_count": p.adaptive_count,
        }
        base.update({k: v for k, v in self._overrides.items() if v is not None})
        return Settings(**base)

    # -- verdict -------------------------------------------------------------------------
    async def _state(self, ctx: RequestContext) -> tuple[str, dict[str, Any]]:
        interval = (await self.settings(ctx.store)).interval
        return await sec_cpt_state(ctx, self.clock(), interval)

    async def evaluate(self, ctx: RequestContext) -> Signal:
        state, d = await self._state(ctx)
        if state == "ok":
            return self.signal(Verdict.PASS, 0, "sec_cpt challenge solved, cookie valid", **d)
        if state == "forged":
            return self.signal(
                Verdict.FAIL, FORGED_SCORE, "sec_cpt cookie is not the one issued (forged?)", **d
            )
        if state == "missing":
            return self.signal(
                Verdict.FAIL, UNSOLVED_SCORE, "solved, but the sec_cpt cookie was not presented"
            )
        if state == "expired":
            return self.signal(
                Verdict.FAIL,
                UNSOLVED_SCORE,
                "challenge interval elapsed, the session must solve again",
                rechallenge=True,
                **d,
            )
        return self.signal(
            Verdict.FAIL, UNSOLVED_SCORE, "no sec_cpt challenge solved for this session"
        )

    async def challenge_satisfied(self, ctx: RequestContext, provider: str | None = None) -> bool:
        # Only vouch for providers this module serves: a sec_cpt must not satisfy another
        # module's challenge (the interactive tile game, the bm-verify interstitial).
        if provider is not None and provider not in self.challenge_providers:
            return False
        return (await self._state(ctx))[0] == "ok"

    # -- challenge generation ------------------------------------------------------------
    async def make_challenge(self, store: Any, sid: str, provider: str) -> dict[str, Any]:
        """Create and persist a challenge; return the public payload."""
        cfg = await self.settings(store)
        token = uuid.UUID(int=self.rng.getrandbits(128), version=4).hex
        now = self.clock()
        count = cfg.adaptive_count if provider == "adaptive" else 1
        difficulty = max(1, cfg.difficulty - 1) if count > 1 else cfg.difficulty
        nonce = f"{self.rng.getrandbits(64):016x}"
        public: dict[str, Any] = {
            "provider": provider,
            "token": token,
            "timestamp": int(now),
            "timeout": cfg.timeout,
            "chlg_duration": cfg.duration,
        }
        if provider != "behavioral":  # behavioral has nothing to compute
            public.update(nonce=nonce, difficulty=difficulty)
            public["algo"] = "sha256(nonce + str(counter)) hex starts with `difficulty` zeros"
        if provider == "adaptive":
            public["count"] = count
        record = {
            "sid": sid,
            "provider": provider,
            "issued_at": now,
            "chlg_duration": cfg.duration,
            "timeout": cfg.timeout,
            "nonce": nonce,
            "difficulty": difficulty,
            "count": count,
        }
        await store.set(f"sec_cpt:ch:{token}", json.dumps(record), ttl=cfg.timeout + 5)
        return public

    async def _sensor_posts(self, store: Any, sid: str) -> int:
        n = await store.get(f"sensor:n:{sid}")
        if n and str(n).isdigit() and int(n) > 0:
            return int(n)
        return 1 if await store.get(f"sensor:{sid}") else 0

    async def check(
        self, store: Any, sid: str, rec: dict[str, Any], body: dict[str, Any], provider: str | None
    ) -> tuple[bool, str, dict[str, Any]]:
        """Judge an answer against the (already consumed) challenge record ``rec``.
        Returns (ok, reason, record)."""
        if rec["sid"] != sid:
            return False, "wrong_session", rec
        if provider and provider != rec["provider"]:
            return False, "wrong_provider", rec
        elapsed = self.clock() - rec["issued_at"]
        if elapsed > rec["timeout"]:
            return False, "expired", rec
        try:
            if rec["provider"] == "behavioral":
                ok = True
            else:
                answers = body.get("answers") or [body["answer"]]
                count = int(rec["count"])
                ok = len(answers) == count and all(
                    hash_ok(sub_nonce(rec["nonce"], i, count), str(int(a)), rec["difficulty"])
                    for i, a in enumerate(answers)
                )
        except (TypeError, ValueError, KeyError):
            return False, "bad_answer", rec
        if not ok:
            return False, "wrong_answer", rec
        if elapsed < rec["chlg_duration"]:
            return False, "too_early", {**rec, "retry_after": rec["chlg_duration"] - elapsed}
        if rec["provider"] in ("behavioral", "adaptive") and not await self._sensor_posts(
            store, sid
        ):
            return False, "no_sensor", rec
        return True, "ok", rec

    async def accept(self, store: Any, sid: str, rec: dict[str, Any]) -> Response:
        """Record a solved challenge and build the success response (with ``sec_cpt``)."""
        resp = JSONResponse({"ok": True, "provider": rec["provider"]})
        now = self.clock()
        cookie = f"{self.rng.getrandbits(128):032X}~3~{int(now)}"
        await store.set(
            f"sec_cpt:{sid}",
            json.dumps({"cookie": cookie, "solved_at": now, "provider": rec["provider"]}),
            ttl=STATE_TTL,
        )
        await clear_challenge_failures(store, sid)
        resp.set_cookie(COOKIE, cookie, path="/", samesite="lax")
        return resp

    async def verify_challenge(
        self, request: Request, token: str, body: dict[str, Any], provider: str | None
    ) -> Response | None:
        """Redeem a token this module issued (the engine's shared ``/_sec/verify`` route)."""
        store = request.app.state.store
        key = f"sec_cpt:ch:{token}"
        raw = await store.get(key)
        if raw is None:
            return None  # not ours: the route asks the next challenge provider
        await store.delete(key)  # single use, even on failure
        sid = request.cookies.get("bm_sz", "")
        ok, reason, rec = await self.check(store, sid, json.loads(raw), body, provider)
        if not ok:
            extra = {"retry_after": round(rec["retry_after"], 2)} if "retry_after" in rec else {}
            return JSONResponse({"ok": False, "error": reason, **extra}, status_code=403)
        return await self.accept(store, sid, rec)

    # -- challenge action ----------------------------------------------------------------
    async def issue_challenge(
        self, request: Request, ctx: RequestContext, provider: str, *, html: bool
    ) -> Response | None:
        if provider not in self.challenge_providers:
            return None
        public = await self.make_challenge(ctx.store, ctx.session_id, provider)
        headers = {"Cache-Control": "no-store"}
        if not html:
            return JSONResponse(public, status_code=428, headers=headers)
        encoded = base64.b64encode(json.dumps(public, separators=(",", ":")).encode()).decode()
        page = (
            "<!doctype html><html><head><meta charset=utf-8>"
            "<title>Checking your browser</title></head><body>"
            f'<iframe id="sec-cpt-if" provider="{provider}" challenge="{encoded}" '
            f'data-duration="{public["chlg_duration"]:g}" '
            f'src="/_sec/cp_challenge/message.htm?provider={provider}" '
            'style="border:0;width:100%;height:12rem"></iframe>'
            f'<script src="{SCRIPT_URL}"></script></body></html>'
        )
        return HTMLResponse(page, headers=headers)

    # -- routes --------------------------------------------------------------------------
    def root_router(self) -> APIRouter:
        """Vendor-style absolute paths (report §1.2 case 6, tier MEDIUM). Verification goes
        through the engine's shared ``/_sec/verify`` route (``verify_challenge``)."""
        r = APIRouter()

        @r.get(f"/_sec/cp_challenge/{SCRIPT_NAME}")
        async def script() -> Response:
            return Response(
                SEC_CPT_JS,
                media_type="application/javascript",
                headers={"Cache-Control": "no-store"},
            )

        @r.get("/_sec/cp_challenge/message.htm")
        async def message() -> Response:
            return HTMLResponse(MESSAGE_HTML)

        return r

    def router(self) -> APIRouter:
        """Lab routes under ``/akam/sec_cpt_challenge/``: a challenge on demand (the vendor only
        issues one as a response action) and the proactive solver script."""
        r = APIRouter()

        @r.get("/challenge")
        async def challenge(request: Request, provider: str = "crypto") -> Response:
            sid = request.cookies.get("bm_sz", "")
            if not sid:
                return JSONResponse({"error": "no_session"}, status_code=400)
            if provider not in PROVIDERS:
                return JSONResponse({"error": "bad_provider"}, status_code=400)
            public = await self.make_challenge(request.app.state.store, sid, provider)
            return JSONResponse(public, headers={"Cache-Control": "no-store"})

        @r.get("/sec-cpt.js")
        async def solver_js() -> Response:
            return Response(
                SEC_CPT_JS,
                media_type="application/javascript",
                headers={"Cache-Control": "no-store"},
            )

        return r
