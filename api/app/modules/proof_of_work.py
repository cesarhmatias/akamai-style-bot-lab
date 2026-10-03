"""Proof-of-work interstitial (Akamai ``sec_cpt`` pattern).

Two variants are served: ``simple`` (legacy arithmetic) and ``hard`` (sha256
leading-zero search). Only the ``hard`` variant unlocks the protected resource.
"""

from __future__ import annotations

import hashlib
import json
import random
import time
import uuid
from collections.abc import Callable
from typing import Any, ClassVar

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from app.contract import DetectionModule, RequestContext, Signal, Verdict

CHALLENGE_TTL = 60
DEFAULT_DIFFICULTY = 4

POW_JS = r"""(function () {
  'use strict';
  var base = '/akam/proof_of_work';
  function getJson(u) {
    return fetch(u, {credentials: 'include'}).then(function (r) { return r.json(); });
  }
  function post(body) {
    return fetch(base + '/verify', {
      method: 'POST', credentials: 'include',
      headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)
    }).then(function (r) { return r.json(); });
  }
  function solveSimple(expr) {
    // expression is "a op b op c" with + - * and standard precedence
    var toks = expr.split(/\s+/), vals = [+toks[0]], ops = [];
    for (var i = 1; i < toks.length; i += 2) {
      if (toks[i] === '*') vals.push(vals.pop() * +toks[i + 1]);
      else { ops.push(toks[i]); vals.push(+toks[i + 1]); }
    }
    var r = vals[0];
    for (var j = 0; j < ops.length; j++) r = ops[j] === '+' ? r + vals[j + 1] : r - vals[j + 1];
    return r;
  }
  function hex(buf) {
    var a = new Uint8Array(buf), s = '';
    for (var i = 0; i < a.length; i++) s += (a[i] < 16 ? '0' : '') + a[i].toString(16);
    return s;
  }
  async function solveHard(ch) {
    var prefix = '0'.repeat(ch.difficulty), enc = new TextEncoder(), start = 0, B = 256;
    for (;;) {
      var jobs = [];
      for (var i = 0; i < B; i++) {
        jobs.push(crypto.subtle.digest('SHA-256', enc.encode(ch.nonce + (start + i))));
      }
      var res = await Promise.all(jobs);
      for (var k = 0; k < B; k++) if (hex(res[k]).indexOf(prefix) === 0) return start + k;
      start += B;
    }
  }
  async function run() {
    try {
      var s = await getJson(base + '/challenge?variant=simple');
      await post({challenge_id: s.challenge_id, answer: solveSimple(s.expression)});
      var h = await getJson(base + '/challenge?variant=hard');
      var counter = await solveHard(h);
      var res = await post({challenge_id: h.challenge_id, answer: counter});
      window.__akPowOk = !!res.ok;
    } catch (e) { window.__akPowOk = false; }
    window.__akPowDone = true;
    window.dispatchEvent(new CustomEvent('ak:pow'));
  }
  run();
})();
"""


def eval_expression(expr: str) -> int:
    """Evaluate ``a op b op c`` (+, -, *) with normal precedence, without eval()."""
    toks = expr.split()
    terms: list[int] = [int(toks[0])]
    signs: list[int] = []
    for i in range(1, len(toks), 2):
        op, val = toks[i], int(toks[i + 1])
        if op == "*":
            terms[-1] *= val
        elif op in "+-":
            signs.append(1 if op == "+" else -1)
            terms.append(val)
        else:
            raise ValueError(op)
    total = terms[0]
    for s, t in zip(signs, terms[1:], strict=True):
        total += s * t
    return total


def hard_ok(nonce: str, counter: str, difficulty: int) -> bool:
    digest = hashlib.sha256((nonce + counter).encode()).hexdigest()
    return digest.startswith("0" * difficulty)


class ProofOfWork(DetectionModule):
    slug: ClassVar[str] = "proof_of_work"
    title: ClassVar[str] = "Proof of work interstitial"
    description: ClassVar[str] = (
        "sec_cpt-style challenge: client must solve a sha256 proof of work (hard) "
        "bound to its session; the legacy arithmetic variant alone only warns."
    )
    category: ClassVar[str] = "js"
    client_scripts: ClassVar[list[str]] = ["pow.js"]

    def __init__(
        self,
        rng: random.Random | None = None,
        clock: Callable[[], float] = time.time,
        difficulty: int = DEFAULT_DIFFICULTY,
    ) -> None:
        self.rng = rng or random.Random()
        self.clock = clock
        self.difficulty = difficulty

    async def evaluate(self, ctx: RequestContext) -> Signal:
        sid = ctx.session_id
        if sid and await ctx.store.get(f"pow:{sid}") == "ok":
            return self.signal(Verdict.PASS, 0, "hard proof of work solved")
        if sid and await ctx.store.get(f"pow:simple:{sid}") == "ok":
            return self.signal(Verdict.WARN, 30, "only the legacy arithmetic challenge was solved")
        return self.signal(Verdict.FAIL, 80, "no proof of work solved for this session")

    # -- challenge generation -------------------------------------------------
    def make_challenge(self, sid: str, variant: str) -> tuple[dict[str, Any], dict[str, Any]]:
        """Return (public payload, private record)."""
        cid = uuid.UUID(int=self.rng.getrandbits(128), version=4).hex
        now = self.clock()
        public: dict[str, Any] = {
            "challenge_id": cid,
            "variant": variant,
            "expires_in": CHALLENGE_TTL,
        }
        record: dict[str, Any] = {"sid": sid, "variant": variant, "ts": now}
        if variant == "simple":
            n = [self.rng.randint(2, 99) for _ in range(3)]
            ops = [self.rng.choice("+-*") for _ in range(2)]
            expr = f"{n[0]} {ops[0]} {n[1]} {ops[1]} {n[2]}"
            public.update(expression=expr, nonce=None, difficulty=0)
            record["answer"] = eval_expression(expr)
        else:
            nonce = f"{self.rng.getrandbits(64):016x}"
            public.update(
                nonce=nonce,
                difficulty=self.difficulty,
                algo="sha256(nonce + str(counter)) hex starts with `difficulty` zeros",
            )
            record.update(nonce=nonce, difficulty=self.difficulty)
        return public, record

    async def check(self, store: Any, sid: str, cid: str, answer: Any) -> tuple[bool, str, str]:
        """Consume challenge ``cid``. Returns (ok, reason, variant)."""
        key = f"pow:ch:{cid}"
        raw = await store.get(key)
        if raw is None:
            return False, "unknown_or_replayed", ""
        await store.delete(key)  # single use, even on failure
        rec = json.loads(raw)
        variant = rec["variant"]
        if rec["sid"] != sid:
            return False, "wrong_session", variant
        if self.clock() - rec["ts"] > CHALLENGE_TTL:
            return False, "expired", variant
        try:
            if variant == "simple":
                ok = int(answer) == rec["answer"]
            else:
                ok = hard_ok(rec["nonce"], str(int(answer)), rec["difficulty"])
        except (TypeError, ValueError):
            return False, "bad_answer", variant
        return (ok, "ok" if ok else "wrong_answer", variant)

    def router(self) -> APIRouter:
        r = APIRouter()

        @r.get("/challenge")
        async def challenge(request: Request, variant: str = "hard") -> Response:
            sid = request.cookies.get("bm_sz", "")
            if not sid:
                return JSONResponse({"error": "no_session"}, status_code=400)
            if variant not in ("simple", "hard"):
                return JSONResponse({"error": "bad_variant"}, status_code=400)
            public, rec = self.make_challenge(sid, variant)
            await request.app.state.store.set(
                f"pow:ch:{public['challenge_id']}", json.dumps(rec), ttl=CHALLENGE_TTL + 5
            )
            return JSONResponse(public, headers={"Cache-Control": "no-store"})

        @r.post("/verify")
        async def verify(request: Request) -> Response:
            sid = request.cookies.get("bm_sz", "")
            try:
                body = await request.json()
                cid = str(body["challenge_id"])
                answer = body["answer"]
            except (ValueError, KeyError, TypeError):
                return JSONResponse({"ok": False, "error": "bad_request"}, status_code=400)
            store = request.app.state.store
            if not sid:
                return JSONResponse({"ok": False, "error": "no_session"}, status_code=400)
            ok, reason, variant = await self.check(store, sid, cid, answer)
            if not ok:
                return JSONResponse({"ok": False, "error": reason}, status_code=403)
            await store.set(
                f"pow:{sid}" if variant == "hard" else f"pow:simple:{sid}", "ok", ttl=3600
            )
            resp = JSONResponse({"ok": True, "variant": variant})
            ts = int(self.clock())
            cookie = f"{self.rng.getrandbits(128):032x}~3~{ts}"
            resp.set_cookie("sec_cpt", cookie, path="/", samesite="lax")
            return resp

        @r.get("/pow.js")
        async def pow_js() -> Response:
            return Response(
                POW_JS, media_type="application/javascript", headers={"Cache-Control": "no-store"}
            )

        return r
