r"""Proof-of-work / ``sec_cpt`` challenge (case 6, audit §1.2 case 6 and §2.4).

Mechanism
    A client that cannot execute JavaScript, store cookies and spend time is stopped by a
    challenge it must solve before it may continue. The challenge is bound to the session
    (``bm_sz``), single use, and has a MINIMUM wall-clock duration: a correct answer that
    arrives before ``chlg_duration`` seconds have passed is rejected.

How real Akamai uses it (report §2.4 and §1.2 case 6)
    * Tier HIGH (concept): Akamai's challenge-action API lists ``AKAMAI_WEB_CRYPTO`` with
      ``cryptoChallengeDurationInSeconds`` (up to 120), ``challengeIntervalInSeconds``
      (1-7200) and the Bot Manager brief describes "minimum-time-to-solve cryptographic
      puzzles" plus an interstitial that enforces a time penalty on clients without
      JavaScript or cookies.
    * Tier MEDIUM (artifacts, vendor docs, one 2020 sandbox capture, one 2026 PR): scripts under
      ``/_sec/cp_challenge/`` (``sec-cpt-<ver>.js``), a 428 Precondition Required JSON body for
      API calls or an HTML page with an iframe ``id="sec-cpt-if"`` carrying ``provider``, a
      base64 ``challenge`` JSON and ``data-duration``; verification at
      ``/_sec/verify?provider=crypto|adaptive`` or ``/_sec/cp_challenge/verify``; a solved
      challenge leaves a ``sec_cpt`` cookie containing ``~3~``. Providers: ``crypto`` (PoW plus
      wait), ``behavioral`` (sensor data) and ``adaptive`` (both, ``count`` solutions).
    * Tier MEDIUM (Bot Manager brief + community/HAR observations): the cookieless
      INTERSTITIAL. The brief describes an interstitial challenge that "requires clients to
      prove they support storing cookies and executing JavaScript". Observed pages carry a
      ``bm-verify`` token and an embedded script of the form
      ``var i = 1234; var j = i + Number("56" + "78");`` and POST JSON
      ``{"bm-verify": <token>, "pow": <i + int(a+b)>}`` to ``/_sec/verify?provider=interstitial``;
      cookies are then issued and the page reloads. The cookie-issuing step and the page's
      exact wording are approximations. A JSON ``location`` in the reply is UNCONFIRMED (the
      sources show reload / meta-refresh, not a JSON location).
    The puzzle algorithm, challenge field values and cookie value are LAB-DEFINED; none of
    this is Akamai's encoding.

How the lab simulates it
    * ``crypto``: find ``counter`` with ``sha256(nonce + str(counter))`` starting with
      ``difficulty`` hex zeros, then wait until ``chlg_duration`` seconds after issue.
    * ``adaptive``: ``count`` solutions (``nonce.i`` + counter, one lower difficulty each) AND the
      behavioral check AND the wait.
    * ``behavioral``: the session must have posted sensor data (``sensor:n:{sid}`` or
      ``sensor:{sid}`` written by ``sensor_data``) and waited ``chlg_duration``; the interstitial
      page loads the other modules' scripts so the sensor can run.
    * ``evaluate()`` validates the ``sec_cpt`` cookie against the store (a forged or missing
      cookie fails even if the store says solved) and re-challenges after
      ``challenge_interval`` seconds. Settings live in the policy document (``chlg_duration``
      default 2 s for the lab, ``challenge_interval`` default 600 s, ``adaptive_count``).
    * A proactive solver (``/akam/proof_of_work/pow.js``, included on the landing page) runs
      the ``crypto`` flow in the background so a real browser holds a valid ``sec_cpt`` before
      it reaches a protected resource. Akamai does not do this; it is a LAB convenience that
      keeps the harness's browser case meaningful.
    * ``interstitial`` (tier MEDIUM, see below): the cookieless arithmetic interstitial.
    * ``simple``: the old free-form arithmetic expression (``a op b op c``) the first lab
      version used (``/akam/proof_of_work/challenge?variant=simple``). It is a lab device kept
      for the harness and is NOT the interstitial. Solving it alone only WARNs.

The interstitial (cookieless gate)
    * Page: HTTP 200 HTML with a per-issuance ``bm-verify`` token bound to ``bm_sz`` (single
      use, expires after ``challenge_timeout``; same failure reasons as the other variants:
      ``unknown_or_replayed``, ``wrong_session``, ``expired``). The arithmetic is DATA in an
      inline script; the server computes the expected ``pow`` from its stored spec
      (``i`` and the digit parts), never from the page text and never with ``eval``.
    * Verify: ``POST /_sec/verify?provider=interstitial`` (vendor-style absolute path, via
      ``root_router``) and ``POST /akam/proof_of_work/interstitial/verify`` (lab alias), body
      ``{"bm-verify": token, "pow": int}``. On success the lab issues/refreshes ``bm_sz``,
      ``ak_bmsc`` and ``_abck`` exactly as its own cookie issuance does (``main.finalize_cookies``),
      stores ``pow:interstitial:{sid}`` and answers ``{"ok": true, ...}``; the page then reloads.
      ``location`` is only returned when the issuing request path is a same-origin path
      (``safe_location`` rejects anything with a scheme, netloc, ``//`` or backslash).
    * Gate: with the flag ``pow_cookieless_gate`` (MEDIUM, default OFF because it changes the
      first-visit behaviour of every client) a navigation that arrives without ``bm_sz`` and
      ``_abck`` is served this page instead of the resource; solving it clears the session.
      The ``interstitial`` challenge provider serves the same page (HTML) or a 428 JSON with
      the same token and expression fields (XHR).
    * Scoring: a fixed regex solves the basic page without running any JavaScript, so a solved
      interstitial only WARNs (30) like ``simple``. Only the hard sha256 proof of work PASSes.
      Precedence: hard > interstitial/simple > none.
    * Hardening (flag ``pow_interstitial_hardened``, confidence LAB, default OFF): the page's
      arithmetic shape is randomized per issuance (identifier names, number of concatenated
      string parts, operand order, whitespace, quote style, ``Number`` / ``parseInt(..,10)`` /
      unary plus, decimal or hex ``i``, ``var`` / ``let``) so a fixed regex such as
      ``var\s+j\s*=\s*i\s*\+\s*Number\("(\d+)"\s*\+\s*"(\d+)"\)`` stops matching and only a
      client that interprets the script (or a robust JS parser) answers correctly. This is a lab
      device, not an Akamai feature; a determined solver can still interpret the script.

How a client passes it
    Challenge via the 428 JSON (or iframe attributes), solve, wait ``chlg_duration`` seconds,
    ``POST /_sec/verify?provider=<p>`` with ``{"token", "answer"|"answers"}``, keep the
    ``sec_cpt`` cookie. A pure-HTTP client can do all of this after sleeping, which is the
    intended lesson: the wait costs time, not identity.

Limits: difficulty and wait are lab constants, and the legacy routes under
``/akam/proof_of_work/`` exist only for the harness clients (same enforcement).
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
from urllib.parse import urlsplit

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

DEFAULT_DIFFICULTY = 4
SCRIPT_NAME = "sec-cpt-1.0.js"
SCRIPT_URL = f"/_sec/cp_challenge/{SCRIPT_NAME}"
PROVIDERS = ("crypto", "behavioral", "adaptive")
INTERSTITIAL = "interstitial"
INTERSTITIAL_PAGE_PATH = "/akam/proof_of_work/interstitial"  # on-demand route (router mount)
INTERSTITIAL_SCORE = 30  # a regex can solve the basic page: WARN, never PASS
COOKIE = "sec_cpt"
STATE_TTL = 3600
# An unsolved challenge is a gray signal, not proof of automation: 45 lands in the "strict"
# segment (challenge) for standard telemetry. A forged sec_cpt cookie is hostile: 80.
UNSOLVED_SCORE = 45
FORGED_SCORE = 80

SEC_CPT_JS = r"""(function () {
  'use strict';
  // Lab-written solver (not Akamai code). Interstitial mode reads the sec-cpt-if iframe;
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
        ch = await (await fetch('/akam/proof_of_work/challenge?provider=crypto',
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
      window.__akPowOk = ok;
      window.__akPowDone = true;
      window.dispatchEvent(new CustomEvent('ak:pow'));
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


def sub_nonce(nonce: str, index: int, count: int) -> str:
    """Single solution uses the nonce as is; adaptive solution ``i`` uses ``nonce.i``."""
    return nonce if count == 1 else f"{nonce}.{index}"


def safe_location(target: str | None) -> str | None:
    """Same-origin guard for the optional ``location`` in the interstitial reply.

    Only a plain absolute PATH is accepted: anything with a scheme or netloc, protocol-relative
    ``//host``, backslashes or control characters is rejected (returns None)."""
    if not target or not target.startswith("/") or target.startswith("//"):
        return None
    if "\\" in target or any(ord(c) < 32 or ord(c) == 127 for c in target):
        return None
    parts = urlsplit(target)
    return None if parts.scheme or parts.netloc else target


def new_interstitial_spec(rng: random.Random, hardened: bool) -> dict[str, Any]:
    """The arithmetic as DATA: ``pow = i + int("".join(parts))``."""
    if not hardened:
        return {"i": rng.randint(1000, 9999), "parts": [str(rng.randint(10, 99)) for _ in range(2)]}
    digits = str(rng.randint(1, 9)) + "".join(
        str(rng.randint(0, 9)) for _ in range(rng.randint(3, 7))
    )
    n = rng.randint(2, min(4, len(digits)))
    cuts = sorted(rng.sample(range(1, len(digits)), n - 1))
    parts = [digits[a:b] for a, b in zip([0, *cuts], [*cuts, len(digits)], strict=True)]
    return {"i": rng.randint(100, 99999), "parts": parts}


def expected_pow(spec: dict[str, Any]) -> int:
    """The server's answer, computed from the stored spec only (never from page text)."""
    return int(spec["i"]) + int("".join(spec["parts"]))


def render_arithmetic(rng: random.Random, spec: dict[str, Any], hardened: bool) -> tuple[str, str]:
    """JavaScript statements computing the answer, and the name of the result variable.

    Basic form (the observed shape): ``var i = 1234; var j = i + Number("56" + "78");``."""
    if not hardened:
        a, b = spec["parts"]
        return f'var i = {spec["i"]}; var j = i + Number("{a}" + "{b}");', "j"
    names: list[str] = []
    while len(names) < 3:
        n = rng.choice("abcdefghklmnpqrstuvwxyz_$") + "".join(
            rng.choice("abcdefghijklmnopqrstuvwxyz0123456789_") for _ in range(rng.randint(2, 6))
        )
        if n not in names and n not in {"i", "j", "var", "let", "new", "for", "if", "do", "in"}:
            names.append(n)
    vi, vj, vz = names

    def ws() -> str:
        return rng.choice(["", " ", "  ", "\t", "\n "])

    def lit(part: str) -> str:
        q = rng.choice(["'", '"'])
        return f"{q}{part}{q}"

    cat = f"{ws()}+{ws()}".join(lit(x) for x in spec["parts"])
    conv = rng.choice(
        [f"Number({cat})", f"parseInt({cat},{ws()}10)", f"(+({cat}))", f"Number({ws()}{cat}{ws()})"]
    )
    i_lit = hex(spec["i"]) if rng.random() < 0.4 else str(spec["i"])
    expr = f"{vi}{ws()}+{ws()}{conv}" if rng.random() < 0.5 else f"{conv}{ws()}+{ws()}{vi}"
    kw = rng.choice(["var", "let"])
    stmts = [f"{kw} {vi}{ws()}={ws()}{i_lit}", f"{kw} {vj}{ws()}={ws()}{expr}"]
    if rng.random() < 0.5:  # a decoy declaration that is not part of the answer
        stmts.insert(rng.randint(0, 2), f"{kw} {vz} = {rng.randint(1, 999)}")
    return (";" + ws()).join(stmts) + ";", vj


def render_interstitial(token: str, arithmetic: str, result: str) -> str:
    """The cookieless interstitial page (HTTP 200). Lab-written markup, not Akamai's."""
    return (
        '<!doctype html><html><head><meta charset="utf-8">'
        "<title>Checking your browser</title></head>"
        '<body style="font-family:system-ui,sans-serif;text-align:center;margin-top:3rem">'
        "<p>Checking your browser&hellip;</p><script>(function(){"
        f"{arithmetic}"
        'fetch("/_sec/verify?provider=interstitial",{method:"POST",credentials:"same-origin",'
        'headers:{"Content-Type":"application/json"},'
        f'body:JSON.stringify({{"bm-verify":"{token}","pow":{result}}})}})'
        ".then(function(r){return r.json()}).then(function(d){if(!d||!d.ok){return}"
        # Follow only a same-origin path (mirrors safe_location). Reloading the on-demand
        # interstitial route would just issue a fresh interstitial, so leave it for "/".
        'var l=d.location;if(typeof l==="string"&&/^\\/(?![\\/\\\\])[^\\x00-\\x1f\\\\]*$/.test(l))'
        "{location.replace(l)}"
        f'else if(location.pathname==="{INTERSTITIAL_PAGE_PATH}"){{location.replace("/")}}'
        "else{location.reload()}})"
        ".catch(function(){});})();</script></body></html>"
    )


@dataclass
class Settings:
    duration: float
    interval: int
    timeout: int
    adaptive_count: int
    difficulty: int


class ProofOfWork(DetectionModule):
    slug: ClassVar[str] = "proof_of_work"
    title: ClassVar[str] = "Proof of work interstitial"
    description: ClassVar[str] = (
        "sec_cpt-style challenge: crypto / behavioral / adaptive providers, a minimum solve "
        "duration (chlg_duration), 428 JSON or iframe interstitial, validated sec_cpt cookie "
        "and a re-challenge interval. Artifacts are MEDIUM-confidence approximations."
    )
    category: ClassVar[str] = "js"
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    client_scripts: ClassVar[list[str]] = ["pow.js"]
    challenge_providers: ClassVar[frozenset[str]] = frozenset({*PROVIDERS, INTERSTITIAL})
    flags: ClassVar[list[FlagSpec]] = [
        FlagSpec(
            name="pow_cookieless_gate",
            description="Serve the cookieless arithmetic interstitial to navigations that "
            "arrive without bm_sz/_abck (Bot Manager brief: prove cookie and JavaScript "
            "support). Off by default because it changes every client's first visit.",
            confidence=Confidence.MEDIUM,
            default=False,
            source="audit §1.2 case 6; Bot Manager brief",
        ),
        FlagSpec(
            name="pow_interstitial_hardened",
            description="LAB device: randomize the interstitial's arithmetic shape per "
            "issuance (names, parts, operand order, quotes, Number/parseInt) so fixed "
            "regex solvers break. Not an Akamai feature.",
            confidence=Confidence.LAB,
            default=False,
            source="lab",
        ),
    ]

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
        """(state, details): ok | forged | missing | expired | interstitial | simple | none."""
        sid = ctx.session_id
        raw = await ctx.store.get(f"pow:{sid}") if sid else None
        if raw:
            rec = json.loads(raw)
            cookie = ctx.cookies.get(COOKIE, "")
            if not cookie:
                return "missing", {}
            if "~3~" not in cookie or cookie != rec.get("cookie"):
                return "forged", {}
            interval = (await self.settings(ctx.store)).interval
            age = self.clock() - float(rec["solved_at"])
            if age > interval:
                return "expired", {"age": round(age, 1), "interval": interval}
            return "ok", {"provider": rec.get("provider"), "age": round(age, 1)}
        if sid and await ctx.store.get(f"pow:{INTERSTITIAL}:{sid}"):
            return INTERSTITIAL, {}
        if sid and await ctx.store.get(f"pow:simple:{sid}") == "ok":
            return "simple", {}
        return "none", {}

    async def evaluate(self, ctx: RequestContext) -> Signal:
        state, d = await self._state(ctx)
        if state == "ok":
            return self.signal(Verdict.PASS, 0, "proof of work solved, sec_cpt cookie valid", **d)
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
        if state == INTERSTITIAL:
            return self.signal(
                Verdict.WARN,
                INTERSTITIAL_SCORE,
                "only the basic arithmetic interstitial was solved (a regex can do that)",
            )
        if state == "simple":
            return self.signal(
                Verdict.WARN, INTERSTITIAL_SCORE, "only the lab's free-form arithmetic was solved"
            )
        return self.signal(Verdict.FAIL, UNSOLVED_SCORE, "no proof of work solved for this session")

    async def challenge_satisfied(self, ctx: RequestContext, provider: str | None = None) -> bool:
        # Only vouch for providers this module serves: a crypto sec_cpt must not satisfy
        # another module's challenge (e.g. the interactive tile game).
        if provider is not None and provider not in self.challenge_providers:
            return False
        state = (await self._state(ctx))[0]
        return state == "ok" or (provider == INTERSTITIAL and state == INTERSTITIAL)

    # -- challenge generation ------------------------------------------------------------
    async def make_challenge(
        self,
        store: Any,
        sid: str,
        provider: str,
        variant: str = "hard",
        *,
        hardened: bool = False,
        return_to: str | None = None,
    ) -> dict[str, Any]:
        """Create and persist a challenge; return the public payload (token = challenge_id)."""
        cfg = await self.settings(store)
        token = uuid.UUID(int=self.rng.getrandbits(128), version=4).hex
        now = self.clock()
        public: dict[str, Any] = {
            "provider": provider,
            "token": token,
            "challenge_id": token,  # legacy alias
            "timestamp": int(now),
            "timeout": cfg.timeout,
            "chlg_duration": cfg.duration,
            "variant": variant,
            "expires_in": cfg.timeout,
        }
        record: dict[str, Any] = {
            "sid": sid,
            "provider": provider,
            "variant": variant,
            "issued_at": now,
            "chlg_duration": cfg.duration,
            "timeout": cfg.timeout,
        }
        if variant == "simple":
            n = [self.rng.randint(2, 99) for _ in range(3)]
            ops = [self.rng.choice("+-*") for _ in range(2)]
            expr = f"{n[0]} {ops[0]} {n[1]} {ops[1]} {n[2]}"
            public.update(
                expression=expr,
                nonce=None,
                difficulty=0,
                lab_only=True,
                note="free-form lab expression; the Akamai-style arithmetic is 'interstitial'",
            )
            record["answer"] = eval_expression(expr)
        elif variant == INTERSTITIAL:
            spec = new_interstitial_spec(self.rng, hardened)
            arithmetic, result = render_arithmetic(self.rng, spec, hardened)
            public.update(
                {
                    "bm-verify": token,
                    "expression": arithmetic,
                    "result_var": result,
                    "hardened": hardened,
                }
            )
            record.update(spec=spec, return_to=safe_location(return_to))
        else:
            count = cfg.adaptive_count if provider == "adaptive" else 1
            difficulty = max(1, cfg.difficulty - 1) if count > 1 else cfg.difficulty
            nonce = f"{self.rng.getrandbits(64):016x}"
            record.update(nonce=nonce, difficulty=difficulty, count=count)
            if provider != "behavioral":  # behavioral has nothing to compute
                public.update(nonce=nonce, difficulty=difficulty)
                public["algo"] = "sha256(nonce + str(counter)) hex starts with `difficulty` zeros"
            if provider == "adaptive":
                public["count"] = count
        await store.set(f"pow:ch:{token}", json.dumps(record), ttl=cfg.timeout + 5)
        return public

    async def _sensor_posts(self, store: Any, sid: str) -> int:
        n = await store.get(f"sensor:n:{sid}")
        if n and str(n).isdigit() and int(n) > 0:
            return int(n)
        return 1 if await store.get(f"sensor:{sid}") else 0

    async def check(
        self, store: Any, sid: str, token: str, body: dict[str, Any], provider: str | None = None
    ) -> tuple[bool, str, dict[str, Any]]:
        """Consume challenge ``token``. Returns (ok, reason, record)."""
        key = f"pow:ch:{token}"
        raw = await store.get(key)
        if raw is None:
            return False, "unknown_or_replayed", {}
        await store.delete(key)  # single use, even on failure
        rec = json.loads(raw)
        if rec["sid"] != sid:
            return False, "wrong_session", rec
        if provider and provider != rec["provider"] and rec["variant"] != "simple":
            return False, "wrong_provider", rec
        elapsed = self.clock() - rec["issued_at"]
        if elapsed > rec["timeout"]:
            return False, "expired", rec
        try:
            if rec["variant"] == "simple":
                ok = int(body["answer"]) == rec["answer"]
            elif rec["variant"] == INTERSTITIAL:
                ok = int(body["pow"]) == expected_pow(rec["spec"])  # from the stored spec only
            elif rec["provider"] == "behavioral":
                ok = True
            else:
                answers = body.get("answers") or [body["answer"]]
                count = int(rec["count"])
                ok = len(answers) == count and all(
                    hard_ok(sub_nonce(rec["nonce"], i, count), str(int(a)), rec["difficulty"])
                    for i, a in enumerate(answers)
                )
        except (TypeError, ValueError, KeyError):
            return False, "bad_answer", rec
        if not ok:
            return False, "wrong_answer", rec
        if rec["variant"] == "hard" and elapsed < rec["chlg_duration"]:
            return False, "too_early", {**rec, "retry_after": rec["chlg_duration"] - elapsed}
        if rec["provider"] in ("behavioral", "adaptive") and not await self._sensor_posts(
            store, sid
        ):
            return False, "no_sensor", rec
        return True, "ok", rec

    async def accept(self, store: Any, sid: str, rec: dict[str, Any]) -> Response:
        """Record a solved challenge and build the success response (with ``sec_cpt``)."""
        resp = JSONResponse({"ok": True, "variant": rec["variant"], "provider": rec["provider"]})
        if rec["variant"] == "simple":
            await store.set(f"pow:simple:{sid}", "ok", ttl=STATE_TTL)
            return resp
        if rec["variant"] == INTERSTITIAL:
            await store.set(
                f"pow:{INTERSTITIAL}:{sid}", json.dumps({"solved_at": self.clock()}), ttl=STATE_TTL
            )
            # UNCONFIRMED: sources show a page reload / meta-refresh, not a JSON location.
            # Only a same-origin path (taken from the request that was challenged) is returned.
            if rec.get("return_to"):
                resp = JSONResponse({**json.loads(bytes(resp.body)), "location": rec["return_to"]})
            return resp
        now = self.clock()
        cookie = f"{self.rng.getrandbits(128):032X}~3~{int(now)}"
        await store.set(
            f"pow:{sid}",
            json.dumps({"cookie": cookie, "solved_at": now, "provider": rec["provider"]}),
            ttl=STATE_TTL,
        )
        await clear_challenge_failures(store, sid)
        resp.set_cookie(COOKIE, cookie, path="/", samesite="lax")
        return resp

    # -- challenge action ----------------------------------------------------------------
    async def issue_challenge(
        self, request: Request, ctx: RequestContext, provider: str, *, html: bool
    ) -> Response | None:
        if provider == INTERSTITIAL:
            return await self.interstitial_response(request, ctx, html=html)
        if provider not in PROVIDERS:
            return None
        public = await self.make_challenge(ctx.store, ctx.session_id, provider)
        public.pop("challenge_id", None)
        public.pop("variant", None)
        public.pop("expires_in", None)
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

    # -- cookieless interstitial -------------------------------------------------------
    async def interstitial_response(
        self, request: Request, ctx: RequestContext, *, html: bool
    ) -> Response:
        """HTML page (200) or, for XHR, a 428 JSON carrying the same token and expression."""
        return_to = request.url.path + (f"?{request.url.query}" if request.url.query else "")
        public = await self.make_challenge(
            ctx.store,
            ctx.session_id,
            INTERSTITIAL,
            INTERSTITIAL,
            hardened=ctx.flag("pow_interstitial_hardened"),
            return_to=return_to,
        )
        headers = {"Cache-Control": "no-store"}
        if not html:
            for k in ("challenge_id", "variant", "expires_in", "result_var"):
                public.pop(k, None)
            return JSONResponse(public, status_code=428, headers=headers)
        page = render_interstitial(public["token"], public["expression"], public["result_var"])
        return HTMLResponse(page, headers=headers)

    async def pre_request(self, request: Request, ctx: RequestContext) -> Response | None:
        """Cookieless gate (flag ``pow_cookieless_gate``, default off): a navigation that
        arrives without ``bm_sz`` and ``_abck`` gets the interstitial instead of the page."""
        if not ctx.flag("pow_cookieless_gate") or request.method != "GET":
            return None
        accept = request.headers.get("accept", "")
        if "text/html" not in accept or ("bm_sz" in ctx.cookies and "_abck" in ctx.cookies):
            return None
        return await self.interstitial_response(request, ctx, html=True)

    # -- routes --------------------------------------------------------------------------
    async def _verify(self, request: Request, provider: str | None) -> Response:
        sid = request.cookies.get("bm_sz", "")
        try:
            body = await request.json()
            token = str(body.get("token") or body.get("bm-verify") or body["challenge_id"])
            if not isinstance(body, dict):
                raise TypeError
        except (ValueError, KeyError, TypeError, AttributeError):
            return JSONResponse({"ok": False, "error": "bad_request"}, status_code=400)
        if not sid:
            return JSONResponse({"ok": False, "error": "no_session"}, status_code=400)
        store = request.app.state.store
        ok, reason, rec = await self.check(store, sid, token, body, provider)
        if not ok:
            extra = {"retry_after": round(rec["retry_after"], 2)} if "retry_after" in rec else {}
            return JSONResponse({"ok": False, "error": reason, **extra}, status_code=403)
        resp = await self.accept(store, sid, rec)
        if rec["variant"] == INTERSTITIAL:
            # issue/refresh bm_sz, ak_bmsc and _abck the way the lab models cookie issuance
            from app.main import finalize_cookies  # late import: main discovers this module

            await finalize_cookies(request, resp, store)
        return resp

    def root_router(self) -> APIRouter:
        """Vendor-style absolute paths (report §1.2 case 6, tier MEDIUM)."""
        r = APIRouter()

        @r.post("/_sec/verify")
        async def sec_verify(request: Request, provider: str | None = None) -> Response:
            return await self._verify(request, provider)

        @r.post("/_sec/cp_challenge/verify")
        async def cp_verify(request: Request, provider: str | None = None) -> Response:
            return await self._verify(request, provider)

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
        """Legacy lab routes under ``/akam/proof_of_work/`` (same enforcement)."""
        r = APIRouter()

        @r.get("/challenge")
        async def challenge(
            request: Request, variant: str = "hard", provider: str = "crypto"
        ) -> Response:
            sid = request.cookies.get("bm_sz", "")
            if not sid:
                return JSONResponse({"error": "no_session"}, status_code=400)
            if variant not in ("simple", "hard", INTERSTITIAL):
                return JSONResponse({"error": "bad_variant"}, status_code=400)
            if provider not in PROVIDERS:
                return JSONResponse({"error": "bad_provider"}, status_code=400)
            if variant == INTERSTITIAL:
                provider = INTERSTITIAL
            hardened = (await request.app.state.registry.resolved_flags()).get(
                "pow_interstitial_hardened", False
            )
            public = await self.make_challenge(
                request.app.state.store, sid, provider, variant, hardened=hardened
            )
            return JSONResponse(public, headers={"Cache-Control": "no-store"})

        @r.get("/interstitial")
        async def interstitial_page(request: Request, return_to: str = "") -> Response:
            """The interstitial page on demand; ``return_to`` is kept only if same-origin."""
            sid = request.cookies.get("bm_sz", "")
            if not sid:
                return JSONResponse({"error": "no_session"}, status_code=400)
            hardened = (await request.app.state.registry.resolved_flags()).get(
                "pow_interstitial_hardened", False
            )
            public = await self.make_challenge(
                request.app.state.store,
                sid,
                INTERSTITIAL,
                INTERSTITIAL,
                hardened=hardened,
                return_to=return_to,
            )
            page = render_interstitial(public["token"], public["expression"], public["result_var"])
            return HTMLResponse(page, headers={"Cache-Control": "no-store"})

        @r.post("/interstitial/verify")
        async def interstitial_verify(request: Request) -> Response:
            return await self._verify(request, INTERSTITIAL)

        @r.post("/verify")
        async def verify(request: Request) -> Response:
            return await self._verify(request, None)

        @r.get("/pow.js")
        async def pow_js() -> Response:
            return Response(
                SEC_CPT_JS,
                media_type="application/javascript",
                headers={"Cache-Control": "no-store"},
            )

        return r
