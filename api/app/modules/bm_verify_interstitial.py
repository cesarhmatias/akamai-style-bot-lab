r"""Cookieless ``bm-verify`` interstitial (audit §1.2 case 6, correction of 2026-10-02).

Mechanism
    A navigation from a session with no server-side proof that it stores cookies and runs
    JavaScript gets an HTML page instead of the resource. The page's inline script does one line
    of arithmetic and POSTs the result with a single-use ``bm-verify`` token; a client without
    JavaScript can follow the page's meta refresh after a time penalty instead. It is a
    capability check, NOT a proof of work: the "work" is one addition, a fixed regex answers it
    without running the script, and checking the answer costs the server as much as finding
    it. Akamai names the answer field ``pow``; the lab keeps that wire name and nothing else of
    the concept.

How real Akamai uses it (report §1.2 case 6, tier MEDIUM)
    * The Bot Manager brief describes, apart from its "minimum-time-to-solve cryptographic
      puzzles", an interstitial challenge that "requires clients to prove they support storing
      cookies and executing JavaScript. If not, Bot Manager enforces a time penalty".
    * Observed pages (bershka-scraper, 2026-09-19..22; sugarplum #172/#177, 2026-09-27) carry a
      ``bm-verify`` token (``AAQ...``), a script of the form
      ``var i = 1789910678; var j = i + Number("3886" + "11036");`` that POSTs JSON
      ``{"bm-verify": <token>, "pow": <i + int(a+b)>}`` to ``/_sec/verify?provider=interstitial``
      and reloads, and a ``<meta http-equiv="refresh" content="5; URL='<url>&bm-verify=...'">``.
      The page itself sets no Akamai cookie; the verify response sets ``_abck``, ``bm_sz`` and
      ``ak_bmsc``, and the cleared session kept getting the real page. Refetching the URL with
      the single-use token (no JavaScript) returned the real page once. A JSON ``location`` in
      the reply is UNCONFIRMED (LOW: the sources show a reload or the meta refresh).
    Page wording, token content and cookie timing are LAB approximations.

How the lab simulates it
    * Page: HTTP 200 HTML with a per-issuance ``bm-verify`` token (``AAQ`` + random lab data)
      bound to ``bm_sz`` (single use, expires after ``challenge_timeout``; failure reasons
      ``unknown_or_replayed``, ``wrong_session``, ``expired``, ``bad_answer``,
      ``wrong_answer``). The arithmetic is DATA in an inline script; the server computes the
      expected answer from its stored spec, never from the page text and never with ``eval``.
      Basic shape as observed: ``i`` is the issuing Unix time (the observed 1789910678 is
      2026-09-20 UTC, inside the capture window: an inference) and the parts have 4 and 5
      digits, so the answer often exceeds 2**31 - 1, as the observed one does (a 32-bit signed
      solver overflows).
    * Verify: ``POST /_sec/verify?provider=interstitial`` (the engine's shared verify route,
      ``verify_challenge``), body ``{"bm-verify": token, "pow": int}``. On success the lab stores
      ``bm_verify:{sid}``, issues/refreshes ``bm_sz``, ``ak_bmsc`` and ``_abck`` through
      ``main.finalize_cookies`` and answers ``{"ok": true, ...}``; the page then reloads.
      APPROXIMATION: the lab already hands those cookies out with the page, because it binds
      the token to ``bm_sz``; in the capture they arrive only with the verify response. Cookie
      presence therefore proves nothing here, and the gate checks server-side state.
    * ``location`` (flag ``interstitial_location``, LOW, default off): the reply carries the
      challenged request's path, only when ``safe_location`` accepts it (no scheme, netloc,
      ``//``, backslash or control characters).
    * Gate: with the flag ``interstitial_cookieless_gate`` (MEDIUM, default OFF because it
      changes the first-visit behaviour of every client) an HTML navigation is served this page
      instead of the resource until the session has server-side proof: a solved interstitial,
      a valid ``sec_cpt`` (``sec_cpt_challenge``) or an ``_abck`` the sensor flow validated.
      Reloading with the cookies the page handed out is not enough. The ``interstitial``
      challenge provider serves the same page (HTML) or a 428 JSON with the same token and
      expression fields (XHR).
    * No-JavaScript path: the page's meta refresh re-requests the URL with ``bm-verify=<token>``
      after ``REFRESH_SECONDS`` (5, as observed). A gated navigation that carries an unused
      token at least that long after issue passes once (the brief's time penalty; that Akamai
      enforces the wait server-side is an inference). The token is consumed and nothing is
      cleared, so the next navigation gets a new interstitial.
    * Scoring (``/protected/bm_verify_interstitial`` only: ``applies_to`` is empty, so the
      all-module pages carry ``sec_cpt_challenge``'s signal and not a second "nothing solved"
      one) follows the best proof the session holds: a valid ``sec_cpt`` or a validated
      ``_abck`` PASSes; a solved interstitial only WARNs 20, because a regex solves the basic
      page (20 is the top of the cautious band of every telemetry type, so the default policy
      monitors the session, as the bershka capture shows for a cleared session); no proof
      FAILs 45 while the interstitial is in use (gate on, or ``challenge_provider`` is
      ``interstitial``) and SKIPs otherwise.
    * Hardening (flag ``interstitial_hardened``, confidence LAB, default OFF): the page's
      arithmetic shape is randomized per issuance (identifier names, number of concatenated
      string parts, operand order, whitespace, quote style, ``Number`` / ``parseInt(..,10)`` /
      unary plus, decimal or hex ``i``, ``var`` / ``let``) so a fixed regex such as
      ``var\s+j\s*=\s*i\s*\+\s*Number\("(\d+)"\s*\+\s*"(\d+)"\)`` stops matching and only a
      client that interprets the script (or a robust JS parser) answers correctly. This is a lab
      device, not an Akamai feature; a determined solver can still interpret the script.

How a client passes it
    Parse the token and the arithmetic, POST ``{"bm-verify", "pow"}``, reload; or, without
    JavaScript, follow the meta refresh after 5 seconds (one page, nothing cleared). Solving it
    tops out at WARN; a solved ``sec_cpt`` challenge or a validated ``_abck`` is what PASSes.

Limits: the page wording and the cookie timing are approximations, the server-side wait on the
refresh path is an inference, and the hardened variant defeats regexes, not a JS engine.
"""

from __future__ import annotations

import json
import random
import string
import time
from collections.abc import Callable
from html import escape as html_escape
from typing import Any, ClassVar
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from app.contract import (
    Confidence,
    DetectionModule,
    EndpointClass,
    FlagSpec,
    RequestContext,
    Signal,
    Verdict,
)
from app.modules.sec_cpt_challenge import sec_cpt_state
from app.policy import PolicyStore
from app.session import is_abck_validated

PROVIDER = "interstitial"
GATE_FLAG = "interstitial_cookieless_gate"
LOCATION_FLAG = "interstitial_location"
HARDENED_FLAG = "interstitial_hardened"
# A regex can solve the basic page: WARN, never PASS. 20 is the top of the cautious band for
# every telemetry type (policy.DEFAULT_BANDS), so the default policy monitors the session and
# serves the page, as the bershka capture shows for a cleared session.
SOLVED_SCORE = 20
# No proof while the interstitial is in use: a gray signal (strict segment, challenge).
UNSOLVED_SCORE = 45
REFRESH_SECONDS = 5  # the observed meta refresh delay (sugarplum #172)
TOKEN_PREFIX = "AAQ"  # observed bm-verify tokens start with AAQ; the rest is random lab data
TOKEN_ALPHABET = string.ascii_letters + string.digits
STATE_TTL = 3600


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


def request_target(path: str, query: str) -> str:
    """Path and query of a challenged request, minus any stale ``bm-verify`` parameter."""
    kept = [(k, v) for k, v in parse_qsl(query, keep_blank_values=True) if k != "bm-verify"]
    return path + (f"?{urlencode(kept)}" if kept else "")


def with_token(target: str, token: str) -> str:
    """``target`` (a same-origin path) with ``bm-verify=<token>`` appended, percent-encoded so it
    can sit inside the meta refresh attribute."""
    parts = urlsplit(target)
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != "bm-verify"]
    query.append(("bm-verify", token))
    return urlunsplit(("", "", quote(parts.path or "/", safe="/%"), urlencode(query), ""))


def js_string(value: str) -> str:
    """A JavaScript string literal that is also safe inside an inline ``<script>``."""
    return (
        json.dumps(value).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    )


def new_spec(rng: random.Random, hardened: bool, now: float) -> dict[str, Any]:
    """The arithmetic as DATA: answer = ``i + int("".join(parts))``.

    Basic shape as observed: ``i`` is the issuing Unix time and the parts have 4 and 5 digits."""
    if not hardened:
        return {
            "i": int(now),
            "parts": [str(rng.randint(1000, 9999)), str(rng.randint(10000, 99999))],
        }
    digits = str(rng.randint(1, 9)) + "".join(
        str(rng.randint(0, 9)) for _ in range(rng.randint(3, 7))
    )
    n = rng.randint(2, min(4, len(digits)))
    cuts = sorted(rng.sample(range(1, len(digits)), n - 1))
    parts = [digits[a:b] for a, b in zip([0, *cuts], [*cuts, len(digits)], strict=True)]
    return {"i": rng.randint(100, 99999), "parts": parts}


def expected_answer(spec: dict[str, Any]) -> int:
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


def render_page(
    token: str, arithmetic: str, result: str, *, refresh_url: str, after: str | None = None
) -> str:
    """The cookieless interstitial page (HTTP 200). Lab-written markup, not Akamai's.

    ``refresh_url`` is the no-JavaScript path: a meta refresh carrying the single-use token, as
    observed. After a successful verify the script follows a same-origin ``location`` when the
    reply has one (LOW flag), else goes to ``after`` (only the on-demand lab route sets it:
    reloading that route would just issue a fresh interstitial), else reloads, as observed."""
    then = f"location.replace({js_string(after)})" if after else "location.reload()"
    return (
        '<!doctype html><html><head><meta charset="utf-8">'
        f'<meta http-equiv="refresh" content="{REFRESH_SECONDS}; '
        f"URL='{html_escape(refresh_url)}'\">"
        "<title>Checking your browser</title></head>"
        '<body style="font-family:system-ui,sans-serif;text-align:center;margin-top:3rem">'
        "<p>Checking your browser&hellip;</p><script>(function(){"
        f"{arithmetic}"
        'fetch("/_sec/verify?provider=interstitial",{method:"POST",credentials:"same-origin",'
        'headers:{"Content-Type":"application/json"},'
        f'body:JSON.stringify({{"bm-verify":"{token}","pow":{result}}})}})'
        ".then(function(r){return r.json()}).then(function(d){if(!d||!d.ok){return}"
        # Follow only a same-origin path (mirrors safe_location).
        'var l=d.location;if(typeof l==="string"&&/^\\/(?![\\/\\\\])[^\\x00-\\x1f\\\\]*$/.test(l))'
        "{location.replace(l)}"
        f"else{{{then}}}}})"
        ".catch(function(){});})();</script></body></html>"
    )


class BmVerifyInterstitial(DetectionModule):
    slug: ClassVar[str] = "bm_verify_interstitial"
    title: ClassVar[str] = "Cookieless bm-verify interstitial"
    description: ClassVar[str] = (
        "Interstitial that asks a cookieless navigation to prove it stores cookies and runs "
        "JavaScript: one line of arithmetic POSTed with a single-use bm-verify token, or a meta "
        "refresh after a time penalty. A capability check, not a proof of work. "
        "MEDIUM-confidence approximation; the cookieless gate is behind a flag (off)."
    )
    category: ClassVar[str] = "js"
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    # Explicit /protected/<slug> only. The gate and the challenge action work without it, and an
    # unsolved interstitial must not add a second "nothing solved" signal next to
    # sec_cpt_challenge's on every page.
    applies_to: ClassVar[frozenset[EndpointClass]] = frozenset()
    challenge_providers: ClassVar[frozenset[str]] = frozenset({PROVIDER})
    flags: ClassVar[list[FlagSpec]] = [
        FlagSpec(
            name=GATE_FLAG,
            description="Serve the cookieless bm-verify interstitial to HTML navigations until "
            "the session has server-side proof (Bot Manager brief: prove cookie and JavaScript "
            "support). Off by default because it changes every client's first visit.",
            confidence=Confidence.MEDIUM,
            default=False,
            source="audit §1.2 case 6; Bot Manager brief",
        ),
        FlagSpec(
            name=LOCATION_FLAG,
            description="Add a same-origin JSON location to the interstitial's verify reply. "
            "Unverified: published sources show the page reloading (or a meta refresh), "
            "never a location field.",
            confidence=Confidence.LOW,
            default=False,
            source="audit §1.2 case 6, §3.1 (JSON location: one unpublished client)",
        ),
        FlagSpec(
            name=HARDENED_FLAG,
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
        timeout: int | None = None,
    ) -> None:
        self.rng = rng or random.Random()
        self.clock = clock
        self._timeout = timeout

    async def timeout(self, store: Any) -> int:
        if self._timeout is not None:
            return self._timeout
        return (await PolicyStore(store).get()).params.challenge_timeout

    # -- verdict -------------------------------------------------------------------------
    async def proof(self, ctx: RequestContext) -> str:
        """Best server-side proof that the session stores cookies and runs JavaScript:
        ``sec_cpt`` | ``abck`` (validated by the sensor flow) | ``interstitial`` | ``none``."""
        sid = ctx.session_id
        if not sid:
            return "none"
        if (await sec_cpt_state(ctx, self.clock()))[0] == "ok":
            return "sec_cpt"
        if await is_abck_validated(ctx.store, sid):
            return "abck"
        if await ctx.store.get(f"bm_verify:{sid}"):
            return "interstitial"
        return "none"

    async def in_use(self, ctx: RequestContext) -> bool:
        """The interstitial can be served: the gate is on or the policy challenges with it."""
        if ctx.flag(GATE_FLAG):
            return True
        return (await PolicyStore(ctx.store).get()).params.challenge_provider == PROVIDER

    async def evaluate(self, ctx: RequestContext) -> Signal:
        proof = await self.proof(ctx)
        if proof == "sec_cpt":
            return self.signal(
                Verdict.PASS, 0, "cookie and JavaScript support proven by a valid sec_cpt"
            )
        if proof == "abck":
            return self.signal(
                Verdict.PASS, 0, "cookie and JavaScript support proven by a validated _abck"
            )
        if proof == "interstitial":
            return self.signal(
                Verdict.WARN,
                SOLVED_SCORE,
                "only the basic arithmetic interstitial was solved (a regex can do that)",
            )
        if await self.in_use(ctx):
            return self.signal(
                Verdict.FAIL, UNSOLVED_SCORE, "no proof of cookie and JavaScript support yet"
            )
        return self.signal(
            Verdict.SKIP, 0, "interstitial not in use (gate off, policy uses another provider)"
        )

    async def challenge_satisfied(self, ctx: RequestContext, provider: str | None = None) -> bool:
        # Only vouch for the interstitial provider: a solved interstitial is too weak to waive
        # a crypto or tile challenge, while a sec_cpt or validated _abck waives this one.
        if provider is not None and provider not in self.challenge_providers:
            return False
        return await self.proof(ctx) != "none"

    # -- challenge generation ------------------------------------------------------------
    async def make_challenge(
        self, store: Any, sid: str, *, hardened: bool, return_to: str | None = None
    ) -> dict[str, Any]:
        """Create and persist an interstitial; return the public payload (token = bm-verify)."""
        timeout = await self.timeout(store)
        token = TOKEN_PREFIX + "".join(self.rng.choice(TOKEN_ALPHABET) for _ in range(61))
        now = self.clock()
        spec = new_spec(self.rng, hardened, now)
        arithmetic, result = render_arithmetic(self.rng, spec, hardened)
        record = {
            "sid": sid,
            "issued_at": now,
            "timeout": timeout,
            "spec": spec,
            "return_to": safe_location(return_to),
        }
        await store.set(f"bm_verify:ch:{token}", json.dumps(record), ttl=timeout + 5)
        return {
            "provider": PROVIDER,
            "token": token,
            "bm-verify": token,
            "expression": arithmetic,
            "result_var": result,
            "hardened": hardened,
            "timestamp": int(now),
            "timeout": timeout,
        }

    def check(
        self, sid: str, rec: dict[str, Any], body: dict[str, Any]
    ) -> tuple[bool, str]:
        """Judge an answer against the (already consumed) challenge record ``rec``."""
        if rec["sid"] != sid:
            return False, "wrong_session"
        if self.clock() - rec["issued_at"] > rec["timeout"]:
            return False, "expired"
        try:
            ok = int(body["pow"]) == expected_answer(rec["spec"])  # from the stored spec only
        except (TypeError, ValueError, KeyError):
            return False, "bad_answer"
        return (True, "ok") if ok else (False, "wrong_answer")

    async def verify_challenge(
        self, request: Request, token: str, body: dict[str, Any], provider: str | None
    ) -> Response | None:
        """Redeem a token this module issued (the engine's shared ``/_sec/verify`` route)."""
        store = request.app.state.store
        key = f"bm_verify:ch:{token}"
        raw = await store.get(key)
        if raw is None:
            return None  # not ours: the route asks the next challenge provider
        await store.delete(key)  # single use, even on failure
        sid = request.cookies.get("bm_sz", "")
        rec = json.loads(raw)
        ok, reason = self.check(sid, rec, body)
        if not ok:
            return JSONResponse({"ok": False, "error": reason}, status_code=403)
        await store.set(f"bm_verify:{sid}", json.dumps({"solved_at": self.clock()}), ttl=STATE_TTL)
        flags = await request.app.state.registry.resolved_flags()
        reply: dict[str, Any] = {"ok": True, "provider": PROVIDER}
        # LOW (flag interstitial_location): sources show a page reload or a meta refresh, never
        # a JSON location. Only a same-origin path (from the request that was challenged).
        if flags.get(LOCATION_FLAG) and rec.get("return_to"):
            reply["location"] = rec["return_to"]
        resp = JSONResponse(reply)
        # issue/refresh bm_sz, ak_bmsc and _abck the way the lab models cookie issuance
        from app.main import finalize_cookies  # late import: main discovers this module

        await finalize_cookies(request, resp, store, flags)
        return resp

    # -- challenge action and gate -------------------------------------------------------
    async def issue_challenge(
        self, request: Request, ctx: RequestContext, provider: str, *, html: bool
    ) -> Response | None:
        if provider != PROVIDER:
            return None
        return await self.interstitial_response(request, ctx, html=html)

    async def interstitial_response(
        self, request: Request, ctx: RequestContext, *, html: bool
    ) -> Response:
        """HTML page (200) or, for XHR, a 428 JSON carrying the same token and expression."""
        return_to = request_target(request.url.path, request.url.query)
        public = await self.make_challenge(
            ctx.store, ctx.session_id, hardened=ctx.flag(HARDENED_FLAG), return_to=return_to
        )
        headers = {"Cache-Control": "no-store"}
        if not html:
            public.pop("result_var")
            return JSONResponse(public, status_code=428, headers=headers)
        page = render_page(
            public["token"],
            public["expression"],
            public["result_var"],
            refresh_url=with_token(return_to, public["token"]),
        )
        return HTMLResponse(page, headers=headers)

    async def gate_cleared(self, ctx: RequestContext) -> bool:
        """Server-side proof only. The lab hands ``bm_sz``/``ak_bmsc``/``_abck`` out with the
        interstitial page itself (the token is bound to ``bm_sz``), so a cookie jar alone proves
        nothing: a solved interstitial, a valid ``sec_cpt`` or a validated ``_abck`` clears it."""
        sid = ctx.session_id
        if not sid or ctx.cookies.get("bm_sz") != sid:
            return False
        return await self.proof(ctx) != "none"

    async def redeem_refresh(self, store: Any, token: str, sid: str) -> bool:
        """The meta-refresh path for clients without JavaScript.

        A navigation carrying an unused interstitial token passes the gate once, provided it
        arrives at least ``REFRESH_SECONDS`` after the page was issued (the time penalty). The
        token is then consumed; a request that comes too early keeps it. A request that sends a
        ``bm_sz`` must send the one the token was issued for; one without cookies is accepted
        (the observed refetch needs neither cookies nor JavaScript)."""
        key = f"bm_verify:ch:{token}"
        raw = await store.get(key)
        if raw is None:
            return False
        rec = json.loads(raw)
        if sid and rec["sid"] != sid:
            return False
        elapsed = self.clock() - rec["issued_at"]
        if elapsed < REFRESH_SECONDS:
            return False
        await store.delete(key)  # single use
        return bool(elapsed <= rec["timeout"])

    async def pre_request(self, request: Request, ctx: RequestContext) -> Response | None:
        """Cookieless gate (flag ``interstitial_cookieless_gate``, default off): an HTML
        navigation from a session without server-side proof gets the interstitial instead of the
        page, unless it carries a redeemable ``bm-verify`` token from the page's meta refresh."""
        if not ctx.flag(GATE_FLAG) or request.method != "GET":
            return None
        if "text/html" not in request.headers.get("accept", "") or await self.gate_cleared(ctx):
            return None
        token = request.query_params.get("bm-verify", "")
        if token and await self.redeem_refresh(ctx.store, token, request.cookies.get("bm_sz", "")):
            return None  # one navigation passes; nothing is cleared
        return await self.interstitial_response(request, ctx, html=True)

    # -- routes --------------------------------------------------------------------------
    def router(self) -> APIRouter:
        """Lab route under ``/akam/bm_verify_interstitial/``: the page on demand (the vendor only
        serves it from the gate or as a challenge action)."""
        r = APIRouter()

        @r.get("/page")
        async def page(request: Request, return_to: str = "") -> Response:
            """The interstitial on demand; ``return_to`` is kept only if same-origin.

            After a successful verify the page goes to ``return_to`` (default ``/``), because
            reloading this route would only issue a fresh interstitial."""
            sid = request.cookies.get("bm_sz", "")
            if not sid:
                return JSONResponse({"error": "no_session"}, status_code=400)
            hardened = (await request.app.state.registry.resolved_flags()).get(
                HARDENED_FLAG, False
            )
            after = safe_location(return_to) or "/"
            public = await self.make_challenge(
                request.app.state.store, sid, hardened=hardened, return_to=return_to
            )
            body = render_page(
                public["token"],
                public["expression"],
                public["result_var"],
                refresh_url=with_token(after, public["token"]),
                after=after,
            )
            return HTMLResponse(body, headers={"Cache-Control": "no-store"})

        return r
