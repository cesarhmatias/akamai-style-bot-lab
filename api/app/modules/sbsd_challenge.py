"""SBSD-style challenge (case 8, audit §1.2 case 8). Confidence: LOW.

Mechanism
    A second challenge channel next to ``_abck``: a per-issuance obfuscated script computes a
    value from browser-only state and posts it back; cookies are issued on success.

How real Akamai uses it (report §1.2 case 8) -- UNVERIFIED, VENDOR-SOURCED
    There is no Akamai primary source. Scraper-vendor docs (Hyper Solutions, xhrdev) call it
    "State Based Scraping Detection" and describe, all tier LOW:
    * passive mode: a script at ``/<random path>?v=<UUID>`` on normal pages, then two POSTs
      (index 0 and 1) of ``{"body": "..."}`` to that path;
    * blocking mode: a challenge page whose script adds ``&t=<token>``, then one POST to
      ``/<path>?t=<token>``;
    * the ``sbsd_o`` cookie (or ``bm_so`` if absent) is issued FIRST and is an input to the
      payload; success leaves ``bm_s``, ``bm_ss``, ``bm_sc`` and ``bm_lso`` (names only; their
      purposes and lifetimes are inconsistent across sources).
    The report also notes that the name and timing fit Content Protector; that link is
    SPECULATION, nothing public connects them.

How the lab simulates it
    * Flag ``sbsd_vendor_flow`` OFF (default): the ORIGINAL LAB DEVICE. ``/akam/sbsd_challenge/
      sbsd.js?v=<UUID>`` serves a per-issuance randomized op-chain script over document/
      navigator values, answered with ``POST /akam/sbsd_challenge/verify {t, v}``. It is a lab
      teaching device, not a model of Akamai; the vendor-described flow below is unverified.
    * Flag ``sbsd_vendor_flow`` ON (LOW): the vendor-described flow. A per-session random
      multi-segment path claims ``GET`` (script) and ``POST`` via ``handle_dynamic``. The script
      response issues ``sbsd_o`` first; the script reads it and builds the lab-defined payload
      ``base64(json{t, v, o, i})`` (``t`` is the op-chain answer, ``o`` the cookie value, ``i``
      the post index) sent as ``{"body": "..."}``. Passive mode needs index 0 then 1; blocking
      mode (``GET /akam/sbsd_challenge/blocking`` or the ``sbsd`` challenge provider) adds
      ``&t=<token>`` to the script URL and needs one POST to ``/<path>?t=<token>``. On success
      ``bm_s``, ``bm_ss``, ``bm_sc`` and ``bm_lso`` are set (vendor-only names, lab values).
      The body encoding is lab-defined, not Akamai's.

How a client passes it
    Execute the served script in a JS environment (the op chain reads title/UA/DOM values),
    keep ``sbsd_o`` and post the body(ies). A pure-HTTP client must reimplement the script.

Limits: a determined client can port the generated JS to Python or run a minimal JS engine;
nothing is replayable between sessions or issuances.
"""

from __future__ import annotations

import base64
import json
import random
import string
import time
import uuid
from collections.abc import Callable
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

VENDOR_COOKIES: dict[str, int] = {  # name -> Max-Age; names LOW, lifetimes from weak disclosures
    "bm_s": 30 * 86400,
    "bm_ss": 3600,
    "bm_sc": 30 * 86400,
    "bm_lso": 30 * 86400,
}
SBSD_O = "sbsd_o"
M32 = 0xFFFFFFFF
SPEC_TTL = 300
OPS = ("add", "sub", "xor", "and", "or", "imul", "rotl", "xorshr")


def _src_value(src: dict[str, Any], ua: str) -> int:
    kind = src["kind"]
    if kind == "title_len":
        return len(src["s"])
    if kind == "ua_len":
        return len(ua)
    if kind == "dom_attr":
        return int(src["n"])
    if kind == "dom_text_len":
        return len(src["s"])
    if kind == "ua_char":
        return ord(ua[src["i"] % len(ua)]) if ua else 0
    if kind == "str_char":
        return ord(src["s"][src["i"]])
    raise ValueError(kind)


def apply_op(op: str, acc: int, val: int, k: int) -> int:
    if op == "add":
        r = acc + val
    elif op == "sub":
        r = acc - val
    elif op == "xor":
        r = acc ^ val
    elif op == "and":
        r = acc & val
    elif op == "or":
        r = acc | val
    elif op == "imul":
        r = (acc & M32) * (val & M32)
    elif op == "rotl":
        a = acc & M32
        r = (a << k) | (a >> (32 - k))
    elif op == "xorshr":
        r = acc ^ ((acc & M32) >> k)
    else:
        raise ValueError(op)
    return r & M32


def expected_answer(spec: dict[str, Any], ua: str) -> int:
    """Replay the op list: unsigned 32-bit result (``acc >>> 0`` in JS)."""
    vals = {s["name"]: _src_value(s, ua) for s in spec["sources"]}
    acc = spec["seed"] & M32
    for step in spec["steps"]:
        acc = apply_op(step["op"], acc, vals[step["src"]] if step["src"] else 0, step["k"])
    return acc


def _ident(rng: random.Random, used: set[str]) -> str:
    while True:
        n = rng.choice("abcdefghijklmnopqrstuvwxyz_$") + "".join(
            rng.choice(string.ascii_letters + string.digits + "_") for _ in range(rng.randint(3, 7))
        )
        if n not in used:
            used.add(n)
            return n


def _word(rng: random.Random, n: int) -> str:
    return "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(n))


def generate_spec(rng: random.Random, v: str) -> dict[str, Any]:
    used: set[str] = {"document", "navigator", "Math", "window", "fetch", "JSON", "v", "el"}
    sources: list[dict[str, Any]] = []

    def add(**kw: Any) -> None:
        sources.append({"name": _ident(rng, used), **kw})

    add(kind="title_len", s=_word(rng, rng.randint(5, 40)))
    add(kind="ua_len")
    add(kind="dom_attr", n=rng.randint(1000, 2_000_000_000), attr=_ident(rng, used))
    add(kind="dom_text_len", s=_word(rng, rng.randint(3, 50)))
    for _ in range(rng.randint(1, 3)):
        add(kind="ua_char", i=rng.randint(0, 400))
    for _ in range(rng.randint(1, 2)):
        s = _word(rng, rng.randint(6, 16))
        add(kind="str_char", s=s, i=rng.randint(0, len(s) - 1))
    rng.shuffle(sources)
    steps: list[dict[str, Any]] = []
    # every source participates at least once, then extra random steps
    order = [s["name"] for s in sources] + [
        rng.choice(sources)["name"] for _ in range(rng.randint(4, 8))
    ]
    rng.shuffle(order)
    for name in order:
        op = rng.choice(OPS)
        k = rng.randint(1, 31) if op in ("rotl", "xorshr") else 0
        steps.append({"op": op, "src": name, "k": k})
    steps.append({"op": "rotl", "src": None, "k": rng.randint(1, 31)})
    return {
        "v": v,
        "acc": _ident(rng, used),
        "seed": rng.getrandbits(32),
        "sources": sources,
        "steps": steps,
    }


def _js_decl(src: dict[str, Any], el: str) -> str:
    n, kind = src["name"], src["kind"]
    if kind == "title_len":
        return (
            f"var {n}=(function(){{var o=document.title;document.title={json.dumps(src['s'])};"
            f"var l=document.title.length;document.title=o;return l}})();"
        )
    if kind == "ua_len":
        return f"var {n}=navigator.userAgent.length;"
    if kind == "dom_attr":
        a = src["attr"]
        return (
            f"var {n}=(function(){{var {el}=document.createElement('div');"
            f"{el}.setAttribute('data-{a}','{src['n']}');"
            f"return parseInt({el}.getAttribute('data-{a}'),10)}})();"
        )
    if kind == "dom_text_len":
        return (
            f"var {n}=(function(){{var {el}=document.createElement('span');"
            f"{el}.textContent={json.dumps(src['s'])};return {el}.textContent.length}})();"
        )
    if kind == "ua_char":
        return f"var {n}=navigator.userAgent.charCodeAt({src['i']}%navigator.userAgent.length);"
    return f"var {n}={json.dumps(src['s'])}.charCodeAt({src['i']});"


def _js_step(acc: str, step: dict[str, Any]) -> str:
    op, s, k = step["op"], step["src"], step["k"]
    if op == "add":
        e = f"({acc}+{s})|0"
    elif op == "sub":
        e = f"({acc}-{s})|0"
    elif op == "xor":
        e = f"{acc}^{s}"
    elif op == "and":
        e = f"{acc}&{s}"
    elif op == "or":
        e = f"{acc}|{s}"
    elif op == "imul":
        e = f"Math.imul({acc},{s})"
    elif op == "rotl":
        e = f"(({acc}<<{k})|({acc}>>>{32 - k}))|0"
    else:
        e = f"{acc}^({acc}>>>{k})"
    return f"{acc}={e};"


def render_js(spec: dict[str, Any], verify_url: str) -> str:
    rng = random.Random(spec["seed"])  # only for decl ordering/el name; spec stays authoritative
    used = {s["name"] for s in spec["sources"]} | {spec["acc"]}
    el = _ident(rng, used)
    decls = [_js_decl(s, el) for s in spec["sources"]]
    rng.shuffle(decls)
    acc = spec["acc"]
    body = "".join(decls) + f"var {acc}={spec['seed']}|0;"
    for st in spec["steps"]:
        if st["src"] is None:
            st = {**st, "src": "0"}
        body += _js_step(acc, st)
    post = (
        f"fetch({json.dumps(verify_url)},{{method:'POST',credentials:'include',"
        "headers:{'Content-Type':'application/json'},"
        f"body:JSON.stringify({{t:{acc}>>>0,v:{json.dumps(spec['v'])}}})}})"
        ".then(function(r){window.__akSbsdOk=r.ok}).catch(function(){window.__akSbsdOk=false})"
        ".then(function(){window.__akSbsdDone=true;"
        "window.dispatchEvent(new CustomEvent('ak:sbsd'))});"
    )
    return f"(function(){{'use strict';{body}{post}}})();\n"


def render_vendor_js(spec: dict[str, Any], post_path: str, mode: str, token: str = "") -> str:
    """Vendor-flow script: same op chain as ``render_js``, but the answer, the ``sbsd_o`` cookie
    value and the post index travel as ``{"body": base64(json)}`` to ``post_path``.

    ``mode`` is ``passive`` (POST index 0, then 1, to ``post_path``) or ``blocking`` (one POST
    to ``post_path?t=<token>``, then reload). The payload layout is lab-defined."""
    base = render_js(spec, "/unused")
    # reuse the op chain: take everything up to the fetch of render_js
    head = base[: base.index("fetch(")]
    acc = spec["acc"]
    target = post_path if mode == "passive" else f"{post_path}?t={token}"
    tail = (
        "var m=document.cookie.match(/(?:^|; )sbsd_o=([^;]*)/)"
        "||document.cookie.match(/(?:^|; )bm_so=([^;]*)/);"
        "var o=m?decodeURIComponent(m[1]):'';"
        "function send(i){return fetch("
        + json.dumps(target)
        + ",{method:'POST',credentials:'include',"
        "headers:{'Content-Type':'application/json'},"
        f"body:JSON.stringify({{body:btoa(JSON.stringify({{t:{acc}>>>0,v:{json.dumps(spec['v'])},o:o,i:i}}))}})}})"
        ".then(function(r){return r.json()})}"
    )
    if mode == "passive":
        run = "send(0).then(function(){return send(1)})"
    else:
        run = "send(0).then(function(d){if(d&&d.ok){location.reload()}return d})"
    done = (
        ".then(function(d){window.__akSbsdOk=!!(d&&d.ok)}).catch(function(){window.__akSbsdOk=false})"
        ".then(function(){window.__akSbsdDone=true;"
        "window.dispatchEvent(new CustomEvent('ak:sbsd'))});"
    )
    return head + tail + run + done + "})();\n"


def encode_body(payload: dict[str, Any]) -> str:
    """Lab-defined body encoding: base64 of compact JSON (what the vendor script sends)."""
    return base64.b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode()


def random_path(rng: random.Random) -> str:
    segs = [
        "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(rng.randint(4, 10)))
        for _ in range(rng.randint(3, 5))
    ]
    return "/" + "/".join(segs)


class SbsdChallenge(DetectionModule):
    slug: ClassVar[str] = "sbsd_challenge"
    title: ClassVar[str] = "SBSD dynamic challenge"
    description: ClassVar[str] = (
        "Per-session, per-issuance obfuscated JS computing a value from browser-only state; "
        "the answer must be POSTed back. LOW confidence: the lab flow is a lab device and the "
        "vendor-described flow (flag sbsd_vendor_flow) is unverified."
    )
    category: ClassVar[str] = "js"
    confidence: ClassVar[Confidence] = Confidence.LOW
    challenge_providers: ClassVar[frozenset[str]] = frozenset({"sbsd"})
    flags: ClassVar[list[FlagSpec]] = [
        FlagSpec(
            name="sbsd_vendor_flow",
            description="Vendor-described SBSD flow: random-path script ?v=<UUID>, sbsd_o issued "
            'first, {"body": ...} POSTs (passive: index 0 and 1; blocking: &t=<token>), '
            "bm_s/bm_ss/bm_sc/bm_lso on success. Unverified, vendor-sourced.",
            confidence=Confidence.LOW,
            default=False,
            source="audit §1.2 case 8",
        )
    ]

    def __init__(
        self, rng: random.Random | None = None, clock: Callable[[], float] = time.time
    ) -> None:
        self.rng = rng or random.Random()
        self.clock = clock

    async def evaluate(self, ctx: RequestContext) -> Signal:
        if ctx.session_id and await ctx.store.get(f"sbsd:{ctx.session_id}") == "ok":
            return self.signal(Verdict.PASS, 0, "SBSD challenge solved")
        return self.signal(Verdict.FAIL, 80, "SBSD challenge not solved for this session")

    # -- vendor-described flow (flag sbsd_vendor_flow) --------------------------------------
    async def _path(self, store: Any, sid: str) -> str:
        key = f"sbsd:path:{sid}"
        path = await store.get(key)
        if not path:
            path = random_path(self.rng)
            await store.set(key, path, ttl=3600)
        return str(path)

    def _new_v(self) -> str:
        return str(uuid.UUID(int=self.rng.getrandbits(128), version=4))

    async def page_snippets(self, ctx: RequestContext) -> list[str]:
        if not ctx.flag("sbsd_vendor_flow"):
            return ['<script src="/akam/sbsd_challenge/sbsd.js" defer></script>']
        path = await self._path(ctx.store, ctx.session_id)
        return [f'<script src="{path}?v={self._new_v()}" defer></script>']

    async def _blocking_page(self, store: Any, sid: str) -> Response:
        """Challenge page of the blocking mode: the script URL carries ``&t=<token>``."""
        path = await self._path(store, sid)
        token = f"{self.rng.getrandbits(96):024x}"
        await store.set(f"sbsd:tok:{sid}", token, ttl=SPEC_TTL)
        page = (
            "<!doctype html><html><head><meta charset=utf-8></head><body "
            'style="font-family:system-ui,sans-serif;text-align:center;margin-top:3rem">'
            "<p>Checking your browser&hellip;</p>"
            f'<script src="{path}?v={self._new_v()}&t={token}"></script></body></html>'
        )
        return HTMLResponse(page, headers={"Cache-Control": "no-store"})

    async def issue_challenge(
        self, request: Request, ctx: RequestContext, provider: str, *, html: bool
    ) -> Response | None:
        if provider != "sbsd" or not ctx.flag("sbsd_vendor_flow") or not html:
            return None
        return await self._blocking_page(ctx.store, ctx.session_id)

    async def handle_dynamic(self, request: Request, ctx: RequestContext) -> Response | None:
        if not ctx.flag("sbsd_vendor_flow") or not ctx.session_id:
            return None
        if request.url.path != await ctx.store.get(f"sbsd:path:{ctx.session_id}"):
            return None
        if request.method == "GET":
            return await self._serve_script(request, ctx)
        return await self._receive_body(request, ctx)

    async def _serve_script(self, request: Request, ctx: RequestContext) -> Response:
        store, sid = ctx.store, ctx.session_id
        try:
            v = str(uuid.UUID(request.query_params.get("v", "")))
        except ValueError:
            v = self._new_v()
        token = request.query_params.get("t", "")
        if token and token != await store.get(f"sbsd:tok:{sid}"):
            return JSONResponse({"error": "bad_token"}, status_code=403)
        mode = "blocking" if token else "passive"
        spec = generate_spec(self.rng, v)
        record = {"spec": spec, "mode": mode, "token": token, "next": 0}
        await store.set(f"sbsd:vspec:{sid}", json.dumps(record), ttl=SPEC_TTL)
        # sbsd_o is issued FIRST (with this very response) and consumed by the payload
        sbsd_o = f"{self.rng.getrandbits(96):024x}~{int(self.clock())}"
        await store.set(f"sbsd:o:{sid}", sbsd_o, ttl=SPEC_TTL)
        resp = Response(
            render_vendor_js(spec, request.url.path, mode, token),
            media_type="application/javascript",
            headers={"Cache-Control": "no-store"},
        )
        resp.set_cookie(SBSD_O, sbsd_o, path="/", samesite="lax", max_age=86400)
        return resp

    async def _receive_body(self, request: Request, ctx: RequestContext) -> Response:
        store, sid = ctx.store, ctx.session_id

        async def fail(error: str, status: int = 403) -> Response:
            await store.delete(f"sbsd:vspec:{sid}")  # restart with a new script request
            return JSONResponse({"ok": False, "error": error}, status_code=status)

        try:
            payload = json.loads(base64.b64decode((await request.json())["body"]))
            t, v, o, i = int(payload["t"]), str(payload["v"]), str(payload["o"]), int(payload["i"])
        except (ValueError, KeyError, TypeError):
            return JSONResponse({"ok": False, "error": "bad_request"}, status_code=400)
        raw = await store.get(f"sbsd:vspec:{sid}")
        if raw is None:
            return JSONResponse({"ok": False, "error": "no_challenge"}, status_code=403)
        rec = json.loads(raw)
        spec = rec["spec"]
        if spec["v"] != v:
            return await fail("stale_v")
        issued_o = await store.get(f"sbsd:o:{sid}")
        cookie_o = request.cookies.get(SBSD_O) or request.cookies.get("bm_so", "")
        if not issued_o or o != issued_o or cookie_o != issued_o:
            return await fail("sbsd_o_mismatch")
        if t != expected_answer(spec, request.headers.get("user-agent", "")):
            return await fail("wrong_answer")
        if rec["mode"] == "blocking":
            if request.query_params.get("t") != rec["token"] or i != 0:
                return await fail("bad_token")
        elif i != rec["next"]:
            return await fail("bad_index")
        elif i == 0:  # passive mode: index 0 accepted, index 1 completes
            rec["next"] = 1
            await store.set(f"sbsd:vspec:{sid}", json.dumps(rec), ttl=SPEC_TTL)
            return JSONResponse({"ok": True, "next": 1})
        await store.delete(f"sbsd:vspec:{sid}")
        await store.set(f"sbsd:{sid}", "ok", ttl=3600)
        resp = JSONResponse({"ok": True})
        now = int(self.clock())
        for name, max_age in VENDOR_COOKIES.items():  # names are vendor-only (LOW); values lab-made
            resp.set_cookie(
                name,
                f"{self.rng.getrandbits(96):024x}~{now}",
                path="/",
                samesite="lax",
                max_age=max_age,
            )
        return resp

    def router(self) -> APIRouter:
        r = APIRouter()

        @r.get("/blocking")
        async def blocking(request: Request) -> Response:
            """Blocking-mode challenge page of the vendor flow (flag sbsd_vendor_flow)."""
            sid = request.cookies.get("bm_sz", "")
            flags = await request.app.state.registry.resolved_flags()
            if not sid or not flags.get("sbsd_vendor_flow"):
                return JSONResponse({"error": "unavailable"}, status_code=404)
            return await self._blocking_page(request.app.state.store, sid)

        @r.get("/sbsd.js")
        async def sbsd_js(request: Request, v: str = "") -> Response:
            sid = request.cookies.get("bm_sz", "")
            if not sid:
                return JSONResponse({"error": "no_session"}, status_code=400)
            try:
                v = str(uuid.UUID(v))
            except ValueError:
                v = str(uuid.UUID(int=self.rng.getrandbits(128), version=4))
            spec = generate_spec(self.rng, v)
            # one live issuance per session: a new one invalidates older `v`s
            await request.app.state.store.set(f"sbsd:spec:{sid}", json.dumps(spec), ttl=SPEC_TTL)
            return Response(
                render_js(spec, "/akam/sbsd_challenge/verify"),
                media_type="application/javascript",
                headers={"Cache-Control": "no-store"},
            )

        @r.post("/verify")
        async def verify(request: Request) -> Response:
            sid = request.cookies.get("bm_sz", "")
            try:
                body = await request.json()
                t, v = int(body["t"]), str(body["v"])
            except (ValueError, KeyError, TypeError):
                return JSONResponse({"ok": False, "error": "bad_request"}, status_code=400)
            store = request.app.state.store
            raw = await store.get(f"sbsd:spec:{sid}") if sid else None
            if raw is None:
                return JSONResponse({"ok": False, "error": "no_challenge"}, status_code=403)
            spec = json.loads(raw)
            if spec["v"] != v:
                return JSONResponse({"ok": False, "error": "stale_v"}, status_code=403)
            await store.delete(f"sbsd:spec:{sid}")  # single use
            ua = request.headers.get("user-agent", "")
            if t != expected_answer(spec, ua):
                return JSONResponse({"ok": False, "error": "wrong_answer"}, status_code=403)
            await store.set(f"sbsd:{sid}", "ok", ttl=3600)
            resp = JSONResponse({"ok": True})
            resp.set_cookie(
                "sbsd_o",
                f"{self.rng.getrandbits(96):024x}~{int(self.clock())}",
                path="/",
                samesite="lax",
            )
            return resp

        return r
