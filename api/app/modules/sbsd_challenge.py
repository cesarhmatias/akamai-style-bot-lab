"""SBSD-style dynamic challenge: per-issuance randomized JS computing a browser-derived value.

The generated script mixes values only a DOM-like JS environment yields
(``document.title`` length, ``navigator.userAgent`` length / char codes, a value
round-tripped through a DOM element) through a random sequence of 32-bit
arithmetic/bitwise ops. The server replays the same op list in Python.

Limitation (by design, documented): a determined client can port the generated
JS to Python or run it in a minimal JS engine; the point is that nothing is
replayable between sessions/issuances and a plain HTTP client cannot get the
answer without interpreting the code.
"""

from __future__ import annotations

import json
import random
import string
import time
import uuid
from collections.abc import Callable
from typing import Any, ClassVar

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from app.contract import DetectionModule, RequestContext, Signal, Verdict

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


class SbsdChallenge(DetectionModule):
    slug: ClassVar[str] = "sbsd_challenge"
    title: ClassVar[str] = "SBSD dynamic challenge"
    description: ClassVar[str] = (
        "Per-session, per-issuance obfuscated JS computing a value from browser-only "
        "state; the answer must be POSTed back. Needs a JS/DOM environment."
    )
    category: ClassVar[str] = "js"
    client_scripts: ClassVar[list[str]] = ["sbsd.js"]

    def __init__(
        self, rng: random.Random | None = None, clock: Callable[[], float] = time.time
    ) -> None:
        self.rng = rng or random.Random()
        self.clock = clock

    async def evaluate(self, ctx: RequestContext) -> Signal:
        if ctx.session_id and await ctx.store.get(f"sbsd:{ctx.session_id}") == "ok":
            return self.signal(Verdict.PASS, 0, "SBSD challenge solved")
        return self.signal(Verdict.FAIL, 80, "SBSD challenge not solved for this session")

    def router(self) -> APIRouter:
        r = APIRouter()

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
