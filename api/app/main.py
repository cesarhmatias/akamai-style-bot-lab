"""FastAPI app factory and routes.

Scored routes: ``GET /`` (page), ``GET /protected/<slug|all>`` (protected),
``POST /api/login`` and ``POST /api/checkout`` (transactional), ``/mobile/api/*`` (mobile).
Each one is evaluated by the engine, which decides an action from the Bot Score segment
(``policy.py``); :func:`create_app` enforces it (``enforce``): deny page, challenge
(428 JSON for XHR / interstitial for navigations), delay, slow, tarpit, serve_alternate
(silent degradation with a canary) and safeguard. See ``engine.py`` and ``responses.py``.
"""

from __future__ import annotations

import asyncio
import html
import json
import secrets
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, ValidationError
from sse_starlette.sse import EventSourceResponse

from .contract import (
    Action,
    DetectionModule,
    EndpointClass,
    RequestContext,
    ScoreReport,
    SessionStore,
)
from .engine import Engine, build_context, normalize_reference
from .policy import CHALLENGE_PROVIDERS, DEFAULT_BANDS, HUMAN, SEGMENTS, TELEMETRY_TYPES
from .registry import Registry
from .responses import (
    PRODUCT,
    alt_order,
    alt_product,
    deny_response,
    hidden_canary_html,
    inject_before_body_end,
    merge_json,
    slowed,
    wants_html,
)
from .session import (
    COOKIE_ABCK,
    COOKIE_AK_BMSC,
    COOKIE_BM_SZ,
    abck_cookie_value,
    is_abck_validated,
    new_ak_bmsc,
    new_bm_sz,
)
from .store import make_store


class ToggleBody(BaseModel):
    enabled: bool


class FlagBody(BaseModel):
    value: bool


# Lab-only debug header: look the verdict up via GET /api/requests/{id}.
REPORT_ID_HEADER = "X-Lab-Report-Id"


def _script_tags(urls: Iterable[str]) -> str:
    return "\n".join(f'<script src="{html.escape(u)}" defer></script>' for u in urls)


async def page_markup(
    registry: Registry, ctx: RequestContext, exclude_challenge_providers: bool = False
) -> str:
    """Script tags + per-session HTML fragments of every ENABLED module, for HTML pages.

    ``exclude_challenge_providers`` drops the challenge modules' own markup (used on
    interstitials, which already carry their solver)."""
    parts: list[str] = []
    for m in await registry.enabled_modules():
        if exclude_challenge_providers and m.challenge_providers:
            continue
        parts.append(_script_tags(f"/akam/{m.slug}/{p.lstrip('/')}" for p in m.client_scripts))
        parts.extend(await m.page_snippets(ctx))
    return "\n".join(p for p in parts if p)


def landing_html(markup: str, product: dict[str, Any] | None = None, canary: str = "") -> str:
    p = product or PRODUCT
    hidden = hidden_canary_html(canary) if canary else ""
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Protected Storefront</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{{font-family:system-ui,sans-serif;max-width:720px;margin:3rem auto;padding:0 1rem}}
.card{{border:1px solid #ddd;border-radius:8px;padding:1rem;margin:1rem 0}}</style></head>
<body><h1>Protected Storefront</h1>
<p>Demo shop guarded by the Akamai-style bot-detection lab. Client scripts run silently.</p>
<div class="card"><h2>{html.escape(str(p["name"]))}</h2>
<p>${p["price"]:g} &middot; {p["stock"]} left in stock</p>{hidden}
<button onclick="location.href='/protected/all'">Buy now</button></div>
{markup}
</body></html>"""


def session_id_for(request: Request) -> str:
    """The request's bm_sz, or a freshly minted one (issued by finalize_cookies).

    Minting before evaluation means modules and page snippets always see a session id,
    even on the very first visit."""
    sid = request.cookies.get(COOKIE_BM_SZ, "")
    if not sid:
        sid = getattr(request.state, "new_bm_sz", "") or new_bm_sz()
        request.state.new_bm_sz = sid
    return sid


async def finalize_cookies(request: Request, response: Response, store: SessionStore) -> None:
    """Issue bm_sz/ak_bmsc/_abck when missing; keep _abck in sync with the store."""
    cookies = request.cookies
    sid = session_id_for(request)
    opts: dict[str, Any] = {"path": "/", "samesite": "lax", "httponly": False}
    if COOKIE_BM_SZ not in cookies:
        response.set_cookie(COOKIE_BM_SZ, sid, **opts)
    if COOKIE_AK_BMSC not in cookies:
        response.set_cookie(COOKIE_AK_BMSC, new_ak_bmsc(), **opts)
    validated = await is_abck_validated(store, sid)
    current = cookies.get(COOKIE_ABCK)
    if current is None or (validated and "~0~" not in current):
        response.set_cookie(COOKIE_ABCK, abck_cookie_value(validated), **opts)


def _json_body(ctx: RequestContext) -> dict[str, Any]:
    try:
        data = json.loads(ctx.body or b"{}")
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def create_app(
    store: SessionStore | None = None, modules: Iterable[DetectionModule] | None = None
) -> FastAPI:
    store = store or make_store()
    registry = Registry(store, modules)
    engine = Engine(registry, store)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        close = getattr(store, "close", None)
        if close is not None:
            await close()

    app = FastAPI(title="Akamai-style bot lab", lifespan=lifespan)
    app.state.engine = engine
    app.state.registry = registry
    app.state.store = store
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=[REPORT_ID_HEADER],
    )

    for m in registry.all():
        router = m.router()
        if router is not None:
            app.include_router(router, prefix=f"/akam/{m.slug}")
        root = m.root_router()
        if root is not None:
            app.include_router(root)

    async def context_for(
        request: Request, endpoint_class: EndpointClass = EndpointClass.PROTECTED
    ) -> RequestContext:
        body = await request.body() if request.method in {"POST", "PUT", "PATCH"} else b""
        return build_context(
            request,
            store,
            session_id=session_id_for(request),
            endpoint_class=endpoint_class,
            body=body,
            flags=await registry.resolved_flags(),
        )

    app.state.context_for = context_for

    # ------------------------------------------------------------------ enforcement

    async def gate(request: Request, ctx: RequestContext) -> Response | None:
        """Run the enabled modules' pre_request gates (waiting room)."""
        for m in await registry.enabled_modules():
            resp = await m.pre_request(request, ctx)
            if resp is not None:
                await finalize_cookies(request, resp, store)
                return resp
        return None

    async def challenge_response(
        request: Request, ctx: RequestContext, report: ScoreReport, label: str
    ) -> Response:
        provider = (
            report.challenge_provider or (await engine.policy.get()).params.challenge_provider
        )
        as_html = wants_html(request)
        resp: Response | None = None
        for m in await registry.enabled_modules():
            if provider in m.challenge_providers:
                resp = await m.issue_challenge(request, ctx, provider, html=as_html)
                if resp is not None:
                    break
        if resp is None:  # nothing can issue it: still a 428 so clients see "challenge"
            resp = JSONResponse({"provider": provider, "error": "no_challenge_provider"}, 428)
        if resp.headers.get("content-type", "").startswith("application/json"):
            return merge_json(
                resp,
                {"ok": False, "case": label, "report": report.model_dump(mode="json")},
            )
        if resp.headers.get("content-type", "").startswith("text/html"):
            markup = await page_markup(registry, ctx, exclude_challenge_providers=True)
            return inject_before_body_end(resp, markup)
        return resp

    async def enforce(
        request: Request,
        ctx: RequestContext,
        report: ScoreReport,
        label: str,
        kind: str,
        info: dict[str, Any] | None = None,
    ) -> Response:
        """Turn the engine's decision into an HTTP response.

        ``kind``: landing | protected | login | checkout | mobile. ``info`` carries
        request-derived values (username, order items, mobile path)."""
        info = info or {}
        params = (await engine.policy.get()).params
        action = report.action
        as_html = wants_html(request)
        report_json = report.model_dump(mode="json")

        def real() -> Response:
            if kind == "landing":
                return HTMLResponse(info["html"])
            body: dict[str, Any] = {"ok": True, "case": label, "report": report_json}
            body.update(real_data(kind, info))
            return JSONResponse(body)

        resp: Response
        if action == Action.DENY:
            if as_html:
                resp = deny_response(
                    request, report.reference, ghost=ctx.flag("akamai_ghost_server_header")
                )
            else:
                resp = JSONResponse(
                    {
                        "ok": False,
                        "case": label,
                        "reference": report.reference,
                        "report": report_json,
                    },
                    status_code=403,
                )
                if ctx.flag("akamai_ghost_server_header"):
                    resp.headers["Server"] = "AkamaiGHost"
        elif action == Action.CHALLENGE:
            resp = await challenge_response(request, ctx, report, label)
        elif action == Action.TARPIT:
            await asyncio.sleep(params.tarpit_seconds)
            resp = Response(status_code=403)  # minimal response after the hold
        elif action == Action.SERVE_ALTERNATE:
            resp = alternate_response(kind, label, report.canary, info, as_html)
        else:
            if action == Action.DELAY:
                await asyncio.sleep(params.delay_seconds)
            resp = real()
            if action == Action.SLOW:
                resp = slowed(resp, params.slow_seconds, params.slow_chunks)
        resp.headers[REPORT_ID_HEADER] = report.id
        await finalize_cookies(request, resp, store)
        return resp

    def real_data(kind: str, info: dict[str, Any]) -> dict[str, Any]:
        if kind == "login":
            return {"user": info.get("user", "")}
        if kind == "checkout":
            return {"order": info["order"]}
        if kind == "mobile":
            return {"path": info.get("path", ""), "data": {"product": PRODUCT}}
        return {"data": {"product": PRODUCT}}

    def alternate_response(
        kind: str, label: str, canary: str, info: dict[str, Any], as_html: bool
    ) -> Response:
        """Silent degradation: HTTP 200, subtly wrong data, canary, no report in the body."""
        if kind == "landing":
            return HTMLResponse(landing_html(info.get("markup", ""), alt_product(canary), canary))
        if as_html and kind == "protected":
            p = alt_product(canary)
            return HTMLResponse(
                f"<!doctype html><html><head><meta charset=utf-8><title>{p['name']}</title></head>"
                f"<body><h1>{html.escape(str(p['name']))}</h1>"
                f"<p>${p['price']:g} &middot; {p['stock']} left in stock</p>"
                f"{hidden_canary_html(canary)}</body></html>"
            )
        body: dict[str, Any] = {"ok": True, "case": label}
        if kind == "login":
            body["user"] = info.get("user", "")
            body["token"] = canary
        elif kind == "checkout":
            body["order"] = alt_order(info["order"], canary)
        else:
            body["data"] = {"product": alt_product(canary)}
            if kind == "mobile":
                body["path"] = info.get("path", "")
        return JSONResponse(body)

    async def run(
        request: Request,
        endpoint_class: EndpointClass,
        label: str,
        kind: str,
        slug: str | None = None,
        info: dict[str, Any] | None = None,
        ctx: RequestContext | None = None,
    ) -> Response:
        ctx = ctx or await context_for(request, endpoint_class)
        report = await engine.evaluate(
            ctx, slug=slug, client_label=request.headers.get("x-lab-client", "")
        )
        return await enforce(request, ctx, report, label, kind, info)

    # ------------------------------------------------------------------ scored routes

    @app.get("/protected/all")
    async def protected_all(request: Request) -> Response:
        ctx = await context_for(request, EndpointClass.PROTECTED)
        if (gated := await gate(request, ctx)) is not None:
            return gated
        return await run(request, EndpointClass.PROTECTED, "all", "protected", None, ctx=ctx)

    @app.get("/protected/{slug}")
    async def protected_one(slug: str, request: Request) -> Response:
        if registry.get(slug) is None:
            raise HTTPException(404, f"unknown case {slug}")
        ctx = await context_for(request, EndpointClass.PROTECTED)
        if (gated := await gate(request, ctx)) is not None:
            return gated
        return await run(request, EndpointClass.PROTECTED, slug, "protected", slug, ctx=ctx)

    @app.get("/", response_class=HTMLResponse)
    async def landing(request: Request) -> Response:
        ctx = await context_for(request, EndpointClass.PAGE)
        if (gated := await gate(request, ctx)) is not None:
            return gated
        markup = await page_markup(registry, ctx)
        info = {"markup": markup, "html": landing_html(markup)}
        return await run(request, EndpointClass.PAGE, "page", "landing", None, info, ctx)

    @app.post("/api/login")
    async def login(request: Request) -> Response:
        ctx = await context_for(request, EndpointClass.TRANSACTIONAL)
        user = _json_body(ctx).get("username")
        if not isinstance(user, str) or not user:
            raise HTTPException(400, "JSON body with a non-empty 'username' is required")
        return await run(
            request, EndpointClass.TRANSACTIONAL, "login", "login", None, {"user": user}, ctx
        )

    @app.post("/api/checkout")
    async def checkout(request: Request) -> Response:
        ctx = await context_for(request, EndpointClass.TRANSACTIONAL)
        body = _json_body(ctx)
        qty = body.get("qty", 1)
        qty = qty if isinstance(qty, int) and 1 <= qty <= 10 else 1
        order = {
            "order_id": f"ord-{secrets.token_hex(4)}",
            "items": [{"sku": PRODUCT["sku"], "qty": qty, "price": PRODUCT["price"]}],
            "total": round(PRODUCT["price"] * qty, 2),
            "currency": PRODUCT["currency"],
        }
        return await run(
            request,
            EndpointClass.TRANSACTIONAL,
            "checkout",
            "checkout",
            None,
            {"order": order},
            ctx,
        )

    @app.api_route("/mobile/api/{path:path}", methods=["GET", "POST"])
    async def mobile(path: str, request: Request) -> Response:
        return await run(
            request, EndpointClass.MOBILE, "mobile", "mobile", None, {"path": "/" + path}
        )

    # ------------------------------------------------------------------ control plane

    @app.get("/api/modules")
    async def list_modules() -> list[dict[str, Any]]:
        out = []
        for m in registry.all():
            sig = engine.last_signal(m.slug)
            out.append(
                {
                    "slug": m.slug,
                    "title": m.title,
                    "description": m.description,
                    "category": m.category,
                    "enabled": await registry.is_enabled(m.slug),
                    "confidence": str(m.confidence),
                    "applies_to": sorted(str(c) for c in m.applies_to),
                    "flags": [f.name for f in m.flags],
                    "challenge_providers": sorted(m.challenge_providers),
                    "last_verdict": sig.model_dump(mode="json") if sig else None,
                }
            )
        return out

    @app.put("/api/modules/{slug}")
    async def toggle_module(slug: str, body: ToggleBody) -> dict[str, Any]:
        if registry.get(slug) is None:
            raise HTTPException(404, f"unknown module {slug}")
        await registry.set_enabled(slug, body.enabled)
        return {"slug": slug, "enabled": body.enabled}

    @app.get("/api/policy")
    async def get_policy() -> dict[str, Any]:
        doc = (await engine.policy.get()).model_dump(mode="json")
        doc["defaults"] = {"bands": DEFAULT_BANDS}
        doc["choices"] = {
            "segments": [HUMAN, *SEGMENTS],
            "telemetry_types": list(TELEMETRY_TYPES),
            "endpoint_classes": [str(c) for c in EndpointClass],
            "actions": [str(a) for a in Action],
            "challenge_providers": list(CHALLENGE_PROVIDERS),
        }
        return doc

    @app.put("/api/policy")
    async def put_policy(patch: dict[str, Any]) -> dict[str, Any]:
        """Deep-merge a (partial) policy document; 422 when the result is invalid."""
        patch = {k: v for k, v in patch.items() if k in {"bands", "actions", "params"}}
        try:
            policy = await engine.policy.update(patch)
        except ValidationError as exc:
            raise HTTPException(422, jsonable_encoder(exc.errors(include_url=False))) from exc
        return policy.model_dump(mode="json")

    @app.delete("/api/policy")
    async def reset_policy() -> dict[str, Any]:
        return (await engine.policy.reset()).model_dump(mode="json")

    @app.get("/api/requests")
    async def requests_(
        limit: int = 100, reference: str | None = None, canary: str | None = None
    ) -> list[dict[str, Any]]:
        items = engine.recent(max(limit, 0) if not (reference or canary) else 500)
        if reference:
            ref = normalize_reference(reference)
            items = [r for r in items if r.reference == ref]
        if canary:
            items = [r for r in items if r.canary == canary]
        return [r.model_dump(mode="json") for r in items[:limit]]

    @app.get("/api/requests/{report_id}")
    async def request_by_id(report_id: str) -> dict[str, Any]:
        rep = engine.get(report_id)
        if rep is None:
            raise HTTPException(404, f"unknown report {report_id}")
        return rep.model_dump(mode="json")

    @app.get("/api/reference/{reference:path}")
    async def by_reference(reference: str) -> dict[str, Any]:
        """Look a deny-page reference ("Reference #18.xxxx.ts.xxxx") up in the report ring."""
        rep = engine.by_reference(reference)
        if rep is None:
            raise HTTPException(404, f"unknown reference {reference}")
        return rep.model_dump(mode="json")

    @app.get("/api/canary/{token}")
    async def by_canary(token: str) -> dict[str, Any]:
        """Which serve_alternate response carried this canary (lab-only lookup)."""
        report_id = await store.get(f"canary:{token}")
        rep = engine.get(report_id) if report_id else None
        if rep is None:
            raise HTTPException(404, f"unknown canary {token}")
        return rep.model_dump(mode="json")

    @app.get("/api/flags")
    async def list_flags() -> list[dict[str, Any]]:
        values = await registry.resolved_flags()
        return [
            {**spec.model_dump(mode="json"), "value": values[name]}
            for name, spec in sorted(registry.flag_specs().items())
        ]

    @app.put("/api/flags/{name}")
    async def set_flag(name: str, body: FlagBody) -> dict[str, Any]:
        if name not in registry.flag_specs():
            raise HTTPException(404, f"unknown flag {name}")
        await registry.set_flag(name, body.value)
        return {"name": name, "value": body.value}

    @app.get("/api/feed")
    async def feed(request: Request) -> EventSourceResponse:
        q = engine.subscribe()

        async def gen() -> AsyncIterator[dict[str, str]]:
            try:
                while not await request.is_disconnected():
                    try:
                        rep = await asyncio.wait_for(q.get(), timeout=15)
                    except TimeoutError:
                        continue
                    yield {"event": "report", "data": json.dumps(rep.model_dump(mode="json"))}
            finally:
                engine.unsubscribe(q)

        return EventSourceResponse(gen(), ping=15)

    @app.post("/api/reset")
    async def reset() -> dict[str, bool]:
        await engine.reset()
        return {"ok": True}

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    # Must stay LAST: same-origin paths no route claimed (per-session random script
    # paths and the like) are offered to each module's handle_dynamic() hook.
    @app.api_route("/{path:path}", methods=["GET", "POST"], include_in_schema=False)
    async def dynamic(path: str, request: Request) -> Response:
        ctx = await context_for(request, EndpointClass.PAGE)
        for m in await registry.enabled_modules():
            resp = await m.handle_dynamic(request, ctx)
            if resp is not None:
                await finalize_cookies(request, resp, store)
                return resp
        raise HTTPException(404, "not found")

    return app


def _default_app() -> FastAPI:
    return create_app()


app = _default_app()
