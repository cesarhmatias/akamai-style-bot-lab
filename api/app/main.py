"""FastAPI app factory and routes."""

from __future__ import annotations

import asyncio
import html
import json
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from .contract import DetectionModule, SessionStore
from .engine import Engine, build_context
from .registry import Registry
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


def client_script_urls(registry: Registry) -> list[str]:
    urls: list[str] = []
    for m in registry.all():
        for path in getattr(m, "client_scripts", None) or []:
            urls.append(f"/akam/{m.slug}/{path.lstrip('/')}")
    return urls


def _script_tags(urls: Iterable[str]) -> str:
    return "\n".join(f'<script src="{html.escape(u)}" defer></script>' for u in urls)


def landing_html(urls: list[str]) -> str:
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Protected Storefront</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{{font-family:system-ui,sans-serif;max-width:720px;margin:3rem auto;padding:0 1rem}}
.card{{border:1px solid #ddd;border-radius:8px;padding:1rem;margin:1rem 0}}</style></head>
<body><h1>Protected Storefront</h1>
<p>Demo shop guarded by the Akamai-style bot-detection lab. Client scripts run silently.</p>
<div class="card"><h2>Limited sneaker drop</h2><p>$199 &middot; 3 left in stock</p>
<button onclick="location.href='/protected/all'">Buy now</button></div>
{_script_tags(urls)}
</body></html>"""


def interstitial_html(urls: list[str]) -> str:
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Checking your browser</title></head>
<body style="font-family:system-ui,sans-serif;text-align:center;margin-top:4rem">
<h1>Checking your browser&hellip;</h1><p>Access denied until the challenge completes.</p>
{_script_tags(urls)}
<script>
(function(){{var n=+(sessionStorage.getItem('lab_retry')||0);
if(n<3){{sessionStorage.setItem('lab_retry',n+1);setTimeout(function(){{location.reload()}},4000)}}}})();
</script></body></html>"""


async def finalize_cookies(request: Request, response: Response, store: SessionStore) -> None:
    """Issue bm_sz/ak_bmsc/_abck when missing; keep _abck in sync with the store."""
    cookies = request.cookies
    sid = cookies.get(COOKIE_BM_SZ, "")
    opts: dict[str, Any] = {"path": "/", "samesite": "lax", "httponly": False}
    if not sid:
        sid = new_bm_sz()
        response.set_cookie(COOKIE_BM_SZ, sid, **opts)
    if COOKIE_AK_BMSC not in cookies:
        response.set_cookie(COOKIE_AK_BMSC, new_ak_bmsc(), **opts)
    validated = await is_abck_validated(store, sid)
    current = cookies.get(COOKIE_ABCK)
    if current is None or (validated and "~0~" not in current):
        response.set_cookie(COOKIE_ABCK, abck_cookie_value(validated), **opts)


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
        CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
    )

    for m in registry.all():
        router = m.router()
        if router is not None:
            app.include_router(router, prefix=f"/akam/{m.slug}")

    async def scored(request: Request, slug: str | None) -> Response:
        ctx = build_context(request, store)
        report = await engine.evaluate(
            ctx, slug=slug, client_label=request.headers.get("x-lab-client", "")
        )
        label = slug or "all"
        resp: Response
        if report.blocked and "text/html" in request.headers.get("accept", ""):
            resp = HTMLResponse(interstitial_html(client_script_urls(registry)), status_code=403)
        else:
            resp = JSONResponse(
                {"ok": not report.blocked, "case": label, "report": report.model_dump(mode="json")},
                status_code=403 if report.blocked else 200,
            )
        await finalize_cookies(request, resp, store)
        return resp

    @app.get("/protected/all")
    async def protected_all(request: Request) -> Response:
        return await scored(request, None)

    @app.get("/protected/{slug}")
    async def protected_one(slug: str, request: Request) -> Response:
        if registry.get(slug) is None:
            raise HTTPException(404, f"unknown case {slug}")
        return await scored(request, slug)

    @app.get("/", response_class=HTMLResponse)
    async def landing(request: Request) -> Response:
        ctx = build_context(request, store)
        await engine.evaluate(ctx, slug=None, client_label=request.headers.get("x-lab-client", ""))
        resp = HTMLResponse(landing_html(client_script_urls(registry)))
        await finalize_cookies(request, resp, store)
        return resp

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

    @app.get("/api/requests")
    async def requests_(limit: int = 100) -> list[dict[str, Any]]:
        return [r.model_dump(mode="json") for r in engine.recent(limit)]

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

    return app


def _default_app() -> FastAPI:
    return create_app()


app = _default_app()
