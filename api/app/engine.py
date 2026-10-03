"""Scoring engine: builds contexts, runs modules, aggregates, keeps the feed.

Aggregation: ``score = min(100, round(max(scores) + 0.25 * sum(other scores)))``.
The strongest signal dominates, the rest add diminishing weight. A request is blocked
when ``score >= BLOCK_THRESHOLD`` or any signal verdict is BLOCK.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import uuid
from collections import deque

from fastapi import Request

from .contract import (
    BLOCK_THRESHOLD,
    EDGE_HEADERS,
    H_CLIENT_IP,
    H_H2,
    H_HEADER_ORDER,
    H_JA3,
    H_JA3_HASH,
    H_JA4,
    H_PROTO,
    DetectionModule,
    EndpointClass,
    RequestContext,
    ScoreReport,
    SessionStore,
    Signal,
    Verdict,
)
from .registry import Registry

log = logging.getLogger(__name__)
RING_SIZE = 500


def aggregate(signals: list[Signal]) -> tuple[int, bool]:
    scores = sorted((s.score for s in signals), reverse=True)
    if not scores:
        return 0, False
    score = min(100, round(scores[0] + 0.25 * sum(scores[1:])))
    blocked = score >= BLOCK_THRESHOLD or any(s.verdict == Verdict.BLOCK for s in signals)
    return score, blocked


def build_context(
    request: Request,
    store: SessionStore,
    *,
    session_id: str | None = None,
    endpoint_class: EndpointClass = EndpointClass.PROTECTED,
    body: bytes = b"",
    flags: dict[str, bool] | None = None,
) -> RequestContext:
    scope_headers = [
        (k.decode("latin-1"), v.decode("latin-1")) for k, v in request.scope["headers"]
    ]
    lowered = [(k.lower(), v) for k, v in scope_headers]
    hmap = {k: v for k, v in lowered}  # last wins; edge headers are single-valued
    if hmap.get(H_HEADER_ORDER):
        order = [h for h in hmap[H_HEADER_ORDER].split(",") if h]
    else:
        order = [k for k, _ in scope_headers if k.lower() not in EDGE_HEADERS]
    peer = request.client.host if request.client else ""
    return RequestContext(
        method=request.method,
        path=request.url.path,
        client_ip=hmap.get(H_CLIENT_IP) or peer,
        headers=[(k, v) for k, v in lowered if k not in EDGE_HEADERS],
        header_order=order,
        cookies=dict(request.cookies),
        user_agent=hmap.get("user-agent", ""),
        ja3=hmap.get(H_JA3, ""),
        ja3_hash=hmap.get(H_JA3_HASH, ""),
        ja4=hmap.get(H_JA4, ""),
        h2_fingerprint=hmap.get(H_H2, ""),
        http_proto=hmap.get(H_PROTO) or "http/1.1",
        session_id=session_id if session_id is not None else request.cookies.get("bm_sz", ""),
        store=store,
        endpoint_class=endpoint_class,
        body_sha256=hashlib.sha256(body).hexdigest() if body else "",
        query=dict(request.query_params),
        flags=flags or {},
    )


class Engine:
    def __init__(self, registry: Registry, store: SessionStore) -> None:
        self.registry = registry
        self.store = store
        self.reports: deque[ScoreReport] = deque(maxlen=RING_SIZE)
        self.subscribers: set[asyncio.Queue[ScoreReport]] = set()

    async def _run(self, module: DetectionModule, ctx: RequestContext) -> Signal:
        try:
            sig = await module.evaluate(ctx)
            if sig.confidence is None:
                sig.confidence = module.confidence
            return sig
        except Exception as exc:
            log.exception("module %s failed", module.slug)
            return Signal(
                module=module.slug,
                verdict=Verdict.WARN,
                score=10,
                reason=f"module error: {type(exc).__name__}: {exc}",
                details={"error": True},
            )

    async def evaluate(
        self, ctx: RequestContext, slug: str | None = None, client_label: str = ""
    ) -> ScoreReport:
        """Run one module (`slug`, if enabled) or all enabled modules; record the report."""
        if slug is not None:
            m = self.registry.get(slug)
            selected = [m] if m and await self.registry.is_enabled(slug) else []
        else:
            selected = [
                m
                for m in await self.registry.enabled_modules()
                if ctx.endpoint_class in m.applies_to
            ]
        signals = list(await asyncio.gather(*(self._run(m, ctx) for m in selected)))
        score, blocked = aggregate(signals)
        report = ScoreReport(
            id=uuid.uuid4().hex[:12],
            method=ctx.method,
            path=ctx.path,
            client_ip=ctx.client_ip,
            user_agent=ctx.user_agent,
            score=score,
            blocked=blocked,
            signals=signals,
            fingerprint={
                "ja3": ctx.ja3,
                "ja3_hash": ctx.ja3_hash,
                "ja4": ctx.ja4,
                "h2": ctx.h2_fingerprint,
                "header_order": ",".join(ctx.header_order),
                "proto": ctx.http_proto,
            },
            headers=ctx.headers,
            cookies=ctx.cookies,
            client_label=client_label,
            endpoint_class=ctx.endpoint_class,
        )
        self.record(report)
        return report

    def record(self, report: ScoreReport) -> None:
        self.reports.append(report)
        for q in list(self.subscribers):
            q.put_nowait(report)

    def recent(self, limit: int = 100) -> list[ScoreReport]:
        items = list(self.reports)[-limit:] if limit > 0 else []
        return list(reversed(items))  # newest first

    def get(self, report_id: str) -> ScoreReport | None:
        for rep in reversed(self.reports):
            if rep.id == report_id:
                return rep
        return None

    def last_signal(self, slug: str) -> Signal | None:
        for rep in reversed(self.reports):
            for s in rep.signals:
                if s.module == slug:
                    return s
        return None

    def subscribe(self) -> asyncio.Queue[ScoreReport]:
        q: asyncio.Queue[ScoreReport] = asyncio.Queue()
        self.subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue[ScoreReport]) -> None:
        self.subscribers.discard(q)

    async def reset(self) -> None:
        """Clear the ring buffer and store state (module toggles are preserved)."""
        toggles = {m.slug: await self.registry.is_enabled(m.slug) for m in self.registry.all()}
        clear = getattr(self.store, "clear", None)
        if clear is not None:
            await clear()
        for slug, enabled in toggles.items():
            await self.registry.set_enabled(slug, enabled)
        self.reports.clear()
