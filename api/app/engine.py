"""Scoring engine: builds contexts, runs modules, aggregates, decides the response action.

Aggregation (unchanged since v1, audit §2.1 only asks for one 0-100 score):
``score = min(100, round(max(scores) + 0.25 * sum(other scores)))``. The strongest signal
dominates, the rest add diminishing weight. ``aggregate()`` still reports the legacy
``score >= BLOCK_THRESHOLD or any BLOCK`` flag, but the engine no longer uses it to block:

1. the score is bucketed into a response segment per telemetry type (``policy.py``);
2. the policy maps (endpoint class, segment) to an :class:`Action`;
3. a BLOCK verdict forces ``deny``; a ``challenge`` is downgraded to monitor when the
   session already solved one (``challenge_satisfied``) and to ``safeguard`` after K failed
   challenges; ``serve_alternate`` gets a canary token; ``deny`` gets an Akamai-style
   reference number;
4. ``ScoreReport.blocked`` is true iff the action is deny, tarpit or challenge.

The engine only DECIDES; ``main.py`` enforces (sleeps, challenge pages, deny page, alt data).
Origin verdict headers (audit §2.9, tier MEDIUM) are computed here: the lab has no real
origin behind the API, so they are only recorded in ``ScoreReport.origin_headers``.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import secrets
import time
import uuid
from collections import deque
from typing import Any

from fastapi import Request

from .contract import (
    BLOCK_THRESHOLD,
    BLOCKING_ACTIONS,
    DETAIL_BOT_CATEGORY,
    DETAIL_BOT_NAME,
    DETAIL_LAYERS,
    DETAIL_TELEMETRY_TYPE,
    DETAIL_USER_RISK,
    EDGE_HEADERS,
    H_CLIENT_IP,
    H_H2,
    H_HEADER_ORDER,
    H_JA3,
    H_JA3_HASH,
    H_JA4,
    H_PROTO,
    Action,
    DetectionModule,
    EndpointClass,
    RequestContext,
    ScoreReport,
    SessionStore,
    Signal,
    Verdict,
)
from .policy import POLICY_KEY, TELEMETRY_TYPES, PolicyStore, decide_challenge
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


MAX_BODY = 64 * 1024
JA4_HEADER = "ja4-fingerprint"  # example header name from Akamai's JA4 settings API (report §2.9)


def telemetry_type_for(ctx: RequestContext, signals: list[Signal]) -> str:
    """Telemetry type: a signal's ``details["telemetry_type"]`` (inline_telemetry says
    "inline"), else ``native`` for the mobile class, else ``standard``."""
    for s in signals:
        t = s.details.get(DETAIL_TELEMETRY_TYPE)
        if t in TELEMETRY_TYPES and t != "standard":
            return str(t)
    if ctx.endpoint_class == EndpointClass.MOBILE:
        return "native"
    return "standard"


def new_reference() -> str:
    """``18.<8 hex>.<unix ts>.<7 hex>``, the shape of Akamai error references (report §2.13)."""
    return f"18.{secrets.token_hex(4)}.{int(time.time())}.{secrets.token_hex(4)[:7]}"


def normalize_reference(ref: str) -> str:
    ref = ref.strip()
    for prefix in ("Reference", "reference"):
        ref = ref.removeprefix(prefix).strip()
    return ref.lstrip("#").strip()


def format_akamai_bot(signals: list[Signal], segment: str, action: Action) -> str:
    """``Akamai-Bot`` origin header (audit §2.9, tier MEDIUM).

    Real observed value: ``Akamai-Categorized Bot (amazonbot):monitor:Web Search Engine Bots``.
    That form is produced only when a ``known_bots`` signal classified the client. The
    unclassified and human forms are LAB-DEFINED (no public example of them exists)."""
    for s in signals:
        name = s.details.get(DETAIL_BOT_NAME)
        if name:
            cat = s.details.get(DETAIL_BOT_CATEGORY) or "Unknown Bots"
            return f"Akamai-Categorized Bot ({name}):{action.value}:{cat}"
    if segment == "human":
        return f"Akamai-Likely Human (lab-defined):{action.value}"
    return f"Akamai-Unclassified Bot (lab-defined):{action.value}:{segment}"


def format_user_risk(risk: dict[str, Any], request_id: str, action: Action) -> str:
    """``Akamai-User-Risk`` origin header (audit §2.9/§2.10, tier MEDIUM).

    Field order from the integrator doc cited in the report:
    ``uuid=…;requestid=…;status=…;score=…;general=…;risk=…;trust=…;allow=…;action=…``.
    The content of each field is lab-defined by ``account_protector``."""

    def join(v: Any) -> str:
        return "|".join(str(x) for x in v) if isinstance(v, list | tuple) else str(v or "")

    return (
        f"uuid={risk.get('uuid', '')};requestid={request_id};status={risk.get('status', 0)};"
        f"score={risk.get('score', 0)};general={join(risk.get('general'))};"
        f"risk={join(risk.get('risk'))};trust={join(risk.get('trust'))};"
        f"allow={risk.get('allow', 0)};action={action.value}"
    )


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
        body=body[:MAX_BODY],
        query=dict(request.query_params),
        flags=flags or {},
    )


class Engine:
    def __init__(self, registry: Registry, store: SessionStore) -> None:
        self.registry = registry
        self.store = store
        self.policy = PolicyStore(store)
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
        score, _legacy_blocked = aggregate(signals)
        forced_deny = any(s.verdict == Verdict.BLOCK for s in signals)

        policy = await self.policy.get()
        telemetry = telemetry_type_for(ctx, signals)
        segment = policy.segment_for(score, telemetry)
        action = policy.action_for(ctx.endpoint_class, segment)
        if forced_deny:
            action = Action.DENY
        provider = ""
        safeguard = False
        if action == Action.CHALLENGE:
            provider = policy.params.challenge_provider
            if await self._challenge_satisfied(ctx, provider):
                action = Action.MONITOR  # already proved itself inside the challenge interval
                provider = ""
            else:
                action, safeguard = await decide_challenge(
                    self.store, ctx.session_id, policy.params
                )
                if safeguard:
                    provider = ""

        report = ScoreReport(
            id=uuid.uuid4().hex[:12],
            method=ctx.method,
            path=ctx.path,
            client_ip=ctx.client_ip,
            user_agent=ctx.user_agent,
            score=score,
            blocked=action in BLOCKING_ACTIONS,
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
            telemetry_type=telemetry,
            segment=segment,
            action=action,
            is_human=score == 0,
            is_safeguard=safeguard,
            challenge_provider=provider,
        )
        for s in signals:
            layers = s.details.get(DETAIL_LAYERS)
            if isinstance(layers, dict):
                report.layers = layers
                break
        if action == Action.DENY:
            report.reference = new_reference()
        elif action == Action.SERVE_ALTERNATE:
            report.canary = f"cnry-{secrets.token_hex(6)}"
            await self.store.set(f"canary:{report.canary}", report.id, ttl=86400)
        report.origin_headers = self._origin_headers(ctx, report)
        self.record(report)
        await self._notify(ctx, report)
        return report

    async def _challenge_satisfied(self, ctx: RequestContext, provider: str) -> bool:
        for m in await self.registry.enabled_modules():
            if not m.challenge_providers:
                continue
            try:
                if await m.challenge_satisfied(ctx, provider):
                    return True
            except Exception:
                log.exception("challenge_satisfied failed for %s", m.slug)
        return False

    async def _notify(self, ctx: RequestContext, report: ScoreReport) -> None:
        for m in await self.registry.enabled_modules():
            try:
                await m.after_score(ctx, report)
            except Exception:
                log.exception("after_score failed for %s", m.slug)

    @staticmethod
    def _origin_headers(ctx: RequestContext, report: ScoreReport) -> dict[str, str]:
        """Verdict headers an origin would receive (audit §2.9, tier MEDIUM)."""
        headers = {"Akamai-Bot": format_akamai_bot(report.signals, report.segment, report.action)}
        for s in report.signals:
            risk = s.details.get(DETAIL_USER_RISK)
            if isinstance(risk, dict):
                headers["Akamai-User-Risk"] = format_user_risk(risk, report.id, report.action)
                break
        if ctx.ja4:
            headers[JA4_HEADER] = ctx.ja4
        return headers

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

    def by_reference(self, reference: str) -> ScoreReport | None:
        ref = normalize_reference(reference)
        for rep in reversed(self.reports):
            if rep.reference and rep.reference == ref:
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
        """Clear the ring buffer and store state: sessions, challenges, penalty boxes, profiles.
        Module toggles, feature flags and the response policy are preserved."""
        toggles = {m.slug: await self.registry.is_enabled(m.slug) for m in self.registry.all()}
        flags = {n: await self.store.get(f"flag:{n}") for n in self.registry.flag_specs()}
        policy_raw = await self.store.get(POLICY_KEY)
        clear = getattr(self.store, "clear", None)
        if clear is not None:
            await clear()
        for slug, enabled in toggles.items():
            await self.registry.set_enabled(slug, enabled)
        for name, raw in flags.items():
            if raw is not None:
                await self.store.set(f"flag:{name}", raw)
        if policy_raw is not None:
            await self.store.set(POLICY_KEY, policy_raw)
        self.reports.clear()
