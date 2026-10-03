"""Shared contract between the scoring engine and every detection module.

Every detection "case" is a subclass of :class:`DetectionModule`. Modules are
independent: they receive a :class:`RequestContext` (built once per request
from the edge-proxy headers, cookies and session state) and return a
:class:`Signal`. The scoring engine aggregates the signals of all *enabled*
modules into a :class:`ScoreReport`.

Score semantics: 0 = certainly human, 100 = certainly bot. A request is
blocked when the final score is >= ``BLOCK_THRESHOLD`` or when any signal has
``verdict == Verdict.BLOCK``.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from enum import StrEnum
from typing import Any, ClassVar, Protocol

from pydantic import BaseModel, Field

BLOCK_THRESHOLD = 50

# Edge-proxy injected headers (see edge/README.md).
H_JA3 = "x-ja3"  # full JA3 string
H_JA3_HASH = "x-ja3-hash"  # md5 of JA3 string
H_JA4 = "x-ja4"
H_H2 = "x-h2-fingerprint"  # Akamai format S[..]|WU[..]|P[..]|PS[..]; empty for HTTP/1.1
H_HEADER_ORDER = "x-header-order"  # comma-separated header names, original casing, wire order
H_CLIENT_IP = "x-client-ip"
H_PROTO = "x-http-proto"  # "h2" or "http/1.1"
EDGE_HEADERS = frozenset(
    {H_JA3, H_JA3_HASH, H_JA4, H_H2, H_HEADER_ORDER, H_CLIENT_IP, H_PROTO}
)


class Verdict(StrEnum):
    PASS = "pass"  # signal is consistent with a real browser
    WARN = "warn"  # suspicious, adds score but does not block alone
    FAIL = "fail"  # strongly bot-like; adds score
    BLOCK = "block"  # hard block regardless of total score
    SKIP = "skip"  # not applicable to this request (contributes 0)


class Confidence(StrEnum):
    """How well a simulated behaviour is backed by public sources (audit report §3.1).

    HIGH   -> implemented as real lab behaviour.
    MEDIUM -> implemented, documented as an approximation.
    LOW    -> vendor-sourced / unverified; only active behind a feature flag (default off).
    LAB    -> lab-only teaching device with no known Akamai analogue.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    LAB = "lab"


class EndpointClass(StrEnum):
    """What kind of resource a scored request targets (drives thresholds and module scope)."""

    PAGE = "page"  # HTML navigations, e.g. GET /
    PROTECTED = "protected"  # GET /protected/<slug> demo resources
    TRANSACTIONAL = "transactional"  # POST /api/login, /api/checkout (inline telemetry)
    MOBILE = "mobile"  # /mobile/api/* (native-app telemetry)


class Action(StrEnum):
    """Response actions a Bot Score segment can map to (audit §2.1)."""

    MONITOR = "monitor"
    ALLOW = "allow"
    DENY = "deny"
    DELAY = "delay"
    SLOW = "slow"
    TARPIT = "tarpit"
    SERVE_ALTERNATE = "serve_alternate"
    CHALLENGE = "challenge"
    SAFEGUARD = "safeguard"


# Actions that mean the client did NOT receive the real resource ("blocked" in reports):
# a deny page, a tarpit-held minimal response, or a challenge. Delay, slow, serve_alternate,
# safeguard, monitor and allow all hand the client a normal 2xx response.
BLOCKING_ACTIONS = frozenset({Action.DENY, Action.TARPIT, Action.CHALLENGE})

# Conventional keys of ``Signal.details`` the engine reads (additive, all optional).
DETAIL_TELEMETRY_TYPE = "telemetry_type"  # "standard" / "inline" / "native"
DETAIL_LAYERS = "layers"  # version_consistency: per-layer version agreement -> ScoreReport.layers
DETAIL_BOT_NAME = "bot_name"  # known_bots: classified bot name, e.g. "amazonbot"
DETAIL_BOT_CATEGORY = "bot_category"  # known_bots: e.g. "Web Search Engine Bots"
DETAIL_USER_RISK = "user_risk"  # account_protector: dict feeding the Akamai-User-Risk header


class Signal(BaseModel):
    """Output of a single module for a single request."""

    module: str
    verdict: Verdict
    score: int = Field(ge=0, le=100, description="Bot-likelihood contribution 0-100")
    reason: str
    details: dict[str, Any] = Field(default_factory=dict)
    confidence: Confidence | None = None  # filled in by the engine from the module


class FlagSpec(BaseModel):
    """A feature flag a module declares; gates LOW-confidence behaviour (default off).

    Resolution order: store key ``flag:{name}`` ("1"/"0", set from the dashboard via
    ``PUT /api/flags/{name}``), then env ``LAB_FLAG_<NAME upper>``, then ``default``.
    """

    name: str  # snake_case, globally unique, e.g. "abck_tilde0_mode"
    description: str
    confidence: Confidence = Confidence.LOW
    default: bool = False
    source: str = ""  # short citation into docs/research/akamai-audit-2026-10.md


class ScoreReport(BaseModel):
    """Final per-request report; also the payload of the live feed (SSE)."""

    id: str
    ts: float = Field(default_factory=time.time)
    method: str
    path: str
    client_ip: str
    user_agent: str
    score: int = Field(ge=0, le=100)
    blocked: bool
    signals: list[Signal]
    fingerprint: dict[str, str] = Field(default_factory=dict)  # ja3/ja4/h2/header order
    headers: list[tuple[str, str]] = Field(default_factory=list)
    cookies: dict[str, str] = Field(default_factory=dict)
    client_label: str = ""  # value of X-Lab-Client header, used by the comparison panel
    # --- v2 (audit remediation) -------------------------------------------------------
    endpoint_class: EndpointClass = EndpointClass.PROTECTED
    telemetry_type: str = "standard"  # "standard" | "inline" | "native" (audit §2.5)
    segment: str = ""  # Bot Score segment name, e.g. "cautious" | "strict" | "aggressive"
    action: Action = Action.ALLOW  # what the lab actually did with the request
    canary: str = ""  # serve_alternate: hidden token planted in the perturbed response
    reference: str = ""  # deny: Akamai-style "Reference #18.xxxx.ts.xxxx" mapped to this report
    layers: dict[str, Any] = Field(default_factory=dict)  # cross-layer version agreement (§2.2)
    origin_headers: dict[str, str] = Field(default_factory=dict)  # verdict headers to origin (§2.9)
    # --- v2.1 (additive) ---------------------------------------------------------------
    is_human: bool = False  # Bot Score 0: no detection fired (EdgeWorkers isHuman() analogue)
    is_safeguard: bool = False  # set aside so a human is not trapped (isSafeguardResponse analogue)
    challenge_provider: str = ""  # crypto | behavioral | adaptive | interactive (when challenged)


class SessionStore(Protocol):
    """Minimal async KV used by modules for per-session/per-IP state (Redis or memory)."""

    async def get(self, key: str) -> str | None: ...
    async def set(self, key: str, value: str, ttl: int | None = None) -> None: ...
    async def incr(self, key: str, ttl: int | None = None) -> int: ...
    async def delete(self, key: str) -> None: ...


class RequestContext(BaseModel):
    """Everything a module may inspect. Built once per request by the engine."""

    model_config = {"arbitrary_types_allowed": True}

    method: str
    path: str
    client_ip: str
    headers: list[tuple[str, str]]  # lower-cased names, edge headers stripped
    header_order: list[str]  # original casing, wire order (from edge)
    cookies: dict[str, str]
    user_agent: str
    ja3: str = ""
    ja3_hash: str = ""
    ja4: str = ""
    h2_fingerprint: str = ""
    http_proto: str = "http/1.1"
    session_id: str = ""  # value of bm_sz cookie (issued before evaluation if missing)
    store: Any = None  # SessionStore
    # --- v2 ------------------------------------------------------------------------------
    endpoint_class: EndpointClass = EndpointClass.PROTECTED
    body_sha256: str = ""  # hex sha256 of the raw request body ("" for GET)
    query: dict[str, str] = Field(default_factory=dict)
    body: bytes = b""  # raw request body (POST/PUT/PATCH, capped at 64 KiB; b"" for GET)
    flags: dict[str, bool] = Field(default_factory=dict)  # resolved feature flags (FlagSpec)

    def flag(self, name: str) -> bool:
        """Resolved value of a declared feature flag (False if undeclared)."""
        return self.flags.get(name, False)

    def header(self, name: str) -> str | None:
        name = name.lower()
        for k, v in self.headers:
            if k == name:
                return v
        return None


class DetectionModule(ABC):
    """Base class for every Akamai-style case.

    Subclasses set the class attributes and implement :meth:`evaluate`. They
    may also expose extra routes (challenge scripts, sensor endpoints) via
    :meth:`router`; these are mounted under ``/akam/<slug>/``.
    """

    slug: ClassVar[str]  # e.g. "tls_fingerprint"; also the docs/cases/<slug>.md name
    title: ClassVar[str]
    description: ClassVar[str]
    category: ClassVar[str]  # "passive" | "cookie" | "js" | "behavioral" | "network" | ...
    default_enabled: ClassVar[bool] = True
    # v2: confidence tier of the simulated mechanism (audit §3.1); shown in the dashboard.
    confidence: ClassVar[Confidence] = Confidence.HIGH
    # v2: endpoint classes this module is evaluated on when running "all enabled modules"
    # (GET /, /protected/all, transactional and mobile endpoints). /protected/<slug>
    # always evaluates the named module regardless of this set.
    applies_to: ClassVar[frozenset[EndpointClass]] = frozenset(
        {EndpointClass.PAGE, EndpointClass.PROTECTED}
    )
    # v2: feature flags this module declares (LOW-confidence behaviour, default off).
    flags: ClassVar[list[FlagSpec]] = []
    # v1 (still supported): static script paths relative to /akam/<slug>/, injected into
    # every HTML page. Prefer page_snippets() for per-session markup.
    client_scripts: ClassVar[list[str]] = []
    # Protected demo resource for this case: GET /protected/<slug>
    # The engine evaluates ONLY this module (plus nothing else) on that path,
    # and ALL enabled modules on GET /protected/all.

    @abstractmethod
    async def evaluate(self, ctx: RequestContext) -> Signal: ...

    def router(self) -> Any | None:  # fastapi.APIRouter | None
        return None

    async def page_snippets(self, ctx: RequestContext) -> list[str]:
        """v2: raw HTML fragments injected before ``</body>`` of every HTML page the lab
        serves (landing page, interstitials). Use for per-session script paths and values
        embedded in markup (e.g. the pixel's global). ``ctx.session_id`` is always set."""
        return []

    def root_router(self) -> Any | None:  # fastapi.APIRouter | None
        """v2.1: routes mounted at the site root (no ``/akam/<slug>`` prefix), for vendor-style
        absolute paths such as ``/_sec/verify``. Mounted before the catch-all route."""
        return None

    # v2.1: challenge providers this module can serve (e.g. {"crypto", "adaptive"}); the
    # response policy's ``challenge_provider`` picks the enabled module that lists it.
    challenge_providers: ClassVar[frozenset[str]] = frozenset()

    async def challenge_satisfied(self, ctx: RequestContext, provider: str | None = None) -> bool:
        """v2.1: challenge providers only. True when this request carries valid proof that
        the session solved this module's challenge recently (cookie AND store state). The
        engine then downgrades a ``challenge`` action to monitor instead of looping."""
        return False

    async def after_score(self, ctx: RequestContext, report: ScoreReport) -> None:
        """v2.1: called on every enabled module after the engine has scored and decided an
        action (``report.segment`` / ``report.action`` are final). Use it to learn from the
        outcome (profiles) or to arm follow-up work (step-up collection). Must not raise."""
        return None

    async def pre_request(self, request: Any, ctx: RequestContext) -> Any | None:
        """v2.1: access-control gate run BEFORE scoring on page and protected requests
        (e.g. a waiting room). Return a Response to short-circuit, or None to continue."""
        return None

    async def issue_challenge(
        self, request: Any, ctx: RequestContext, provider: str, *, html: bool
    ) -> Any | None:
        """v2.1: build the challenge response (a fastapi Response) for the ``challenge`` action.
        ``html`` is True for browser navigations (interstitial page), False for XHR/API
        callers (428 JSON). Return None to decline."""
        return None

    async def handle_dynamic(self, request: Any, ctx: RequestContext) -> Any | None:
        """v2: claim a request on an otherwise unrouted same-origin path (GET or POST),
        e.g. a per-session random sensor-script path. Return a Response to claim it,
        or None to pass. Called in module slug order; first non-None wins."""
        return None

    def signal(
        self, verdict: Verdict, score: int, reason: str, **details: Any
    ) -> Signal:
        return Signal(
            module=self.slug, verdict=verdict, score=score, reason=reason, details=details
        )
