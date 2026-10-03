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


class Signal(BaseModel):
    """Output of a single module for a single request."""

    module: str
    verdict: Verdict
    score: int = Field(ge=0, le=100, description="Bot-likelihood contribution 0-100")
    reason: str
    details: dict[str, Any] = Field(default_factory=dict)


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
    session_id: str = ""  # value of bm_sz cookie (or "" if none yet)
    store: Any = None  # SessionStore

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
    category: ClassVar[str]  # "passive" | "cookie" | "js" | "behavioral" | "network"
    default_enabled: ClassVar[bool] = True
    # Protected demo resource for this case: GET /protected/<slug>
    # The engine evaluates ONLY this module (plus nothing else) on that path,
    # and ALL enabled modules on GET /protected/all.

    @abstractmethod
    async def evaluate(self, ctx: RequestContext) -> Signal: ...

    def router(self) -> Any | None:  # fastapi.APIRouter | None
        return None

    def signal(
        self, verdict: Verdict, score: int, reason: str, **details: Any
    ) -> Signal:
        return Signal(
            module=self.slug, verdict=verdict, score=score, reason=reason, details=details
        )
