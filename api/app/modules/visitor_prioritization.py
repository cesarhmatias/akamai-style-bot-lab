"""Visitor Prioritization style waiting room (audit §2.15, tier LOW overall).

Mechanism
    Under load, admit only part of the NEW visitors and park the rest on a waiting page. An
    admitted visitor carries an "allowed user" cookie; a parked visitor carries a short-lived
    waiting-room cookie and is let in after the wait.

How real Akamai uses it (report §2.15)
    Akamai's Visitor Prioritization cloudlet issues an allowed-user cookie (the instance label
    changes its name) and a waiting-room cookie (Akamai TechDocs, 2026-06-23). The prefix
    ``akavpau_<label>`` for the allowed-user cookie is LOW confidence (a single search snippet).
    The lab's storefront is a "limited sneaker drop", the textbook use case. The overall
    tier is LOW: the module is OFF by default (``default_enabled = False``).

How the lab simulates it
    * A ``pre_request`` gate on page and protected requests. A session is NEW until it has an
      admission record. Admission is a deterministic hash of the session id: the same session
      always lands in the same bucket, ``admit_percent`` (default 50, env
      ``LAB_VP_ADMIT_PERCENT``) of buckets are admitted at once.
    * Everyone else gets the waiting-room page (HTTP 200 HTML for navigations, 503 JSON with
      ``Retry-After`` for API callers), a ``lab_vp_waiting`` cookie with a TTL equal to the wait,
      and is admitted once ``wait_seconds`` (default 30, env ``LAB_VP_WAIT_SECONDS``) elapsed.
    * Admission sets the allowed-user cookie. Its name is ``lab_vp_allowed`` unless the LOW
      flag ``akavpau_cookie_name`` is on, which uses ``akavpau_<label>`` (label from
      ``LAB_VP_LABEL``, default ``lab``).

How a client passes it
    Keep the cookies and wait; a parked client simply polls until admitted.

Limits: no real queue, capacity or position; the position shown is a lab number.
It is a gate, not a detection: ``evaluate()`` is always SKIP and it has no ``applies_to``.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from collections.abc import Callable
from typing import Any, ClassVar

from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from app.contract import Confidence, DetectionModule, FlagSpec, RequestContext, Signal, Verdict

ALLOWED_TTL = 3600
WAIT_COOKIE = "lab_vp_waiting"
LAB_ALLOWED_COOKIE = "lab_vp_allowed"


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


def bucket(sid: str) -> int:
    """Deterministic 0-99 bucket of a session id."""
    return int(hashlib.sha256(sid.encode()).hexdigest()[:8], 16) % 100


class VisitorPrioritization(DetectionModule):
    slug: ClassVar[str] = "visitor_prioritization"
    title: ClassVar[str] = "Visitor prioritization waiting room"
    description: ClassVar[str] = (
        "Admits a percentage of new sessions and parks the rest on a waiting-room page with a "
        "TTL cookie. LOW confidence overall; off by default."
    )
    category: ClassVar[str] = "network"
    confidence: ClassVar[Confidence] = Confidence.LOW
    default_enabled: ClassVar[bool] = False
    applies_to: ClassVar[frozenset[Any]] = frozenset()
    flags: ClassVar[list[FlagSpec]] = [
        FlagSpec(
            name="akavpau_cookie_name",
            description="Name the allowed-user cookie akavpau_<label> (vendor-sourced, a single "
            "search snippet) instead of the lab name lab_vp_allowed. Unverified.",
            confidence=Confidence.LOW,
            default=False,
            source="audit §2.15",
        )
    ]

    def __init__(
        self,
        admit_percent: float | None = None,
        wait_seconds: float | None = None,
        label: str | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.admit_percent = (
            admit_percent if admit_percent is not None else _env_float("LAB_VP_ADMIT_PERCENT", 50)
        )
        self.wait_seconds = (
            wait_seconds if wait_seconds is not None else _env_float("LAB_VP_WAIT_SECONDS", 30)
        )
        self.label = label or os.environ.get("LAB_VP_LABEL", "lab")
        self.clock = clock

    def allowed_cookie_name(self, ctx: RequestContext) -> str:
        return f"akavpau_{self.label}" if ctx.flag("akavpau_cookie_name") else LAB_ALLOWED_COOKIE

    async def evaluate(self, ctx: RequestContext) -> Signal:
        return self.signal(Verdict.SKIP, 0, "the waiting room is an access gate, not a detection")

    def _admit(self, request: Request, ctx: RequestContext) -> None:
        """Queue the allowed-user cookie for the response that will be served."""
        name = self.allowed_cookie_name(ctx)
        queued = getattr(request.state, "extra_cookies", [])
        queued.append(
            (
                name,
                f"{bucket(ctx.session_id):02d}~{int(self.clock())}",
                {"path": "/", "samesite": "lax", "max_age": ALLOWED_TTL},
            )
        )
        request.state.extra_cookies = queued

    async def pre_request(self, request: Request, ctx: RequestContext) -> Response | None:
        sid = ctx.session_id
        if not sid:
            return None
        store, now = ctx.store, self.clock()
        if await store.get(f"vp:allowed:{sid}"):
            if self.allowed_cookie_name(ctx) not in ctx.cookies:
                self._admit(request, ctx)  # restore a dropped cookie
            return None
        raw = await store.get(f"vp:parked:{sid}")
        parked_at = float(json.loads(raw)["at"]) if raw else None
        if parked_at is None and bucket(sid) < self.admit_percent:
            await store.set(f"vp:allowed:{sid}", "1", ttl=ALLOWED_TTL)
            self._admit(request, ctx)
            return None
        if parked_at is not None and now - parked_at >= self.wait_seconds:
            await store.set(f"vp:allowed:{sid}", "1", ttl=ALLOWED_TTL)
            await store.delete(f"vp:parked:{sid}")
            self._admit(request, ctx)
            return None
        if parked_at is None:
            parked_at = now
            await store.set(
                f"vp:parked:{sid}", json.dumps({"at": now}), ttl=int(self.wait_seconds) + 60
            )
        remaining = max(1, int(self.wait_seconds - (now - parked_at) + 0.999))
        accept = request.headers.get("accept", "")
        wants_html = "text/html" in accept and "application/json" not in accept
        resp: Response
        if wants_html:
            resp = HTMLResponse(
                "<!doctype html><html><head><meta charset=utf-8><title>You are in the queue</title>"
                f'<meta http-equiv="refresh" content="{min(remaining, 5)}"></head>'
                '<body style="font-family:system-ui,sans-serif;text-align:center;margin-top:4rem">'
                "<h1>You are in the waiting room</h1>"
                f"<p>Estimated wait: about {remaining} seconds. Keep this tab open.</p>"
                "</body></html>"
            )
        else:
            resp = JSONResponse(
                {"ok": False, "error": "waiting_room", "retry_after": remaining}, status_code=503
            )
        resp.headers["Retry-After"] = str(remaining)
        resp.set_cookie(WAIT_COOKIE, str(int(parked_at)), path="/", max_age=remaining)
        return resp
