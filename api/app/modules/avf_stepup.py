"""Advanced Validation Framework style step-up data collection (audit §2.6).

Mechanism
    When a detection lacks enough information for a confident decision, ask the device for
    MORE data on demand instead of always collecting it. Only gray-zone clients ever see the
    extra script.

How real Akamai uses it
    Tier MEDIUM-HIGH: Akamai's 2026-03-10 blog says "If a detection method lacks sufficient
    information to make a confident decision, the new AVF dynamically requests additional data
    from the device". What it asks for, and how the answer is scored, is not public. The probe
    set below (WebGL vendor/renderer, audio-context fingerprint hash, font probe count) is the
    report's suggestion (§2.6), not a documented Akamai list.

How the lab simulates it
    * ``after_score``: when a request lands in the ``strict`` segment and no step-up data was
      received for the session, the session is marked ``avf:need:{sid}``.
    * ``page_snippets`` then adds ``/akam/avf_stepup/stepup.js`` to every lab HTML page
      (landing page and challenge interstitials) for that session only. The script collects the
      probes and POSTs ``{webgl:{vendor, renderer}, audio, fonts}`` to ``/akam/avf_stepup/data``.
    * ``evaluate()`` is SKIP when no step-up was requested, WARN (30) when it was requested but
      no data arrived (a client that cannot run the script), and otherwise scores the data:
      software GL renderers (SwiftShader, llvmpipe), a renderer that contradicts the User-Agent
      platform, a missing or degenerate audio hash, and a very small font set.
    * The next request is re-scored with that signal; the data endpoint also returns the
      step-up score so a client can see the effect.
    The alternative from the report (route the strict segment to the tile challenge instead of
    a script) is available by setting ``challenge_provider`` to ``interactive`` in the policy.

How a client passes it
    Run the script in a real browser with a real GPU or a believable software stack. A
    pure-HTTP client never sees the script's output and keeps the WARN.

Limits: lab heuristics; headless Chromium reports SwiftShader and will score as suspicious.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from typing import Any, ClassVar

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from app.contract import (
    Confidence,
    DetectionModule,
    EndpointClass,
    RequestContext,
    ScoreReport,
    Signal,
    Verdict,
)

NEED_TTL = 900
DATA_TTL = 3600
MISSING_SCORE = 30
SOFTWARE_RENDERERS = ("swiftshader", "llvmpipe", "softpipe", "mesa offscreen")

STEPUP_JS = r"""(function () {
  'use strict';
  // Lab-written step-up collector (not Akamai code).
  function webgl() {
    try {
      var c = document.createElement('canvas');
      var gl = c.getContext('webgl') || c.getContext('experimental-webgl');
      if (!gl) return {vendor: '', renderer: ''};
      var ext = gl.getExtension('WEBGL_debug_renderer_info');
      return {
        vendor: String(gl.getParameter(ext ? ext.UNMASKED_VENDOR_WEBGL : gl.VENDOR)),
        renderer: String(gl.getParameter(ext ? ext.UNMASKED_RENDERER_WEBGL : gl.RENDERER))
      };
    } catch (e) { return {vendor: '', renderer: ''}; }
  }
  function audio() {
    return new Promise(function (resolve) {
      try {
        var Ctx = window.OfflineAudioContext || window.webkitOfflineAudioContext;
        var ctx = new Ctx(1, 5000, 44100), osc = ctx.createOscillator();
        var comp = ctx.createDynamicsCompressor();
        osc.type = 'triangle'; osc.frequency.value = 10000;
        osc.connect(comp); comp.connect(ctx.destination); osc.start(0);
        ctx.oncomplete = function (e) {
          var d = e.renderedBuffer.getChannelData(0), s = 0;
          for (var i = 4500; i < 5000; i++) s += Math.abs(d[i]);
          resolve(s.toFixed(6));
        };
        ctx.startRendering();
      } catch (e) { resolve(''); }
    });
  }
  function fonts() {
    var names = ['Arial', 'Verdana', 'Times New Roman', 'Courier New', 'Georgia', 'Palatino',
      'Garamond', 'Comic Sans MS', 'Trebuchet MS', 'Impact', 'Tahoma', 'Helvetica', 'Menlo',
      'Consolas', 'Ubuntu', 'DejaVu Sans', 'Liberation Sans', 'Noto Sans', 'Segoe UI', 'Roboto'];
    var span = document.createElement('span');
    span.style.cssText = 'position:absolute;left:-9999px;font-size:48px';
    span.textContent = 'mmmmmmmmmmlli';
    document.body.appendChild(span);
    span.style.fontFamily = 'monospace';
    var base = span.offsetWidth, n = 0;
    names.forEach(function (f) {
      span.style.fontFamily = "'" + f + "',monospace";
      if (span.offsetWidth !== base) n++;
    });
    document.body.removeChild(span);
    return n;
  }
  function run() {
    audio().then(function (a) {
      return fetch('/akam/avf_stepup/data', {
        method: 'POST', credentials: 'include', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({webgl: webgl(), audio: a, fonts: fonts()})
      });
    }).catch(function () {}).then(function () {
      window.__akStepupDone = true;
    });
  }
  if (document.body) run(); else document.addEventListener('DOMContentLoaded', run);
})();
"""


def analyze(data: dict[str, Any], user_agent: str) -> tuple[int, list[str]]:
    """Score step-up data 0-100 (higher = more bot-like) with human-readable findings."""
    score, findings = 0, []
    gl = data.get("webgl") or {}
    vendor, renderer = str(gl.get("vendor", "")), str(gl.get("renderer", ""))
    low = renderer.lower()
    ua = user_agent.lower()
    if not renderer:
        score += 25
        findings.append("no WebGL renderer reported")
    elif any(s in low for s in SOFTWARE_RENDERERS):
        score += 35
        findings.append(f"software GL renderer ({renderer})")
    if renderer and (
        ("windows" in ua and ("mesa" in low or "apple" in low))
        or ("macintosh" in ua and ("direct3d" in low or "mesa" in low))
    ):
        score += 30
        findings.append("WebGL renderer contradicts the User-Agent platform")
    audio = str(data.get("audio", ""))
    if not audio or float(audio or 0) == 0.0:
        score += 20
        findings.append("audio fingerprint missing or degenerate")
    try:
        fonts = int(data.get("fonts", 0))
    except (TypeError, ValueError):
        fonts = 0
    if fonts < 3:
        score += 25
        findings.append(f"very few fonts detected ({fonts})")
    _ = vendor
    return min(100, score), findings


class AvfStepup(DetectionModule):
    slug: ClassVar[str] = "avf_stepup"
    title: ClassVar[str] = "AVF step-up collection"
    description: ClassVar[str] = (
        "On-demand extra data (WebGL, audio hash, fonts) requested only from sessions that "
        "landed in the strict segment, then re-scored. Concept MEDIUM-HIGH; probe set is a lab "
        "approximation."
    )
    category: ClassVar[str] = "js"
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    applies_to: ClassVar[frozenset[EndpointClass]] = frozenset(
        {EndpointClass.PAGE, EndpointClass.PROTECTED, EndpointClass.TRANSACTIONAL}
    )

    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self.clock = clock

    async def evaluate(self, ctx: RequestContext) -> Signal:
        sid = ctx.session_id
        raw = await ctx.store.get(f"avf:data:{sid}") if sid else None
        if raw:
            rec = json.loads(raw)
            score = int(rec["score"])
            if score == 0:
                return self.signal(
                    Verdict.PASS, 0, "step-up data consistent", findings=rec["findings"]
                )
            verdict = Verdict.FAIL if score >= 50 else Verdict.WARN
            return self.signal(
                verdict,
                score,
                "step-up data suspicious: " + "; ".join(rec["findings"]),
                findings=rec["findings"],
            )
        if sid and await ctx.store.get(f"avf:need:{sid}"):
            return self.signal(
                Verdict.WARN,
                MISSING_SCORE,
                "step-up data requested but not received",
                requested=True,
            )
        return self.signal(Verdict.SKIP, 0, "no step-up requested for this session")

    async def after_score(self, ctx: RequestContext, report: ScoreReport) -> None:
        sid = ctx.session_id
        if report.segment == "strict" and sid and not await ctx.store.get(f"avf:data:{sid}"):
            await ctx.store.set(f"avf:need:{sid}", str(int(self.clock())), ttl=NEED_TTL)

    async def page_snippets(self, ctx: RequestContext) -> list[str]:
        sid = ctx.session_id
        if not sid or await ctx.store.get(f"avf:data:{sid}"):
            return []
        if await ctx.store.get(f"avf:need:{sid}"):
            return ['<script src="/akam/avf_stepup/stepup.js" defer></script>']
        return []

    def router(self) -> APIRouter:
        r = APIRouter()

        @r.get("/stepup.js")
        async def stepup_js() -> Response:
            return Response(
                STEPUP_JS,
                media_type="application/javascript",
                headers={"Cache-Control": "no-store"},
            )

        @r.post("/data")
        async def data(request: Request) -> Response:
            sid = request.cookies.get("bm_sz", "")
            store = request.app.state.store
            try:
                body = await request.json()
                if not isinstance(body, dict) or "webgl" not in body:
                    raise ValueError
            except ValueError:
                return JSONResponse({"ok": False, "error": "bad_request"}, status_code=400)
            if not sid or not await store.get(f"avf:need:{sid}"):
                return JSONResponse({"ok": False, "error": "not_requested"}, status_code=403)
            score, findings = analyze(body, request.headers.get("user-agent", ""))
            rec = {"score": score, "findings": findings, "received_at": self.clock()}
            await store.set(f"avf:data:{sid}", json.dumps(rec), ttl=DATA_TTL)
            return JSONResponse({"ok": True, "stepup_score": score, "findings": findings})

        return r
