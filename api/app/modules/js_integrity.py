"""``js_integrity``: JavaScript integrity and automation-artifact probes (audit report §2.3).

Mechanism
---------
Bot Manager's sensor reads properties that automation frameworks change and sends the results
inside the payload. A 2026 measurement of 7,944 sites found ``navigator.webdriver`` read on
34% of them, ``HeadlessChrome`` brands in client hints as a strong headless tell, and
automation honeypot properties checked on 46% ([S], Gundelach et al., 2026-06-12).

Tiers (report §2.3 and §3.1)
----------------------------
* HIGH (concept: integrity probes in the sensor [V]/[S]): native-code checks on Navigator
  getters, where the ``webdriver`` descriptor lives, ``HeadlessChrome`` in the UA or
  ``userAgentData.brands``, framework-injected globals, the shape of ``window.chrome``.
* LOW (vendor claims): Akamai-specific CDP / headless probes. Only behind the ``cdp_probes``
  flag (default off): an ``Error.stack`` getter trap that fires when DevTools / ``Runtime.enable``
  serialises a logged error. UNVERIFIED, vendor-sourced.

How the lab simulates it
------------------------
``static/sensor.src.js`` records the probes under ``integrity`` (plus ``navigator.brands``,
``navigator.webdriver``); ``sensor_data`` stores them with the sensor, and this module scores
them from ``sensor:{sid}`` (or ``sensor:integrity:{sid}`` when the sensor was rejected, so the
reason is still explainable). No sensor at all is a FAIL with a reason. Per-probe results and
confidence are in ``details["probes"]``.

Real Chrome: ``webdriver`` is an accessor on ``Navigator.prototype`` whose getter prints
``function get webdriver() { [native code] }`` and nothing on the ``navigator`` instance.
``Object.defineProperty(Navigator.prototype, 'webdriver', {get: () => false})`` (what the lab's
Playwright client does) leaves the descriptor in place but swaps in a script function:
``toString`` shows its source and its name is ``get`` -> flagged. Defining it on the instance
is flagged by location.

How a client passes
-------------------
By not tampering: a stock (headful or patched-at-source) browser reports native getters and
no automation globals. A client that fabricates native-shaped results without running the
script passes (client-supplied data; real Akamai rotates and obfuscates its probes, the lab
does not claim to match that).

Limits
------
Weights are lab-defined. ``window.chrome.runtime`` is optional here because it only exists on
some pages; the expected set is ``app``, ``csi`` and ``loadTimes``.
"""

from __future__ import annotations

import json
import re
from typing import Any, ClassVar

from app.contract import (
    Confidence,
    DetectionModule,
    EndpointClass,
    FlagSpec,
    RequestContext,
    Signal,
    Verdict,
)

FAIL_AT = 50
WARN_AT = 20
NAV_GETTERS = ("webdriver", "userAgent", "platform", "languages", "hardwareConcurrency", "plugins")
_CHROME_UA = re.compile(r"Chrome/(\d+)")


def _probe(status: str, weight: int, conf: str, note: str = "") -> dict[str, Any]:
    return {
        "status": status,
        "weight": weight if status != "pass" else 0,
        "confidence": conf,
        "note": note,
    }


def _claims_desktop_chrome(ua: str) -> int | None:
    m = _CHROME_UA.search(ua)
    if not m or "Mobile" in ua or "Android" in ua:
        return None
    return int(m.group(1))


def analyze_integrity(
    integrity: dict[str, Any] | None, nav: dict[str, Any], cdp_enabled: bool = False
) -> tuple[int, dict[str, dict[str, Any]], list[str]]:
    """Return ``(score, probes, reasons)`` for one sensor's integrity block."""
    probes: dict[str, dict[str, Any]] = {}
    reasons: list[str] = []

    def add(name: str, p: dict[str, Any], reason: str = "") -> None:
        probes[name] = p
        if p["status"] != "pass" and reason:
            reasons.append(reason)

    ua = str(nav.get("userAgent", ""))
    brands = [str(b) for b in nav.get("brands") or []]
    integ = integrity or {}

    if nav.get("webdriver") is True:
        add("webdriver_flag", _probe("fail", 100, "high"), "navigator.webdriver is true")
    else:
        add("webdriver_flag", _probe("pass", 0, "high"))

    getters = integ.get("nav") or {}
    wd = getters.get("webdriver")
    if not isinstance(wd, dict):
        add(
            "webdriver_getter",
            _probe("fail", 80, "high", "no probe data"),
            "integrity probes missing from the sensor",
        )
    elif wd.get("where") != "proto":
        add(
            "webdriver_getter",
            _probe("fail", 70, "high", f"descriptor on {wd.get('where')}"),
            "navigator.webdriver is not an accessor on Navigator.prototype "
            f"(found: {wd.get('where')})",
        )
    elif not (wd.get("accessor") and wd.get("native") and wd.get("name_ok")):
        add(
            "webdriver_getter",
            _probe("fail", 70, "high", "getter is a script function"),
            "navigator.webdriver getter is not native (overridden by script)",
        )
    else:
        add("webdriver_getter", _probe("pass", 0, "high", "native getter on Navigator.prototype"))

    tampered = sorted(
        k
        for k in NAV_GETTERS
        if k != "webdriver"
        and isinstance(getters.get(k), dict)
        and not (
            getters[k].get("where") in ("proto", "none")
            and (not getters[k].get("accessor") or getters[k].get("native"))
        )
    )
    if tampered:
        add(
            "navigator_getters",
            _probe("fail", 55, "high", ", ".join(tampered)),
            f"non-native Navigator getters: {', '.join(tampered)}",
        )
    else:
        add("navigator_getters", _probe("pass", 0, "high"))

    if integ and integ.get("fts_native") is False:
        add(
            "function_tostring",
            _probe("fail", 50, "high"),
            "Function.prototype.toString is patched",
        )
    else:
        add("function_tostring", _probe("pass", 0, "high"))

    headless = "HeadlessChrome" in ua or any(b.startswith("HeadlessChrome") for b in brands)
    if headless:
        add("headless_marker", _probe("fail", 85, "high"), "HeadlessChrome in UA or client hints")
    else:
        add("headless_marker", _probe("pass", 0, "high"))

    found = [str(g) for g in integ.get("globals") or []][:10]
    if found:
        add(
            "automation_globals",
            _probe("fail", 90, "high", ", ".join(found)),
            f"automation globals present: {', '.join(found)}",
        )
    else:
        add("automation_globals", _probe("pass", 0, "high"))

    chrome_major = _claims_desktop_chrome(ua)
    if chrome_major is not None and integ:
        chrome = integ.get("chrome") or {}
        keys = [k for k in chrome.get("keys", []) if k in ("app", "csi", "loadTimes")]
        if not chrome.get("present"):
            add(
                "window_chrome",
                _probe("warn", 25, "high", "absent"),
                "window.chrome is absent in a Chrome UA",
            )
        elif len(keys) < 2:
            add(
                "window_chrome",
                _probe("warn", 15, "high", f"keys: {keys}"),
                "window.chrome has an atypical shape",
            )
        else:
            add("window_chrome", _probe("pass", 0, "high", f"keys: {keys}"))
        if chrome_major >= 90 and not brands:
            add(
                "client_hint_brands",
                _probe("warn", 15, "high", "empty userAgentData.brands"),
                "Chrome UA but no userAgentData brands (UA overridden without client hints?)",
            )
        else:
            add("client_hint_brands", _probe("pass", 0, "high"))

    if cdp_enabled and "cdp" in integ:
        if integ.get("cdp") is True:
            add(
                "cdp_stack_trap",
                _probe("fail", 60, "low", "unverified, vendor-sourced"),
                "Error.stack trap fired (DevTools/CDP serialised a logged error)",
            )
        else:
            add("cdp_stack_trap", _probe("pass", 0, "low", "unverified, vendor-sourced"))

    weights = sorted((p["weight"] for p in probes.values()), reverse=True)
    score = min(100, round(weights[0] + 0.5 * sum(weights[1:]))) if weights else 0
    return score, probes, reasons


class JsIntegrityModule(DetectionModule):
    slug: ClassVar[str] = "js_integrity"
    title: ClassVar[str] = "JS integrity / automation probes"
    description: ClassVar[str] = (
        "Scores native-getter, webdriver descriptor, headless-marker, automation-global and "
        "window.chrome probes reported by the sensor."
    )
    category: ClassVar[str] = "js"
    confidence: ClassVar[Confidence] = Confidence.HIGH
    applies_to: ClassVar[frozenset[EndpointClass]] = frozenset(
        {EndpointClass.PAGE, EndpointClass.PROTECTED, EndpointClass.TRANSACTIONAL}
    )
    flags: ClassVar[list[FlagSpec]] = [
        FlagSpec(
            name="cdp_probes",
            description="Add an Error.stack getter-trap probe for CDP/DevTools serialisation.",
            confidence=Confidence.LOW,
            source="report §2.3, §3.1 (Akamai-specific CDP/headless probes: vendor claims)",
        )
    ]

    async def evaluate(self, ctx: RequestContext) -> Signal:
        sid, store = ctx.session_id, ctx.store
        raw = await store.get(f"sensor:{sid}") if sid else None
        if not raw and sid:
            raw = await store.get(f"sensor:integrity:{sid}")
        if not raw:
            rej = await store.get(f"sensor_rejected:{sid}") if sid else None
            reason = (
                f"no usable sensor ({rej})" if rej else "no sensor posted (no integrity probes)"
            )
            return self.signal(Verdict.FAIL, 90, reason)
        try:
            data = json.loads(raw)
            nav = data.get("navigator") or {}
            if not isinstance(nav, dict):
                raise TypeError("navigator")
            if "ua" in data and not nav.get("userAgent"):
                nav = {**nav, "userAgent": data["ua"]}
            score, probes, reasons = analyze_integrity(
                data.get("integrity"), nav, ctx.flag("cdp_probes")
            )
        except (ValueError, TypeError, AttributeError):
            return self.signal(Verdict.FAIL, 90, "unreadable integrity telemetry")
        failed = [n for n, p in probes.items() if p["status"] != "pass"]
        if score >= FAIL_AT:
            verdict = Verdict.FAIL
        elif score >= WARN_AT:
            verdict = Verdict.WARN
        else:
            verdict = Verdict.PASS
        reason = (
            "; ".join(reasons) if reasons else "integrity probes consistent with a real browser"
        )
        return self.signal(verdict, score, reason, probes=probes, failed=failed)
