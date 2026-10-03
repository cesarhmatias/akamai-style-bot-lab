"""Cross-layer Chrome version consistency (passive TLS/header markers vs UA, hints and JS).

Mechanism: every layer of a request independently leaks which Chrome release produced it. The
TLS hello carries release-specific groups and codepoints, the headers carry release-specific
values, the User-Agent and ``sec-ch-ua`` state a version outright, and the sensor script can read
``navigator.userAgentData``. A genuine browser has all of them agree; a spoofed UA, a stale
impersonation profile or a UA override on a different build does not.

How real Akamai uses it (audit report ``docs/research/akamai-audit-2026-10.md`` section 2.2,
HIGH): "browser version mismatches" are a named transparent-detection target (Akamai
detection-methods page), Content Protector checks JavaScript-collected traits against
protocol-level data (2024 press release), and the 2017 white paper correlates TCP, TLS and HTTP/2.
Akamai's concrete rules are not public; the markers and thresholds below are the lab's own, built
on Chromium-documented release changes.

How the lab simulates it (``details["layers"]`` carries the result; the response agent copies it
into ``ScoreReport.layers`` and the dashboard shows whether the layers agree):

* ``tls_min`` / ``tls_max``: Chrome window implied by TLS markers (see
  ``tls_fingerprint.chrome_tls_era``): group 4588 => 131+, Kyber => <= 130, ALPS 17613 => 133+,
  ALPS 17513 => <= 132, ML-DSA signature schemes in a Chrome-shaped hello => 150+ (MEDIUM).
* ``hdr_min``: ``zstd`` in accept-encoding => 123+; ``priority`` header over h2 => 124+.
* ``ua_major``: ``Chrome/<major>`` from the User-Agent; ``sech_major``: Chromium (or Google
  Chrome) brand major in ``sec-ch-ua``; ``js_major``: same brands read by the sensor
  (store key ``sensor:{session_id}``, field ``navigator.brands``; absent unless a sensor was
  posted).
* every claimed major (UA, sec-ch-ua, JS) must lie inside ``[max(tls_min, hdr_min), tls_max]``
  and the claimed majors must be equal. A violation backed only by the MEDIUM ML-DSA marker is
  WARN 40; any other violation is FAIL 80 with a precise reason. Non-Chromium UAs (Firefox,
  Safari, iOS browsers, tools) are SKIP: the era markers describe Chrome only, and Firefox also
  sends ML-KEM.

How a client passes: be a real current browser, or an impersonation profile whose UA, hints and
TLS come from the SAME release. Typical failures: Playwright with a UA overridden to an old Chrome
on a newer bundled Chromium (TLS says 150+, UA says 131); curl_cffi ``chrome131`` with a newer UA
(legacy ALPS 17513 caps TLS at <= 132); a Chrome UA whose hints disagree.

Limits: markers are release-window facts, so the check only rejects what is provably
inconsistent. A UA that is merely older than the real browser, while inside every window, is not
flagged. The Chrome 150 ML-DSA marker rests on one issue plus client-library PRs.
"""

from __future__ import annotations

import json
from typing import Any

from app.contract import Confidence, DetectionModule, EndpointClass, RequestContext, Signal, Verdict
from app.modules.header_order import accept_encodings, brand_major, parse_sec_ch_ua, parse_ua
from app.modules.tls_fingerprint import chrome_tls_era, classify_tls, tls_view

ZSTD_MIN = 123
PRIORITY_H2_MIN = 124
FAIL_SCORE = 80
WARN_SCORE = 40


def js_brand_major(sensor: dict[str, Any] | None) -> int | None:
    """Chromium major from the sensor's ``navigator.brands`` (``"Brand/ver"`` strings or
    ``{"brand", "version"}`` objects; also tolerates a top-level ``brands``)."""
    if not isinstance(sensor, dict):
        return None
    nav = sensor.get("navigator")
    brands = (nav.get("brands") if isinstance(nav, dict) else None) or sensor.get("brands")
    if not isinstance(brands, list):
        return None
    found: dict[str, int] = {}
    for b in brands:
        name, ver = "", ""
        if isinstance(b, str) and "/" in b:
            name, _, ver = b.rpartition("/")
        elif isinstance(b, dict):
            name, ver = str(b.get("brand", "")), str(b.get("version", ""))
        major = ver.split(".")[0]
        if name and major.isdigit():
            found[name] = int(major)
    return brand_major(found)


class VersionConsistencyModule(DetectionModule):
    slug = "version_consistency"
    title = "Cross-layer version consistency"
    description = (
        "Derives a Chrome version window from TLS and header markers and compares it with the "
        "User-Agent, sec-ch-ua and the JavaScript-reported brands."
    )
    category = "passive"
    confidence = Confidence.HIGH  # ML-DSA (150+) is MEDIUM and only yields a WARN
    applies_to = frozenset(
        {EndpointClass.PAGE, EndpointClass.PROTECTED, EndpointClass.TRANSACTIONAL}
    )

    async def _js_major(self, ctx: RequestContext) -> int | None:
        if not ctx.session_id or ctx.store is None:
            return None
        raw = await ctx.store.get(f"sensor:{ctx.session_id}")
        if not raw:
            return None
        try:
            return js_brand_major(json.loads(raw))
        except ValueError:
            return None

    async def evaluate(self, ctx: RequestContext) -> Signal:
        ua = parse_ua(ctx.user_agent)
        layers: dict[str, Any] = {
            "ua_major": ua["major"], "sech_major": None, "js_major": None,
            "tls_min": None, "tls_max": None, "hdr_min": None, "agree": True,
            "disagreements": [], "applicable": ua["chrome"],
        }
        if not ua["chrome"]:
            return self.signal(
                Verdict.SKIP, 0,
                "Not a Chromium UA: Chrome era markers do not apply", layers=layers,
            )
        ua_major: int = ua["major"]
        sech = brand_major(parse_sec_ch_ua(ctx.header("sec-ch-ua") or ""))
        js = await self._js_major(ctx)
        layers["sech_major"], layers["js_major"] = sech, js

        tls = classify_tls(ctx.ja3, ctx.ja4, ctx.header("x-ja3-grease"), ctx.header("x-tls-exts"))
        chrome_shaped = tls["family"] == "chrome"
        layers["tls_family"] = tls["family"]
        lows: list[tuple[int, str, str]] = []
        highs: list[tuple[int, str, str]] = []
        if chrome_shaped:
            era = chrome_tls_era(tls_view(ctx), chrome_shaped=True)
            lows, highs = list(era.lows), list(era.highs)
            layers["tls_min"], layers["tls_max"] = era.min_major, era.max_major
        hdr: list[tuple[int, str, str]] = []
        if "zstd" in accept_encodings(ctx.header("accept-encoding") or ""):
            hdr.append((ZSTD_MIN, "accept-encoding zstd => Chrome 123+", "high"))
        if ctx.header("priority") is not None and ctx.http_proto == "h2":
            hdr.append((PRIORITY_H2_MIN, "priority header on h2 => Chrome 124+", "high"))
        lows += hdr
        layers["hdr_min"] = max((b for b, _, _ in hdr), default=None)
        layers["min_version"] = max((b for b, _, _ in lows), default=None)
        layers["max_version"] = min((b for b, _, _ in highs), default=None)

        # (reason, tier) per violated constraint.
        problems: list[tuple[str, str]] = []
        claims = [("User-Agent", ua_major), ("sec-ch-ua", sech), ("navigator.userAgentData", js)]
        for label, major in claims:
            if major is None:
                continue
            for bound, why, tier in lows:
                if major < bound:
                    problems.append((f"{label} claims Chrome {major} but {why}", tier))
            for bound, why, tier in highs:
                if major > bound:
                    problems.append((f"{label} claims Chrome {major} but {why}", tier))
        if sech is not None and sech != ua_major:
            problems.append(
                (f"User-Agent says Chrome {ua_major} but sec-ch-ua says {sech}", "high")
            )
        if js is not None and js != ua_major:
            problems.append(
                (f"User-Agent says Chrome {ua_major} but navigator.userAgentData says {js}",
                 "high")
            )
        layers["disagreements"] = [r for r, _ in problems]
        layers["agree"] = not problems
        layers["evidence"] = [w for _, w, _ in lows] + [w for _, w, _ in highs]

        if not problems:
            has_markers = bool(lows or highs or sech is not None or js is not None)
            reason = (
                "Chrome version agrees across layers"
                if has_markers
                else "Only the User-Agent states a version: nothing to compare"
            )
            return self.signal(Verdict.PASS, 0, reason, layers=layers)
        reason = "; ".join(r for r, _ in problems)
        if all(t == "medium" for _, t in problems):
            return self.signal(
                Verdict.WARN, WARN_SCORE, reason + " [medium-confidence marker]", layers=layers
            )
        return self.signal(Verdict.FAIL, FAIL_SCORE, reason, layers=layers)
