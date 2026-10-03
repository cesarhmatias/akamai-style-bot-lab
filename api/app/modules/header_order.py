"""HTTP header presence, order, casing and Chrome-version consistency check.

Mechanism: browsers emit headers in a stack-specific, stable order and set (Chrome: ``sec-ch-ua*``
first, then ``upgrade-insecure-requests``, ``user-agent``, ``accept``, ``sec-fetch-*``,
``accept-encoding``, ``accept-language``, ``priority``). HTTP client libraries use dict order and
omit browser-only headers. Header VALUES also change with Chrome releases, so a request can
contradict the version its own User-Agent claims.

How real Akamai uses it (audit report ``docs/research/akamai-audit-2026-10.md``, section 1.2
case 3): Akamai's detection-methods page lists "out-of-order headers and browser version
mismatches" as transparent-detection targets [HIGH]. The exact rules and thresholds are not
public; the thresholds below are the lab's own. The Chrome facts used are from Chromium
documentation [HIGH]: ``zstd`` in accept-encoding since Chrome 123, the RFC 9218 ``priority``
header since 124 on HTTP/2 and HTTP/3 only, the reduced User-Agent (``Chrome/<major>.0.0.0``)
complete since 113, ``sec-ch-ua`` brands carrying the same major as the UA. ``HeadlessChrome`` in
the UA or brands is a headless tell measured across vendors in 2026 [HIGH, secondary source].

How this lab simulates it: ``ctx.header_order`` (original casing, wire order, from the edge) is
compared with the baselines of the browser family the UA claims (Chrome by default; Firefox and
Safari baselines are MEDIUM-tier reconstructions) for navigation and fetch/XHR requests, using a
longest-common-subsequence ratio over the headers both sides know. Extra checks, each with points:

* order: (1 - similarity) * 60
* 25 missing ``sec-fetch-*``; 15 missing ``accept-language``; 10 missing ``sec-ch-ua`` (Chrome UA)
* 50 uppercase header names on h2. RFC 9113 makes these malformed on h2, so this rule rarely
  fires: a real h2 stack already lowercases, and HTTP/1.1 casing is irrelevant.
* 30 python-requests telltales (``Accept: */*``, ``gzip, deflate`` without ``br``, ``Connection``)
* 35 Chrome >= 123 UA without ``zstd`` in accept-encoding (version mismatch)
* 30 ``priority`` header on HTTP/1.1 (Chrome sends it only on h2/h3; curl_cffi known issue #785)
* 30 non-reduced desktop Chrome UA (full build ``Chrome/131.0.6778.86``, or unfrozen platform
  token) on Chrome >= 113
* 40 UA major differs from the ``sec-ch-ua`` Chromium/Chrome brand major
* 60 ``HeadlessChrome`` in the UA or in the ``sec-ch-ua`` brands (strong flag)

Score is capped at 100. < 20 PASS, 20-49 WARN, >= 50 FAIL. No order data -> WARN 40.

How a client passes: send exactly the browser's header set in the browser's order, with values
consistent with the claimed version (impersonation libraries and real browsers do; mind that an
impersonation profile freezes the version it was captured from).
"""

from __future__ import annotations

import re

from app.contract import Confidence, DetectionModule, RequestContext, Signal, Verdict

CHROME_NAV = [
    "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "upgrade-insecure-requests",
    "user-agent", "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user",
    "sec-fetch-dest", "referer", "accept-encoding", "accept-language", "cookie", "priority",
]
CHROME_FETCH = [
    "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "user-agent", "accept", "origin",
    "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "referer", "accept-encoding",
    "accept-language", "cookie", "priority",
]
# Firefox and Safari baselines (MEDIUM: reconstructed from published captures; header order is
# a lab heuristic, Akamai's exact rules are not public). Chrome stays the default for unknown UAs.
FIREFOX_NAV = [
    "user-agent", "accept", "accept-language", "accept-encoding", "referer", "cookie",
    "upgrade-insecure-requests", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site",
    "sec-fetch-user", "priority", "te",
]
FIREFOX_FETCH = [
    "user-agent", "accept", "accept-language", "accept-encoding", "referer", "origin", "cookie",
    "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "priority", "te",
]
SAFARI_NAV = [
    "sec-fetch-dest", "user-agent", "accept", "sec-fetch-site", "sec-fetch-mode", "referer",
    "accept-language", "priority", "accept-encoding", "cookie",
]
SAFARI_FETCH = [
    "sec-fetch-dest", "user-agent", "accept", "sec-fetch-site", "sec-fetch-mode", "origin",
    "referer", "accept-language", "priority", "accept-encoding", "cookie",
]
BASELINES = {"navigation": CHROME_NAV, "fetch": CHROME_FETCH}
FAMILY_BASELINES = {
    "chrome": BASELINES,
    "firefox": {"navigation": FIREFOX_NAV, "fetch": FIREFOX_FETCH},
    "safari": {"navigation": SAFARI_NAV, "fetch": SAFARI_FETCH},
}
IGNORED = {"host", "content-length", "content-type", "x-lab-client", "connection"}
SEC_FETCH = ("sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest")


_CHROME_TOKEN = re.compile(r"(?<![A-Za-z])Chrome/(\d+)\.(\d+)\.(\d+)\.(\d+)")
_HEADLESS_TOKEN = re.compile(r"HeadlessChrome/(\d+)")
_BRAND = re.compile(r'"((?:[^"\\]|\\.)*)"\s*;\s*v="(\d+)')
REDUCED_UA_SINCE = 113  # desktop reduction complete (Chromium UA-reduction plan)
ZSTD_SINCE = 123
CHROMIUM_BRANDS = ("Chromium", "Google Chrome")


def parse_ua(ua: str) -> dict:
    """Extract Chrome facts from a User-Agent: major, full build, headless, mobile."""
    m = _CHROME_TOKEN.search(ua)
    hl = _HEADLESS_TOKEN.search(ua)
    major = int(m.group(1)) if m else int(hl.group(1)) if hl else None
    return {
        "major": major,
        "full": bool(m) and m is not None and m.group(2, 3, 4) != ("0", "0", "0"),
        "headless": hl is not None,
        "chrome": major is not None,
        "mobile": "Mobile" in ua,
        "edge": "Edg/" in ua or "EdgA/" in ua,
    }


def header_family(ua: str) -> str:
    """Browser family a UA claims, for baseline selection: chrome | firefox | safari."""
    low = ua.lower()
    if re.search(r"crios/|fxios/|edgios/|iphone|ipad|ipod", low):
        return "safari"  # every iOS browser sends WebKit's header set
    if "firefox/" in low:
        return "firefox"
    if "chrome/" in low or "chromium/" in low:
        return "chrome"
    if "safari/" in low:
        return "safari"
    return "chrome"


def parse_sec_ch_ua(value: str) -> dict[str, int]:
    """``"Google Chrome";v="153", "Not_A Brand";v="8"`` -> {brand: major}."""
    return {b.replace('\\"', '"'): int(v) for b, v in _BRAND.findall(value or "")}


def brand_major(brands: dict[str, int]) -> int | None:
    """Chromium engine major from a brand list (Chromium brand first, then Google Chrome)."""
    for name in CHROMIUM_BRANDS:
        if name in brands:
            return brands[name]
    return None


def accept_encodings(value: str) -> set[str]:
    return {t.split(";")[0].strip().lower() for t in value.split(",") if t.strip()}


def lcs_len(a: list[str], b: list[str]) -> int:
    prev = [0] * (len(b) + 1)
    for x in a:
        cur = [0]
        for j, y in enumerate(b, 1):
            cur.append(prev[j - 1] + 1 if x == y else max(prev[j], cur[j - 1]))
        prev = cur
    return prev[-1]


def similarity(observed: list[str], baseline: list[str]) -> float:
    """LCS ratio over headers both sides know (so extra headers do not hurt)."""
    known = [h for h in observed if h in baseline]
    if not known:
        return 0.0
    ref = [h for h in baseline if h in known]
    return lcs_len(known, ref) / len(known)


class HeaderOrderModule(DetectionModule):
    slug = "header_order"
    title = "Header order and casing"
    description = "Compares header set, order and casing with a Chrome request baseline."
    category = "passive"
    confidence = Confidence.HIGH

    @staticmethod
    def _version_checks(ctx: RequestContext, scores: dict[str, int], flags: list[str]) -> None:
        """Chrome version-consistency checks (audit 1.2 case 3)."""
        ua = parse_ua(ctx.user_agent)
        brands = parse_sec_ch_ua(ctx.header("sec-ch-ua") or "")
        major = ua["major"]
        if ctx.header("priority") is not None and ctx.http_proto != "h2":
            scores["priority_on_http1"] = 30
            flags.append("priority header on HTTP/1.1 (Chrome sends it only on h2/h3 since 124)")
        if ua["headless"] or any("headless" in b.lower() for b in brands):
            scores["headless_token"] = 60
            where = "User-Agent" if ua["headless"] else "sec-ch-ua brands"
            flags.append(f"HeadlessChrome token in {where}")
        if major is None or ua["headless"]:
            return
        if major >= ZSTD_SINCE and "zstd" not in accept_encodings(
            ctx.header("accept-encoding") or ""
        ):
            scores["missing_zstd"] = 35
            flags.append(f"Chrome {major} UA without zstd in accept-encoding (sent since 123)")
        if major >= REDUCED_UA_SINCE and not ua["mobile"]:
            low = ctx.user_agent
            unfrozen = ("Windows NT" in low and "Windows NT 10.0" not in low) or (
                "Macintosh" in low and "10_15_7" not in low
            )
            if ua["full"] or unfrozen:
                scores["reduced_ua"] = 30
                flags.append(
                    f"Chrome {major} UA is not the reduced Chrome/{major}.0.0.0 form"
                    + (" (unfrozen platform token)" if unfrozen and not ua["full"] else "")
                )
        sech = brand_major(brands)
        if sech is not None and sech != major:
            scores["ua_sec_ch_ua_major"] = 40
            flags.append(f"UA says Chrome {major} but sec-ch-ua says {sech}")

    async def evaluate(self, ctx: RequestContext) -> Signal:
        raw = [h for h in ctx.header_order if h]
        if not raw:
            return self.signal(Verdict.WARN, 40, "No header order available (not via edge?)")
        names = [h.lower() for h in raw if h.lower() not in IGNORED]
        present = set(names)
        ua = ctx.user_agent.lower()
        chrome_ua = "chrome/" in ua
        scores: dict[str, int] = {}
        flags: list[str] = []

        family = header_family(ctx.user_agent)
        sims = {k: similarity(names, v) for k, v in FAMILY_BASELINES[family].items()}
        best, sim = max(sims.items(), key=lambda kv: kv[1])
        scores["order"] = round((1 - sim) * 60)

        if not all(h in present for h in SEC_FETCH):
            scores["missing_sec_fetch"] = 25
            flags.append("missing sec-fetch-* headers")
        if "accept-language" not in present:
            scores["missing_accept_language"] = 15
            flags.append("missing accept-language")
        if chrome_ua and "sec-ch-ua" not in present:
            scores["missing_sec_ch_ua"] = 10
            flags.append("Chrome UA without sec-ch-ua")
        if ctx.http_proto == "h2" and any(h != h.lower() for h in raw):
            scores["h2_uppercase"] = 50
            flags.append("Title-Case header names on HTTP/2 (impossible)")

        accept = ctx.header("accept") or ""
        tell: list[str] = []
        if "python-requests" in ua or "python-urllib" in ua:
            tell.append("python UA")
        if accept.strip() == "*/*" and "sec-fetch-mode" not in present:
            tell.append("Accept: */*")
        if (ctx.header("accept-encoding") or "").replace(" ", "") == "gzip,deflate":
            tell.append("accept-encoding without br")
        if (ctx.header("connection") or "").lower() == "keep-alive" or any(
            h.lower() == "connection" for h in raw
        ):
            tell.append("Connection header")
        if len(tell) >= 2 or "python UA" in tell:
            scores["requests_telltales"] = 30
            flags.append("python-requests telltales: " + ", ".join(tell))

        self._version_checks(ctx, scores, flags)

        score = min(100, sum(scores.values()))
        d = {
            "similarity": round(sim, 2), "baseline": best, "baseline_family": family,
            "breakdown": scores, "flags": flags, "observed": names,
        }
        if score < 20:
            return self.signal(
                Verdict.PASS, score, f"Header set and order match {family.title()}", **d
            )
        reason = "; ".join(flags) or (
            f"Header order differs from {family.title()} ({sim:.0%} similar)"
        )
        verdict = Verdict.FAIL if score >= 50 else Verdict.WARN
        return self.signal(verdict, score, reason, **d)
