"""HTTP header presence, casing and ordering check.

What real Akamai does: browsers emit headers in a stack-specific, stable order and
set (Chrome: ``sec-ch-ua*`` first, then ``upgrade-insecure-requests``, ``user-agent``,
``accept``, ``sec-fetch-*``, ``accept-encoding``, ``accept-language``). HTTP client
libraries use dict order and omit browser-only headers, and HTTP/2 mandates lowercase
names, so Title-Case on an h2 connection proves a downgraded/proxied or forged request.

How this lab detects it: ``ctx.header_order`` (original casing, wire order, from the
edge) is compared with Chrome baselines for navigation and fetch/XHR requests using a
longest-common-subsequence ratio over the headers both sides know. We also flag
missing ``sec-fetch-*`` / ``accept-language`` / ``sec-ch-ua`` (Chrome UA), uppercase
names on h2, and python-requests telltales (``Accept: */*``, ``gzip, deflate`` without
``br``, ``Connection: keep-alive``, its UA).

Scoring: (1 - similarity) * 60 + 25 missing sec-fetch-* + 15 missing accept-language
+ 10 missing sec-ch-ua (Chrome UA) + 50 uppercase on h2 + 30 requests telltales
(capped at 100). < 20 PASS, 20-49 WARN, >= 50 FAIL. No order data -> WARN 40.

How a client passes: send exactly the browser's header set in the browser's order
(impersonation libraries do this, or use a real browser).
"""

from __future__ import annotations

from app.contract import DetectionModule, RequestContext, Signal, Verdict

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
BASELINES = {"navigation": CHROME_NAV, "fetch": CHROME_FETCH}
IGNORED = {"host", "content-length", "content-type", "x-lab-client", "connection"}
SEC_FETCH = ("sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest")


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

        sims = {k: similarity(names, v) for k, v in BASELINES.items()}
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

        score = min(100, sum(scores.values()))
        d = {
            "similarity": round(sim, 2), "baseline": best, "breakdown": scores,
            "flags": flags, "observed": names,
        }
        if score < 20:
            return self.signal(Verdict.PASS, score, "Header set and order match Chrome", **d)
        reason = "; ".join(flags) or f"Header order differs from Chrome ({sim:.0%} similar)"
        verdict = Verdict.FAIL if score >= 50 else Verdict.WARN
        return self.signal(verdict, score, reason, **d)
