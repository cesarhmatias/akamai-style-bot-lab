"""``session_validation``: HTML navigations versus XHR/JSON calls per session (audit report §2.7).

Mechanism
---------
Cookie-database descriptions (worded like vendor documentation, [S, weak]) say ``bm_sv`` is
"used as part of the session validation detection method to keep track of the number of HTML
page requests and AJAX requests that the client makes" (2 h), and ``bm_mi`` is used "to confirm
that requests are coming from a real browser using the browser validation detection method"
(2 h). The detection NAMES and cookie purposes are LOW confidence (the Bot Manager API reference
is login-gated, report §3.1); the concept (catching API-only scrapers that never load pages)
is MEDIUM.

How the lab simulates it
------------------------
Every evaluated request is classified from the browser-set fetch metadata (``sec-fetch-mode`` /
``sec-fetch-dest``, falling back to ``accept``): ``nav`` (HTML navigation) or ``xhr``
(fetch/XHR/JSON). Counters live in ``sv:nav:{sid}`` and ``sv:xhr:{sid}``. Findings:

* a JSON/XHR/transactional call in a session that never loaded a page (FAIL);
* an XHR whose chain is broken: ``Sec-Fetch-Site`` not ``same-origin``/``same-site``, or no
  same-origin ``Referer`` (FAIL; the ``Referer`` host is only compared when the browser did not
  assert ``same-origin`` itself);
* a browser User-Agent with no ``Sec-Fetch-*`` metadata at all (WARN: browsers omit it on plain
  HTTP to non-localhost origins);
* a very high XHR-to-navigation ratio (WARN).

A real browser flow (landing page navigation, then protected/transactional calls from that
page) passes. A pure-HTTP client that loads ``/`` first with a browser's fetch-metadata headers
also passes this check: the module catches API-only clients, not header spoofing.

Flag ``bm_sv_cookies`` (LOW, unverified, vendor/cookie-database sourced; default off)
-------------------------------------------------------------------------------------
Issue ``bm_sv`` and ``bm_mi`` (lab-defined MAC values, see ``app.session.extra_cookies``) and
require ``bm_sv`` on XHR requests. Cookies cannot be set from ``evaluate``, so the response
agent's ``finalize_cookies`` must issue ``extra_cookies(sid, flags)`` for each cookie the request
lacks. Until it does, flag-on XHR requests only WARN.

How a client passes
-------------------
Load a page first (so the session has a navigation), then call APIs from that page's origin
with ``Sec-Fetch-Site: same-origin`` and a same-origin ``Referer``.

Limits
------
Fetch-metadata headers are trivially forged by non-browser clients; thresholds are lab-defined.
"""

from __future__ import annotations

import hmac
import re
from typing import ClassVar
from urllib.parse import urlsplit

from app.contract import (
    Confidence,
    DetectionModule,
    EndpointClass,
    FlagSpec,
    RequestContext,
    Signal,
    Verdict,
)
from app.session import COOKIE_BM_SV, SESSION_TTL, bm_sv_value

FAIL_AT = 50
WARN_AT = 20
MAX_XHR_PER_NAV = 20
_BROWSER_UA = re.compile(r"Chrome/\d+|Firefox/\d+|Version/\d+.*Safari/")


def classify(ctx: RequestContext) -> tuple[str, bool]:
    """``(kind, has_fetch_metadata)`` with kind ``nav`` or ``xhr``."""
    mode = (ctx.header("sec-fetch-mode") or "").lower()
    if mode:
        return ("nav" if mode in {"navigate", "nested-navigate"} else "xhr"), True
    accept = (ctx.header("accept") or "").lower()
    return ("nav" if "text/html" in accept else "xhr"), False


class SessionValidationModule(DetectionModule):
    slug: ClassVar[str] = "session_validation"
    title: ClassVar[str] = "Session validation (navigations vs XHR)"
    description: ClassVar[str] = (
        "Counts HTML navigations and XHR/JSON calls per session; flags API-only sessions and "
        "broken Referer / Sec-Fetch-Site chains."
    )
    category: ClassVar[str] = "behavioral"
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    applies_to: ClassVar[frozenset[EndpointClass]] = frozenset(
        {EndpointClass.PAGE, EndpointClass.PROTECTED, EndpointClass.TRANSACTIONAL}
    )
    flags: ClassVar[list[FlagSpec]] = [
        FlagSpec(
            name="bm_sv_cookies",
            description="Issue bm_sv / bm_mi cookies and require bm_sv on XHR requests.",
            confidence=Confidence.LOW,
            source="report §2.7, §3.1 (bm_sv/bm_mi names and purposes: cookie databases, weak)",
        )
    ]

    async def evaluate(self, ctx: RequestContext) -> Signal:
        sid, store = ctx.session_id, ctx.store
        kind, has_meta = classify(ctx)
        navs = xhrs = 0
        if sid and store is not None:
            if kind == "nav":
                navs = await store.incr(f"sv:nav:{sid}", SESSION_TTL)
                await store.set(f"sv:lastnav:{sid}", ctx.path, SESSION_TTL)
                xhrs = int(await store.get(f"sv:xhr:{sid}") or 0)
            else:
                xhrs = await store.incr(f"sv:xhr:{sid}", SESSION_TTL)
                navs = int(await store.get(f"sv:nav:{sid}") or 0)

        problems: list[tuple[int, str]] = []
        if (kind == "xhr" or ctx.endpoint_class == EndpointClass.TRANSACTIONAL) and navs == 0:
            problems.append((80, "JSON/transactional call in a session with no page navigation"))
        if kind == "xhr" and has_meta:
            site = (ctx.header("sec-fetch-site") or "").lower()
            if site not in {"same-origin", "same-site"}:
                problems.append(
                    (60, f"XHR with Sec-Fetch-Site '{site or 'missing'}' (broken chain)")
                )
            referer = ctx.header("referer") or ""
            host = ctx.header("host") or ""
            ref_host = urlsplit(referer).netloc
            if not referer:
                problems.append((55, "XHR without a Referer (broken chain)"))
            elif host and ref_host != host and site != "same-origin":
                problems.append((55, "XHR Referer is not same-origin (broken chain)"))
        if not has_meta and _BROWSER_UA.search(ctx.user_agent):
            problems.append((30, "browser User-Agent without Sec-Fetch-* metadata"))
        if navs and xhrs > MAX_XHR_PER_NAV * navs:
            problems.append((40, f"{xhrs} XHR calls for {navs} page navigations"))
        if ctx.flag("bm_sv_cookies") and kind == "xhr" and sid:
            have = ctx.cookies.get(COOKIE_BM_SV, "")
            if not (have and hmac.compare_digest(have, bm_sv_value(sid))):
                problems.append((30, "bm_sv cookie missing or invalid"))

        details = {"kind": kind, "navigations": navs, "xhr": xhrs, "fetch_metadata": has_meta}
        if not problems:
            return self.signal(Verdict.PASS, 0, "navigation/XHR chain consistent", **details)
        scores = sorted((s for s, _ in problems), reverse=True)
        score = min(100, round(scores[0] + 0.25 * sum(scores[1:])))
        verdict = (
            Verdict.FAIL if score >= FAIL_AT else Verdict.WARN if score >= WARN_AT else Verdict.PASS
        )
        return self.signal(verdict, score, "; ".join(t for _, t in problems), **details)
