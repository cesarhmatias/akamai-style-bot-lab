"""Naive scraper: plain ``requests``, no browser impersonation, no challenge handling.

It keeps the cookie jar (``requests.Session``) and visits the landing page once, like any
scraper that wants a session, but runs no script, solves no challenge and sends none of the
telemetry the lab asks for. Every case is a plain request on the case's endpoint. The two
interstitial rows are no different: it gets the page (or not) and never solves it.
"""

from __future__ import annotations

import requests

from .common import (
    CASE_TABLE,
    CASES,
    INTERSTITIAL_RETURN_TO,
    LAB_URL,
    REPORT_ID_HEADER,
    CaseResult,
    judge,
    row_env,
    run_http_case,
)

LABEL = "naive"


def new_session() -> requests.Session:
    s = requests.Session()
    s.verify = False
    s.headers["X-Lab-Client"] = LABEL
    s.get(LAB_URL + "/", timeout=15)  # receives bm_sz/_abck, runs no scripts
    return s


def interstitial_case(case: str) -> CaseResult:
    """A fresh session that never attempts the interstitial, then the protected resource."""
    s = new_session()
    r = s.get(LAB_URL + INTERSTITIAL_RETURN_TO, timeout=15)
    return judge(
        LABEL,
        case,
        r.status_code,
        r.headers.get(REPORT_ID_HEADER),
        "interstitial not attempted (no script, no regex)",
    )


def run(cases: list[str] | None = None) -> list[CaseResult]:
    requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
    s = new_session()
    out: list[CaseResult] = []
    for case in cases or CASES:
        with row_env(case):
            if CASE_TABLE[case].endpoint == "interstitial":
                out.append(interstitial_case(case))
            else:
                out.append(run_http_case(LABEL, s, case))
    return out
