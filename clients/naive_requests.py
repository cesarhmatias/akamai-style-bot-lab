"""Naive scraper: plain ``requests``, no browser impersonation, no challenge handling.

It keeps the cookie jar (``requests.Session``) and visits the landing page once, like any
scraper that wants a session, but runs no script, solves no challenge and sends none of the
telemetry the lab asks for. Every case is a plain request on the case's endpoint.
"""

from __future__ import annotations

import requests

from .common import CASES, LAB_URL, CaseResult, run_http_case

LABEL = "naive"


def run(cases: list[str] | None = None) -> list[CaseResult]:
    requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
    s = requests.Session()
    s.verify = False
    s.headers["X-Lab-Client"] = LABEL
    s.get(LAB_URL + "/", timeout=15)  # receives bm_sz/_abck, runs no scripts
    return [run_http_case(LABEL, s, case) for case in cases or CASES]
