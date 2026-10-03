"""Naive scraper: plain ``requests``, no browser impersonation, no challenge handling."""

from __future__ import annotations

import requests

from .common import CASES, LAB_URL, CaseResult, protected_url, result_from_response

LABEL = "naive"


def run(cases: list[str] | None = None) -> list[CaseResult]:
    requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
    s = requests.Session()
    s.verify = False
    s.headers["X-Lab-Client"] = LABEL
    s.get(LAB_URL + "/", timeout=15)  # receives bm_sz/_abck, runs no scripts
    out: list[CaseResult] = []
    for case in cases or CASES:
        r = s.get(protected_url(case), timeout=15)
        try:
            body = r.json()
        except ValueError:
            body = None
        out.append(result_from_response(LABEL, case, r.status_code, body))
    return out
