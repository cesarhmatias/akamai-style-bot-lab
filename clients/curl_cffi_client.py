"""curl_cffi with a pinned Chrome impersonation profile.

Real Chrome TLS/HTTP2/header stack and cookie persistence, plus pure-HTTP solvers for the
proof-of-work (hard sha256) and pixel challenges. No JavaScript is executed, so the sensor,
``_abck`` validation, SBSD and behavioral cases are expected to fail.
"""

from __future__ import annotations

import hashlib
from typing import Any

from curl_cffi import requests as cffi

from .common import CASES, LAB_URL, CaseResult, protected_url, result_from_response

LABEL = "curl_cffi"
IMPERSONATE = "chrome131"
NAV_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,"
    "image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Language": "en-US,en;q=0.9",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-User": "?1",
    "Sec-Fetch-Dest": "document",
    "X-Lab-Client": LABEL,
}
POW_MAX_ITERATIONS = 5_000_000


def solve_pow(nonce: str, difficulty: int) -> int:
    prefix = "0" * difficulty
    for counter in range(POW_MAX_ITERATIONS):
        if hashlib.sha256(f"{nonce}{counter}".encode()).hexdigest().startswith(prefix):
            return counter
    raise RuntimeError("proof of work not solved")


def _api_headers() -> dict[str, str]:
    return {
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": LAB_URL + "/",
        "Origin": LAB_URL,
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "X-Lab-Client": LABEL,
    }


def solve_proof_of_work(s: Any) -> bool:
    base = LAB_URL + "/akam/proof_of_work"
    ch = s.get(f"{base}/challenge?variant=hard", headers=_api_headers()).json()
    counter = solve_pow(ch["nonce"], int(ch["difficulty"]))
    r = s.post(
        f"{base}/verify",
        json={"challenge_id": ch["challenge_id"], "answer": counter},
        headers=_api_headers(),
    )
    return bool(r.status_code == 200 and r.json().get("ok"))


def solve_pixel(s: Any) -> bool:
    base = LAB_URL + "/akam/pixel_challenge"
    cfg = s.get(f"{base}/config", headers=_api_headers()).json()
    s.get(
        f"{base}/pixel.gif",
        params={"ap": cfg["pixel_id"], "t": cfg["token"], "_": "1"},
        headers={**_api_headers(), "Accept": "image/avif,image/webp,image/apng,*/*;q=0.8",
                 "Sec-Fetch-Dest": "image", "Sec-Fetch-Mode": "no-cors"},
    )
    r = s.post(
        f"{base}/beacon",
        json={"ap": cfg["pixel_id"], "t": cfg["token"], "ts": 1},
        headers=_api_headers(),
    )
    return bool(r.status_code == 200 and r.json().get("ok"))


def run(cases: list[str] | None = None) -> list[CaseResult]:
    out: list[CaseResult] = []
    with cffi.Session(impersonate=IMPERSONATE, verify=False) as s:
        s.get(LAB_URL + "/", headers=NAV_HEADERS)
        solve_proof_of_work(s)
        solve_pixel(s)
        for case in cases or CASES:
            r = s.get(protected_url(case), headers={**NAV_HEADERS, "Sec-Fetch-Site": "same-origin"})
            try:
                body = r.json()
            except ValueError:
                body = None
            out.append(result_from_response(LABEL, case, r.status_code, body))
    return out
