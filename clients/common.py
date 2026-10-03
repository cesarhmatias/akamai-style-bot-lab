"""Shared configuration, result types and control-plane helpers for the lab clients."""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from typing import Any

import requests

LAB_URL = os.environ.get("LAB_URL", "https://localhost:8443").rstrip("/")
CONTROL_URL = os.environ.get("CONTROL_URL", "http://localhost:3000").rstrip("/")

CASES: list[str] = [
    "tls_fingerprint",
    "h2_fingerprint",
    "header_order",
    "abck_cookie",
    "sensor_data",
    "proof_of_work",
    "pixel_challenge",
    "sbsd_challenge",
    "behavioral",
    "ip_reputation",
]
CLIENTS: list[str] = ["naive", "curl_cffi", "playwright"]


@dataclass
class CaseResult:
    client: str
    case: str
    passed: bool
    status: int
    verdict: str = ""
    score: int = -1
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def protected_url(case: str) -> str:
    return f"{LAB_URL}/protected/{case}"


def _control(method: str, path: str, **kw: Any) -> requests.Response:
    resp = requests.request(method, f"{CONTROL_URL}{path}", timeout=15, **kw)
    resp.raise_for_status()
    return resp


def reset_lab() -> None:
    """Clear sessions, reputation, feed and request history (toggles are preserved)."""
    _control("POST", "/api/reset")


def set_module(slug: str, enabled: bool) -> None:
    _control("PUT", f"/api/modules/{slug}", json={"enabled": enabled})


def enable_all(cases: list[str] | None = None) -> None:
    for slug in cases or CASES:
        set_module(slug, True)


def recent_reports(limit: int = 100) -> list[dict[str, Any]]:
    data: list[dict[str, Any]] = _control("GET", f"/api/requests?limit={limit}").json()
    return data


def result_from_report(client: str, case: str, status: int, report: dict[str, Any]) -> CaseResult:
    sig = next((s for s in report.get("signals", []) if s.get("module") == case), None)
    if sig is None:
        return CaseResult(client, case, status == 200, status, reason="no signal in report")
    return CaseResult(
        client, case, status == 200, status, sig["verdict"], int(sig["score"]), sig["reason"]
    )


def result_from_response(
    client: str, case: str, status: int, body: Any, label: str | None = None
) -> CaseResult:
    """Build a result from a /protected/<case> response.

    A blocked navigation (Accept: text/html) gets an HTML interstitial without the report, so
    in that case the newest matching report is looked up through the control plane.
    """
    if isinstance(body, dict) and "report" in body:
        return result_from_report(client, case, status, body["report"])
    for rep in recent_reports():
        if rep.get("path") == f"/protected/{case}" and rep.get("client_label") == (label or client):
            return result_from_report(client, case, status, rep)
    return CaseResult(client, case, status == 200, status, reason="report not found")
