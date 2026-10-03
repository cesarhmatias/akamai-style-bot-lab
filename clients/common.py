"""Shared configuration, result types, control-plane helpers and the case table.

Every case is judged from its SIGNAL in the score report, never from the HTTP status: the lab
answers with 200 for ``monitor`` / ``delay`` / ``serve_alternate`` and with 428 or an HTML page
for a challenge, so the status says nothing about the detection. Each scored response carries
``X-Lab-Report-Id``; ``GET /api/requests/{id}`` returns the report and :func:`judge` picks the
signal of the module the case is about.

Cell semantics (``CaseResult.cell``): ``pass`` (verdict pass or skip), ``warn`` or ``fail``
(verdict fail or block; a missing report or signal also counts as fail).
"""

from __future__ import annotations

import contextlib
import os
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from typing import Any

import requests

LAB_URL = os.environ.get("LAB_URL", "https://localhost:8443").rstrip("/")
CONTROL_URL = os.environ.get("CONTROL_URL", "http://localhost:3000").rstrip("/")
REPORT_ID_HEADER = "x-lab-report-id"
USERNAME = "alice@example.com"
MOBILE_PATH = "/mobile/api/profile"

CLIENTS: list[str] = ["naive", "curl_cffi", "playwright"]


@dataclass(frozen=True)
class Case:
    """One matrix row. ``module`` is the module whose signal is judged; ``endpoint`` is the
    endpoint class the case is exercised on (protected | login | checkout | mobile |
    interstitial)."""

    name: str
    module: str
    endpoint: str
    summary: str


# Order matters: it is the matrix order AND the order every client runs the cases in, because
# a few modules keep per-session state (avf_stepup arms after a strict-segment request).
_CASES = [
    Case("tls_fingerprint", "tls_fingerprint", "protected", "TLS ClientHello vs claimed UA"),
    Case("h2_fingerprint", "h2_fingerprint", "protected", "HTTP/2 SETTINGS/WINDOW_UPDATE/order"),
    Case("header_order", "header_order", "protected", "header set, order and version values"),
    Case(
        "version_consistency", "version_consistency", "protected", "UA vs TLS vs hints vs JS major"
    ),
    Case("known_bots", "known_bots", "protected", "crawler impersonation (no client claims one)"),
    Case("ip_reputation", "ip_reputation", "protected", "request rate and reputation"),
    Case("session_validation", "session_validation", "protected", "page then XHR chain"),
    Case("abck_cookie", "abck_cookie", "protected", "_abck validated server-side"),
    Case("sensor_data", "sensor_data", "protected", "sensor payload posted"),
    Case("js_integrity", "js_integrity", "protected", "automation artifacts in the sensor"),
    Case("behavioral", "behavioral", "protected", "interaction telemetry"),
    Case("proof_of_work", "proof_of_work", "protected", "hard sha256 proof of work (sec_cpt)"),
    Case("pixel_challenge", "pixel_challenge", "protected", "pixel beacon from the page HTML"),
    Case("sbsd_challenge", "sbsd_challenge", "protected", "SBSD op-chain challenge"),
    Case("interactive_challenge", "interactive_challenge", "protected", "interactive tile game"),
    Case("avf_stepup", "avf_stepup", "protected", "on-demand step-up data (WebGL/audio/fonts)"),
    Case("inline_telemetry", "inline_telemetry", "checkout", "request-bound inline telemetry"),
    Case("account_protector", "account_protector", "login", "login risk against the profile"),
    Case("native_app", "native_app", "mobile", "native-app sensor header on /mobile/api"),
    # The two rows below judge the proof_of_work signal AFTER an interstitial attempt, in a
    # fresh session (the hard PoW would win by precedence otherwise).
    Case(
        "pow_interstitial",
        "proof_of_work",
        "interstitial",
        "basic cookieless interstitial (a regex can solve it)",
    ),
    Case(
        "pow_interstitial_hardened",
        "proof_of_work",
        "interstitial",
        "same interstitial with the hardened, randomized arithmetic shape",
    ),
]
CASE_TABLE: dict[str, Case] = {c.name: c for c in _CASES}
CASES: list[str] = [c.name for c in _CASES]

# Modules that are OFF by default (default_enabled = False and/or flag gated, confidence LOW).
# They never join the default matrix; RESULTS.md lists them with the reason.
EXCLUDED: dict[str, str] = {
    "botnet_cluster": "needs many source IPs presenting one fingerprint; one container IP "
    "cannot form a cluster (LOW, flag botnet_cluster)",
    "tcp_fingerprint": "documented stub: always SKIP, needs raw SYN capture the Docker "
    "topology cannot give (LOW, flag tcp_fingerprint)",
    "visitor_prioritization": "a waiting-room gate, not a detection: evaluate() is always SKIP "
    "(LOW, flag akavpau_cookie_name)",
}


@dataclass
class CaseResult:
    client: str
    case: str
    endpoint: str = ""
    status: int = 0
    verdict: str = ""  # pass | warn | fail | block | skip | none (no report / signal)
    score: int = -1
    reason: str = ""
    action: str = ""  # report.action (monitor, challenge, deny, serve_alternate, ...)
    segment: str = ""  # report.segment (human, cautious, strict, aggressive)
    report_id: str = ""
    note: str = ""  # what the CLIENT did (e.g. "verify accepted"), not what the lab saw
    fingerprint: dict[str, str] = field(default_factory=dict)
    user_agent: str = ""

    @property
    def cell(self) -> str:
        if self.verdict in ("pass", "skip"):
            return "pass"
        if self.verdict == "warn":
            return "warn"
        return "fail"

    @property
    def passed(self) -> bool:
        return self.cell == "pass"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["cell"] = self.cell
        return d


# ------------------------------------------------------------------------ control plane


def _control(method: str, path: str, **kw: Any) -> requests.Response:
    resp = requests.request(method, f"{CONTROL_URL}{path}", timeout=15, **kw)
    resp.raise_for_status()
    return resp


def reset_lab() -> None:
    """Clear sessions, reputation, feed and request history (toggles/flags/policy are kept)."""
    _control("POST", "/api/reset")


def set_module(slug: str, enabled: bool) -> None:
    _control("PUT", f"/api/modules/{slug}", json={"enabled": enabled})


def get_modules() -> list[dict[str, Any]]:
    data: list[dict[str, Any]] = _control("GET", "/api/modules").json()
    return data


def get_flags() -> dict[str, bool]:
    return {f["name"]: bool(f["value"]) for f in _control("GET", "/api/flags").json()}


def set_flag(name: str, value: bool) -> None:
    _control("PUT", f"/api/flags/{name}", json={"value": value})


def get_challenge_provider() -> str:
    return str(_control("GET", "/api/policy").json()["params"]["challenge_provider"])


def set_challenge_provider(provider: str) -> None:
    _control("PUT", "/api/policy", json={"params": {"challenge_provider": provider}})


def recent_reports(limit: int = 100) -> list[dict[str, Any]]:
    data: list[dict[str, Any]] = _control("GET", f"/api/requests?limit={limit}").json()
    return data


def check_case_table() -> None:
    """Fail loudly when the lab gained a module the harness has no case (or exclusion) for."""
    slugs = {m["slug"] for m in get_modules()}
    covered = {c.module for c in _CASES} | set(EXCLUDED)
    extra = sorted(slugs - covered)
    missing = sorted(covered - slugs)
    if extra or missing:
        raise SystemExit(
            f"case table out of sync with /api/modules: no case for {extra}, "
            f"unknown module {missing}"
        )


def prepare_lab() -> dict[str, Any]:
    """Pin the toggles the matrix assumes (default-on modules ON, EXCLUDED ones OFF) and
    return a snapshot of what was there so :func:`restore_lab` can put it back."""
    check_case_table()
    snapshot: dict[str, Any] = {
        "modules": {m["slug"]: bool(m["enabled"]) for m in get_modules()},
        "flags": get_flags(),
        "provider": get_challenge_provider(),
    }
    wanted = {c.module for c in _CASES}
    for slug in snapshot["modules"]:
        set_module(slug, slug in wanted)
    return snapshot


def restore_lab(snapshot: dict[str, Any]) -> None:
    for slug, enabled in snapshot["modules"].items():
        set_module(slug, enabled)
    for name, value in snapshot["flags"].items():
        if get_flags().get(name) != value:
            set_flag(name, value)
    set_challenge_provider(snapshot["provider"])


# Per-row lab configuration, applied only while that row runs and restored afterwards.
ROW_FLAGS: dict[str, dict[str, bool]] = {
    # the cookieless gate is what serves a cookie-less browser the interstitial page
    "pow_interstitial": {"pow_cookieless_gate": True},
    "pow_interstitial_hardened": {"pow_cookieless_gate": True, "pow_interstitial_hardened": True},
}
INTERSTITIAL_RETURN_TO = "/protected/proof_of_work"
INTERSTITIAL_PATH = f"/akam/proof_of_work/interstitial?return_to={INTERSTITIAL_RETURN_TO}"
ROW_PROVIDER: dict[str, str] = {"interactive_challenge": "interactive"}


@contextlib.contextmanager
def row_env(case: str) -> Iterator[None]:
    """Apply the flags / challenge provider a row needs, restore the previous values on exit."""
    flags = ROW_FLAGS.get(case, {})
    provider = ROW_PROVIDER.get(case)
    before_flags = get_flags()
    before_provider = get_challenge_provider()
    try:
        for name, value in flags.items():
            set_flag(name, value)
        if provider:
            set_challenge_provider(provider)
        yield
    finally:
        for name in flags:
            set_flag(name, before_flags[name])
        if provider:
            set_challenge_provider(before_provider)


# ------------------------------------------------------------------------------- judging


def judge(client: str, case: str, status: int, report_id: str | None, note: str = "") -> CaseResult:
    """Build the result of ``case`` from the report behind ``report_id`` (X-Lab-Report-Id)."""
    spec = CASE_TABLE[case]
    res = CaseResult(client, case, spec.endpoint, status, verdict="none", note=note)
    if not report_id:
        res.reason = "no X-Lab-Report-Id on the response (request was not scored)"
        return res
    resp = requests.get(f"{CONTROL_URL}/api/requests/{report_id}", timeout=15)
    if resp.status_code != 200:
        res.reason = f"report {report_id} not found"
        return res
    report: dict[str, Any] = resp.json()
    res.report_id = report_id
    res.action = str(report.get("action", ""))
    res.segment = str(report.get("segment", ""))
    res.fingerprint = {k: str(v) for k, v in (report.get("fingerprint") or {}).items()}
    res.user_agent = str(report.get("user_agent", ""))
    sig = next((s for s in report.get("signals", []) if s.get("module") == spec.module), None)
    if sig is None:
        res.reason = f"no {spec.module} signal in report {report_id}"
        return res
    res.verdict = str(sig["verdict"])
    res.score = int(sig["score"])
    res.reason = str(sig["reason"])
    return res


# ------------------------------------------------------------- shared pure-HTTP driver


def run_http_case(
    label: str,
    session: Any,
    case: str,
    *,
    nav_headers: dict[str, str] | None = None,
    api_headers: dict[str, str] | None = None,
    mobile_headers: dict[str, str] | None = None,
    note: str = "",
) -> CaseResult:
    """Exercise ``case`` on its endpoint class with a requests-style ``session``
    (``requests`` and ``curl_cffi`` both fit). The caller supplies the header sets so each
    client keeps its own representative configuration."""
    spec = CASE_TABLE[case]
    if spec.endpoint == "protected":
        r = session.get(f"{LAB_URL}/protected/{case}", headers=nav_headers, timeout=30)
    elif spec.endpoint == "login":
        r = session.post(
            f"{LAB_URL}/api/login",
            json={"username": USERNAME, "password": "correct horse battery staple"},
            headers=api_headers,
            timeout=30,
        )
    elif spec.endpoint == "checkout":
        r = session.post(
            f"{LAB_URL}/api/checkout", json={"qty": 1}, headers=api_headers, timeout=30
        )
    elif spec.endpoint == "mobile":
        r = session.get(f"{LAB_URL}{MOBILE_PATH}", headers=mobile_headers, timeout=30)
    else:  # pragma: no cover - table guard
        raise ValueError(f"{case}: endpoint {spec.endpoint} needs a client-specific flow")
    return judge(label, case, r.status_code, r.headers.get(REPORT_ID_HEADER), note)
