"""curl_cffi with a pinned Chrome impersonation profile, no JavaScript.

Representative default configuration, NOT tuned to pass: ``impersonate="chrome131"`` stays
pinned even though the profile is about 23 Chrome majors old (the audit's point: an
impersonation profile freezes one release, so its UA/hints/TLS drift behind real Chrome).

What it does with pure HTTP and no script engine:

* real Chrome TLS/HTTP2/header stack and a cookie jar;
* ``proof_of_work``: ``GET /akam/proof_of_work/challenge?variant=hard``, solve the sha256
  puzzle, wait at least ``chlg_duration`` seconds after the challenge was issued, POST the
  answer to ``/akam/proof_of_work/verify`` and keep the ``sec_cpt`` cookie;
* ``pixel_challenge``: parse the landing page for ``bazadebezolkohpepadr=<int>`` and the
  ``/akam/<n>/<hex8>`` script path, then POST ``p=<ts_ms>.<digest>`` to
  ``/akam/<n>/pixel_<hex8>`` (the digest recipe is the pixel module's documented, lab-defined
  one, which the served script also computes);
* the BASIC cookieless interstitial, with regexes only (no JavaScript is run): a cookie-less
  navigation to the protected resource gets the page from the gate (or, with the gate off, it
  asks for it on demand); it reads ``var i = N;``, ``var j = i + Number("A" + "B");`` and the
  ``"bm-verify"`` token, POSTs ``{"bm-verify": token, "pow": N + int(A+B)}`` to
  ``/_sec/verify?provider=interstitial`` and then reloads the resource, as the page does. It
  follows a ``location`` only when the reply has one (LOW flag) and only if it is same-origin.
  When the page does not look like that (the hardened variant) it stops with a clear reason
  instead of guessing;
* login / checkout WITHOUT inline telemetry (it cannot run the page script that attaches it);
* ``native_app``: acts as a native mobile app. It re-implements the lab's documented
  ``X-acf-sensor-data`` header (shared lab app key, synthetic motion stream) because an app
  HTTP stack is the closest thing this client models. The key is a published lab constant,
  not a secret: see RESULTS.md for why that makes the cell a statement about the lab's
  documented sample key rather than about real SDKs.

It does not run the sensor, the SBSD op chain or the tile game, so those cases fail by design.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import random
import re
import time
from typing import Any
from urllib.parse import urljoin, urlsplit

from curl_cffi import requests as cffi

from .common import (
    CASE_TABLE,
    CASES,
    INTERSTITIAL_PATH,
    INTERSTITIAL_RETURN_TO,
    LAB_URL,
    MOBILE_PATH,
    REPORT_ID_HEADER,
    CaseResult,
    judge,
    row_env,
    run_http_case,
)

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
POW_MARGIN_S = 0.3  # slack on top of chlg_duration (clock and network jitter)
# Lab native-app sample key (documented constant in the native_app module, NOT a secret).
APP_KEY = "lab-native-app-key-v1"
APP_VERSION = "4.2.0"
SDK_VERSION = "3.1.0"
NATIVE_SEED = 7


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
    """Hard sha256 PoW over plain HTTP: solve, wait out ``chlg_duration``, verify."""
    base = LAB_URL + "/akam/proof_of_work"
    t_ask = time.monotonic()  # taken BEFORE the request so the server-side age is >= ours
    ch = s.get(f"{base}/challenge?variant=hard", headers=_api_headers()).json()
    counter = solve_pow(ch["nonce"], int(ch["difficulty"]))
    remaining = float(ch["chlg_duration"]) + POW_MARGIN_S - (time.monotonic() - t_ask)
    if remaining > 0:
        time.sleep(remaining)
    r = s.post(
        f"{base}/verify",
        json={"token": ch["token"], "answer": counter},
        headers=_api_headers(),
    )
    return bool(r.status_code == 200 and r.json().get("ok"))  # sec_cpt is kept by the jar


def parse_pixel(html: str) -> tuple[int, str, str] | None:
    """(value, n, hex8) from the page: the ``bazadebezolkohpepadr`` global and script path."""
    value = re.search(r"bazadebezolkohpepadr\s*=\s*(\d+)\s*;", html)
    path = re.search(r'src="/akam/(\d+)/([0-9a-f]{8})"', html)
    if not (value and path):
        return None
    return int(value.group(1)), path.group(1), path.group(2)


def solve_pixel(s: Any, html: str) -> bool:
    found = parse_pixel(html)
    sid = s.cookies.get("bm_sz")
    if found is None or not sid:
        return False
    value, n, hex8 = found
    ts_ms = int(time.time() * 1000)
    digest = hashlib.sha256(f"{value}.{hex8}.{ts_ms}.{sid}".encode()).hexdigest()[:32]
    r = s.post(
        f"{LAB_URL}/akam/{n}/pixel_{hex8}",
        data={"p": f"{ts_ms}.{digest}"},
        headers=_api_headers(),
    )
    return bool(r.status_code == 200 and r.json().get("ok"))


# The observed basic interstitial shape. A fixed regex is all this client has, which is the point
# of the hardened variant: it randomizes the shape so these stop matching.
_I_RE = re.compile(r"var\s+i\s*=\s*(\d+)\s*;")
_J_RE = re.compile(r'var\s+j\s*=\s*i\s*\+\s*Number\("(\d+)"\s*\+\s*"(\d+)"\)')
_TOKEN_RE = re.compile(r'"bm-verify"\s*:\s*"([^"]+)"')


def same_origin_path(location: str) -> str | None:
    """The path (and query) of ``location`` when it stays on the lab's origin, else None."""
    if "\\" in location or any(ord(c) < 32 for c in location):  # browsers read \ as /
        return None
    target = urljoin(LAB_URL + "/", location)
    a, b = urlsplit(target), urlsplit(LAB_URL)
    if (a.scheme, a.netloc) != (b.scheme, b.netloc):
        return None
    return a.path + (f"?{a.query}" if a.query else "")


def solve_interstitial(s: Any) -> tuple[Any | None, str]:
    """Regex-only solver for the basic cookieless interstitial.

    Returns ``(response_to_the_reload_or_followed_location | None, note)``. Never raises: a page
    the regexes do not match, a rejected verify or a cross-origin ``location`` end in a clear
    note."""
    html = s.get(LAB_URL + INTERSTITIAL_RETURN_TO, headers=NAV_HEADERS).text  # cookie-less visit
    if '"bm-verify"' not in html:  # the gate is off: ask for the page on demand
        html = s.get(LAB_URL + INTERSTITIAL_PATH, headers=NAV_HEADERS).text
    i, j, token = _I_RE.search(html), _J_RE.search(html), _TOKEN_RE.search(html)
    if not (i and j and token):
        return None, "regex did not match the interstitial script (hardened shape?), not solved"
    answer = int(i.group(1)) + int(j.group(1) + j.group(2))
    r = s.post(
        f"{LAB_URL}/_sec/verify?provider=interstitial",
        json={"bm-verify": token.group(1), "pow": answer},
        headers=_api_headers(),
    )
    try:
        body = r.json()
    except ValueError:
        body = {}
    if r.status_code != 200 or not body.get("ok"):
        return None, f"regex solved, verify rejected ({body.get('error', r.status_code)})"
    nav = {**NAV_HEADERS, "Sec-Fetch-Site": "same-origin", "Referer": LAB_URL + "/"}
    location = body.get("location")  # only with the LOW pow_interstitial_location flag
    if location:
        path = same_origin_path(str(location))
        if path is None:
            return None, "regex solved, verify accepted, cross-origin location rejected"
        followed = s.get(LAB_URL + path, headers=nav)
        return followed, "regex solved, verify accepted, followed location"
    # no location: do what the page does and load the resource again
    reload = s.get(LAB_URL + INTERSTITIAL_RETURN_TO, headers=nav)
    return reload, "regex solved, verify accepted, reloaded"


def interstitial_case(case: str) -> CaseResult:
    """Fresh, cookie-less session (the hard PoW would win by precedence), solve with regexes,
    then judge the proof_of_work signal of the protected resource. A client that could not
    solve it is still behind the gate, so that request is never scored."""
    with cffi.Session(impersonate=IMPERSONATE, verify=False) as s:
        followed, note = solve_interstitial(s)
        if followed is None or urlsplit(str(followed.url)).path != INTERSTITIAL_RETURN_TO:
            nav = {**NAV_HEADERS, "Sec-Fetch-Site": "same-origin", "Referer": LAB_URL + "/"}
            followed = s.get(LAB_URL + INTERSTITIAL_RETURN_TO, headers=nav)
        res = judge(
            LABEL, case, followed.status_code, followed.headers.get(REPORT_ID_HEADER), note
        )
        if res.verdict == "none" and '"bm-verify"' in followed.text:
            res.reason = "the gate served the interstitial again (session not cleared): not scored"
        return res


def native_header(path: str, rng: random.Random) -> str:
    """The lab's ``X-acf-sensor-data`` value, re-implemented from the native_app docstring.

    ``lab1;<b64url(json)>;<hmac_sha256_hex(app_key, "lab1;" + b64url)>`` with a synthetic
    accelerometer/gyroscope stream (12 samples, strictly increasing time, varying values)."""
    ts = int(time.time() * 1000)
    stream = [[20 * i, *(round(rng.gauss(0, 0.4), 4) for _ in range(6))] for i in range(1, 13)]
    device = "".join(rng.choice("0123456789abcdef") for _ in range(32))
    nonce = hashlib.sha256(f"{device}{ts}".encode()).hexdigest()[:16]
    doc = {
        "d": device,
        "av": APP_VERSION,
        "sv": SDK_VERSION,
        "t": ts,
        "n": nonce,
        "p": path,
        "s": stream,
    }
    body = base64.urlsafe_b64encode(json.dumps(doc, separators=(",", ":")).encode()).decode()
    body = body.rstrip("=")
    mac = hmac.new(APP_KEY.encode(), f"lab1;{body}".encode(), hashlib.sha256).hexdigest()
    return f"lab1;{body};{mac}"


def run(cases: list[str] | None = None) -> list[CaseResult]:
    out: list[CaseResult] = []
    rng = random.Random(NATIVE_SEED)
    with cffi.Session(impersonate=IMPERSONATE, verify=False) as s:
        landing = s.get(LAB_URL + "/", headers=NAV_HEADERS)
        pow_ok = solve_proof_of_work(s)
        pixel_ok = solve_pixel(s, landing.text)
        nav = {**NAV_HEADERS, "Sec-Fetch-Site": "same-origin", "Referer": LAB_URL + "/"}
        for case in cases or CASES:
            note = ""
            if case == "proof_of_work":
                note = f"hard PoW solved over HTTP, verify {'accepted' if pow_ok else 'rejected'}"
            elif case == "pixel_challenge":
                note = f"pixel beacon {'accepted' if pixel_ok else 'rejected'}"
            mobile = (
                {"X-Lab-Client": LABEL, "X-acf-sensor-data": native_header(MOBILE_PATH, rng)}
                if case == "native_app"
                else None
            )
            if CASE_TABLE[case].endpoint == "interstitial":
                with row_env(case):
                    out.append(interstitial_case(case))
                continue
            with row_env(case):
                out.append(
                    run_http_case(
                        LABEL,
                        s,
                        case,
                        nav_headers=nav,
                        api_headers={**_api_headers(), "Content-Type": "application/json"},
                        mobile_headers=mobile,
                        note=note,
                    )
                )
    return out
