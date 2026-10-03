import asyncio

from app.contract import RequestContext, Verdict
from app.modules.header_order import CHROME_FETCH, CHROME_NAV, HeaderOrderModule, lcs_len

CHROME_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36"
)


def run(order, ua=CHROME_UA, proto="h2", headers=None):
    hs = headers if headers is not None else [(h.lower(), "x") for h in order]
    c = RequestContext(
        method="GET", path="/", client_ip="1.1.1.1", headers=hs, header_order=order,
        cookies={}, user_agent=ua, http_proto=proto,
    )
    return asyncio.run(HeaderOrderModule().evaluate(c))


def test_chrome_navigation_passes():
    assert run(["host", *CHROME_NAV]).verdict == Verdict.PASS


def test_chrome_fetch_passes():
    assert run(CHROME_FETCH).verdict == Verdict.PASS


def test_playwright_headless_passes():
    ua = CHROME_UA.replace("Chrome/", "HeadlessChrome/")
    assert run(["Host", *CHROME_NAV], ua, "http/1.1").verdict == Verdict.PASS


def test_curl_cffi_chrome_passes():
    order = [h for h in CHROME_NAV if h not in ("sec-fetch-user", "priority", "cookie")]
    assert run(order).verdict == Verdict.PASS


def test_python_requests_fails():
    order = ["Host", "User-Agent", "Accept-Encoding", "Accept", "Connection"]
    hs = [("user-agent", "python-requests/2.32.0"), ("accept-encoding", "gzip, deflate"),
          ("accept", "*/*"), ("connection", "keep-alive")]
    s = run(order, "python-requests/2.32.0", "http/1.1", hs)
    assert s.verdict == Verdict.FAIL and s.score >= 50
    assert any("requests" in f for f in s.details["flags"])


def test_chrome_ua_missing_sec_headers_not_pass():
    s = run(["user-agent", "accept", "accept-encoding", "accept-language"])
    assert s.verdict != Verdict.PASS and "sec-fetch" in s.reason


def test_title_case_on_h2_flagged():
    s = run([h.title() for h in CHROME_NAV], proto="h2")
    assert s.details["breakdown"]["h2_uppercase"] == 50
    assert s.verdict == Verdict.FAIL


def test_title_case_http11_ok():
    assert run([h.title() for h in CHROME_NAV], proto="http/1.1").verdict == Verdict.PASS


def test_shuffled_order_scores():
    order = list(reversed(CHROME_NAV))
    s = run(order)
    assert s.verdict != Verdict.PASS and s.details["similarity"] < 0.5


def test_no_order_warns():
    s = run([])
    assert s.verdict == Verdict.WARN and s.score == 40


def test_lcs():
    assert lcs_len(list("abcd"), list("acbd")) == 3
