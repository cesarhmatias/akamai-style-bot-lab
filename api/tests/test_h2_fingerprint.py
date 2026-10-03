import asyncio

from app.contract import RequestContext, Verdict
from app.modules.h2_fingerprint import H2FingerprintModule, parse_h2

CHROME_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36"
)
FF_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
CHROME_FP = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
FF_FP = "1:65536;2:0;4:131072;5:16384|12517377|3:0:0:201,5:0:0:101|m,p,a,s"
HTTPX_H2_FP = "3:100;4:65535|65535|0|m,s,a,p"


def run(fp, ua=CHROME_UA, proto="h2"):
    c = RequestContext(
        method="GET",
        path="/",
        client_ip="1.1.1.1",
        headers=[],
        header_order=[],
        cookies={},
        user_agent=ua,
        h2_fingerprint=fp,
        http_proto=proto,
    )
    return asyncio.run(H2FingerprintModule().evaluate(c))


def test_chrome_pass():
    assert run(CHROME_FP).verdict == Verdict.PASS


def test_headless_chrome_ua_pass():
    assert run(CHROME_FP, CHROME_UA.replace("Chrome/", "HeadlessChrome/")).verdict == Verdict.PASS


def test_curl_cffi_chrome_pass():
    # curl_cffi chrome impersonation emits the same H2 frames as Chrome.
    assert run(CHROME_FP, "Mozilla/5.0 Chrome/124.0.0.0 Safari/537.36").score == 0


def test_firefox_matches_firefox_profile():
    assert run(FF_FP, FF_UA).verdict == Verdict.PASS


def test_firefox_fp_with_chrome_ua_fails_with_breakdown():
    s = run(FF_FP, CHROME_UA)
    assert s.verdict == Verdict.FAIL and s.score >= 50
    assert s.details["breakdown"]["pseudo_order"] > 0


def test_python_h2_lib_fails():
    s = run(HTTPX_H2_FP)
    assert s.verdict == Verdict.FAIL and s.score == 100


def test_http11_with_chrome_ua_fails_80():
    s = run("", proto="http/1.1")
    assert s.verdict == Verdict.FAIL and s.score == 80
    assert "h2" in s.reason


def test_http11_python_requests():
    assert run("", "python-requests/2.32", "http/1.1").verdict == Verdict.FAIL


def test_single_deviation_warns():
    s = run("1:65536;2:0;4:6291456;6:262144|15663105|0|m,s,a,p")
    assert s.verdict == Verdict.WARN and s.score == 25


def test_malformed():
    assert run("garbage").verdict == Verdict.FAIL
    assert parse_h2("a|b|c|d") is None
