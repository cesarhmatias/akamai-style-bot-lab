import asyncio

from app.contract import RequestContext, Verdict
from app.modules.tls_fingerprint import TlsFingerprintModule, classify_tls

CHROME_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36"
)
FF_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
CHROME_JA3 = (
    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,"
    "0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0"
)
# Same Chrome, extensions permuted: must still pass.
CHROME_JA3_PERMUTED = CHROME_JA3.replace("0-23-65281-10-11", "11-10-27-0-65281-23")
FF_JA3 = (
    "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,"
    "0-23-65281-10-11-35-16-5-34-51-43-13-45-28-27,29-23-24-25-256-257,0"
)
PY_JA3 = (
    "771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158,"
    "0-11-10-35-22-23-13-43-45-51,29-23-30-25-24,0-1-2"
)
GO_JA3 = (
    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49161-49172-49162,"
    "0-5-10-11-13-16-18-23-43-45-51-65281,29-23-24-25,0"
)


def ctx(ja3="", ja4="", ua=CHROME_UA, headers=None):
    return RequestContext(
        method="GET", path="/", client_ip="1.2.3.4", headers=headers or [],
        header_order=[], cookies={}, user_agent=ua, ja3=ja3, ja4=ja4,
    )


def run(c):
    return asyncio.run(TlsFingerprintModule().evaluate(c))


def test_chrome_passes():
    assert run(ctx(CHROME_JA3, "t13d1516h2_x_y")).verdict == Verdict.PASS


def test_chrome_permuted_extensions_passes():
    assert run(ctx(CHROME_JA3_PERMUTED, "t13d1516h2_x_y")).verdict == Verdict.PASS


def test_headless_chrome_ua_passes():
    ua = CHROME_UA.replace("Chrome/", "HeadlessChrome/")
    assert run(ctx(CHROME_JA3, "t13d1516h2_x_y", ua)).verdict == Verdict.PASS


def test_grease_header_only_hello():
    ja3 = "771,4865-4866-4867-49195,0-23-27,29,0"
    assert classify_tls(ja3, "", "1", None)["family"] == "chrome"


def test_python_requests_fails_with_chrome_ua():
    s = run(ctx(PY_JA3, "t13d1012h1_a_b"))
    assert s.verdict == Verdict.FAIL and s.score == 85


def test_python_requests_own_ua_fails():
    s = run(ctx(PY_JA3, "t13d1012h1_a_b", "python-requests/2.32.0"))
    assert s.verdict == Verdict.FAIL and s.score == 75


def test_go_fails():
    assert run(ctx(GO_JA3, "t13d1312h2_a_b", "Go-http-client/2.0")).verdict == Verdict.FAIL


def test_firefox_passes_and_mismatch_fails():
    assert run(ctx(FF_JA3, "t13d1717h2_a_b", FF_UA)).verdict == Verdict.PASS
    assert run(ctx(FF_JA3, "t13d1717h2_a_b", CHROME_UA)).score == 85


def test_chrome_tls_with_firefox_ua_fails():
    assert run(ctx(CHROME_JA3, "t13d1516h2_x_y", FF_UA)).score == 85


def test_no_fingerprint_warns():
    s = run(ctx())
    assert s.verdict == Verdict.WARN and s.score == 40


def test_unknown_tls_warns():
    assert run(ctx("771,1-2-3,0,29,0", "t12d0305h2_a_b")).verdict == Verdict.WARN
