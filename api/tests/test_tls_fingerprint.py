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


# --- Safari / WebKit ---------------------------------------------------------------
# RECONSTRUCTED FIXTURE (not a live capture): built from the shape published for Safari 18.3
# (curl_cffi #530; docs/research/akamai-audit-2026-10.md §1.2 case 1): Chrome's TLS 1.3 prefix,
# compress_certificate (27) + padding (21), no ALPS, no ECH, 3DES/CBC tail. The JA4 family
# t13d2014h2_a09f3c656075 is Safari 16-18; the extension-hash part is a plausible stand-in.
SAFARI_JA3 = (
    "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-"
    "53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0"
)
SAFARI_JA4 = "t13d2014h2_a09f3c656075_e7c285222651"
SAFARI_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/18.3 Safari/605.1.15"
)
IOS_UA = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/604.1"
)
CRIOS_UA = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) CriOS/131.0.6778.103 Mobile/15E148 Safari/604.1"
)
FXIOS_UA = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) FxiOS/135.0 Mobile/15E148 Safari/605.1.15"
)
EDGIOS_UA = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/18.0 EdgiOS/131.0.2903.92 Mobile/15E148 Safari/605.1.15"
)
IPAD_UA = IOS_UA.replace("iPhone", "iPad")


def _hdr(grease):
    return [("x-ja3-grease", grease)]


def test_safari_classified_with_and_without_grease():
    assert classify_tls(SAFARI_JA3, SAFARI_JA4, "1", None)["family"] == "safari"
    assert classify_tls(SAFARI_JA3, SAFARI_JA4, "0", None)["family"] == "safari"
    assert classify_tls(SAFARI_JA3, SAFARI_JA4, None, None)["family"] == "safari"


def test_safari_classified_from_ja4_alone():
    assert classify_tls("", SAFARI_JA4, "1", None)["family"] == "safari"


def test_safari_ua_passes_with_and_without_grease():
    for g in ("1", "0"):
        s = run(ctx(SAFARI_JA3, SAFARI_JA4, SAFARI_UA, _hdr(g)))
        assert s.verdict == Verdict.PASS and s.score == 0


def test_every_ios_browser_ua_passes_with_safari_hello():
    # iOS rule: all iOS browsers use WebKit, so they present a Safari hello.
    for ua in (IOS_UA, IPAD_UA, CRIOS_UA, FXIOS_UA, EDGIOS_UA):
        assert run(ctx(SAFARI_JA3, SAFARI_JA4, ua, _hdr("1"))).verdict == Verdict.PASS, ua


def test_safari_tls_with_chrome_or_firefox_desktop_ua_fails():
    assert run(ctx(SAFARI_JA3, SAFARI_JA4, CHROME_UA, _hdr("1"))).score == 85
    assert run(ctx(SAFARI_JA3, SAFARI_JA4, FF_UA, _hdr("1"))).score == 85


def test_chrome_tls_with_safari_or_ios_ua_fails():
    assert run(ctx(CHROME_JA3, "t13d1516h2_x_y", SAFARI_UA)).score == 85
    assert run(ctx(CHROME_JA3, "t13d1516h2_x_y", CRIOS_UA)).score == 85


def test_chrome_with_alps_and_ech_stays_chrome():
    ja3 = CHROME_JA3.replace("17513-21", "17613-65037-21")
    ja4 = "t13d1516h2_8daaf6152771_d8a2da3f94cd"
    assert classify_tls(ja3, ja4, "1", None)["family"] == "chrome"
    # Even if the legacy tail were present, ALPS/ECH rule out WebKit.
    with_tail = ja3.replace("-47-53,", "-47-53-49160-49170-10,")
    assert classify_tls(with_tail, "", "1", None)["family"] == "chrome"


def test_go_and_openssl_are_not_safari():
    go_ja4 = "t13d1312h2_f57a46bbacb6_ab7e3b40a677"
    py_ja4 = "t13d1812h1_85036bcba153_375ca2c5e164"
    assert classify_tls(GO_JA3, go_ja4, "0", None)["family"] == "go"
    assert classify_tls(PY_JA3, py_ja4, "0", None)["family"] == "openssl"


def test_ios_and_firefox_ua_families():
    from app.modules.tls_fingerprint import ua_family

    for ua in (IOS_UA, IPAD_UA, CRIOS_UA, FXIOS_UA, EDGIOS_UA, SAFARI_UA):
        assert ua_family(ua) == "safari", ua
    assert ua_family(FF_UA) == "firefox"
    assert ua_family(CHROME_UA) == "chrome"
