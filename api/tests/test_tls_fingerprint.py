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


# --- era markers, extension order, rarity (audit 1.2 case 1) --------------------------------
from app.modules.tls_fingerprint import (  # noqa: E402
    KNOWN_CHROME_JA4,
    KNOWN_FINGERPRINTS,
    chrome_tls_era,
    tls_view,
)
from app.store import MemoryStore  # noqa: E402

CH133_JA3 = (
    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,"
    "27-65037-0-23-65281-10-11-35-16-5-13-18-51-45-43-17613-21,4588-29-23-24,0"
)
CH133_JA4 = "t13d1516h2_8daaf6152771_d8a2da3f94cd"
CH153_JA4 = "t13d1517h2_8daaf6152771_cb7bf5808d99"
ORDER = "grease,27,65037,0,23,65281,10,11,35,16,5,13,18,51,45,43,17613,21,grease"


def hdrs(**kw):
    return [(k.replace("_", "-"), v) for k, v in kw.items()]


def era_for(ja3="", **kw):
    c = ctx(ja3, headers=hdrs(**kw))
    return chrome_tls_era(tls_view(c), chrome_shaped=True)


def test_known_ja4_table_refreshed():
    assert "t13d1516h2_8daaf6152771_02713d6af862" in KNOWN_CHROME_JA4
    assert "t13d1516h2_8daaf6152771_d8a2da3f94cd" in KNOWN_CHROME_JA4
    assert "t13d1517h2_8daaf6152771_cb7bf5808d99" in KNOWN_CHROME_JA4
    assert KNOWN_FINGERPRINTS["safari-ja4-16-18"]["ja4"].startswith("t13d2014h2_a09f3c656075_")


def test_era_mlkem_means_131_plus():
    e = era_for(x_tls_groups="grease,4588,29,23,24")
    assert (e.min_major, e.max_major) == (131, None)


def test_era_kyber_means_130_or_older():
    e = era_for(x_tls_groups="grease,25497,29,23,24")
    assert (e.min_major, e.max_major) == (None, 130)


def test_era_alps_codepoints():
    assert era_for(x_tls_alps="17613").min_major == 133
    assert era_for(x_tls_alps="17513").max_major == 132
    assert era_for(x_tls_alps="none").min_major is None


def test_era_from_ja3_fallback_without_new_headers():
    e = chrome_tls_era(tls_view(ctx(CH133_JA3, CH133_JA4)), chrome_shaped=True)
    assert (e.min_major, e.max_major) == (133, None)  # 4588 -> 131, 17613 -> 133


def test_era_combined_window_curl_cffi_chrome131_shape():
    e = era_for(x_tls_groups="grease,4588,29,23,24", x_tls_alps="17513")
    assert (e.min_major, e.max_major) == (131, 132)


def test_era_mldsa_only_in_chrome_shaped_hello():
    sig = "0904,0905,0906,0403,0804"
    chrome = chrome_tls_era(tls_view(ctx(headers=hdrs(x_tls_sigalgs=sig))), chrome_shaped=True)
    go = chrome_tls_era(tls_view(ctx(headers=hdrs(x_tls_sigalgs=sig))), chrome_shaped=False)
    assert chrome.min_major == 150 and chrome.confidence[chrome.evidence[0]] == "medium"
    assert go.min_major is None


def test_era_chrome_152_markers_only_in_chrome_shaped_hello():
    """Chrome 152 puts a GREASE value first in signature_algorithms and adds trust_anchors."""
    grease = hdrs(x_tls_sigalgs="grease,0904,0905,0906,0403,0804")
    anchors = hdrs(x_tls_exts=ORDER.replace("17613", "17613,51764"))
    for h in (grease, anchors):
        chrome = chrome_tls_era(tls_view(ctx(headers=h)), chrome_shaped=True)
        go = chrome_tls_era(tls_view(ctx(headers=h)), chrome_shaped=False)
        assert chrome.min_major == 152
        assert [t for b, _, t in chrome.lows if b == 152] == ["medium"]
        assert all(b != 152 for b, _, _ in go.lows)
    # absence proves nothing: the headless shell sends GREASE but no trust_anchors
    assert era_for(x_tls_exts=ORDER).min_major == 133  # ALPS 17613 only


def test_signal_details_expose_era_and_confidence():
    s = run(ctx(CH133_JA3, CH133_JA4, headers=hdrs(x_ja3_grease="1", x_tls_alps="17613")))
    assert s.verdict == Verdict.PASS
    assert s.details["era"]["min"] == 133
    assert s.details["check_confidence"]["extension_order"] == "medium"


def run_with_store(store, conn, order=ORDER, ja4=CH133_JA4, ua=CHROME_UA):
    c = ctx(CH133_JA3, ja4, ua, hdrs(x_ja3_grease="1", x_tls_exts=order, x_tls_conn=conn))
    c.store = store
    return asyncio.run(TlsFingerprintModule().evaluate(c))


def test_identical_extension_order_over_three_connections_warns():
    store = MemoryStore()
    assert run_with_store(store, "c1").verdict == Verdict.PASS
    assert run_with_store(store, "c2").verdict == Verdict.PASS
    s = run_with_store(store, "c3")
    assert s.verdict == Verdict.WARN and s.score == 25
    assert "extension order" in s.reason and "[medium]" in s.reason


def test_same_connection_repeated_does_not_count():
    store = MemoryStore()
    for _ in range(6):
        assert run_with_store(store, "same-conn").verdict == Verdict.PASS


def test_permuting_chrome_never_warns():
    store = MemoryStore()
    orders = [ORDER, ORDER.replace("27,65037", "65037,27"), ORDER.replace("0,23", "23,0")]
    for i, o in enumerate(orders * 3):
        assert run_with_store(store, f"c{i}", o).verdict == Verdict.PASS


def test_order_tracking_is_per_ip_and_ja4():
    store = MemoryStore()
    for i in range(3):
        run_with_store(store, f"a{i}")
    c = ctx(CH133_JA3, CH133_JA4, CHROME_UA,
            hdrs(x_ja3_grease="1", x_tls_exts=ORDER, x_tls_conn="z"))
    c.store, c.client_ip = store, "9.9.9.9"
    assert asyncio.run(TlsFingerprintModule().evaluate(c)).verdict == Verdict.PASS


def test_unknown_chrome_ja4_warns_low_score():
    s = run_with_store(MemoryStore(), "c1", ja4="t13d1516h2_8daaf6152771_0123456789ab")
    assert s.verdict == Verdict.WARN and s.score == 10 and s.details["ja4_known"] is False
    assert "not in the known Chrome fingerprint table" in s.reason
    assert s.details["ja4_chromium_build"] is False


def test_chromium_build_ja4_warns_and_is_named():
    """Playwright's headless shell 153 = the JA4 Scrapfly lists as Brave 153 on Linux: a real
    Chromium hello, just not Google Chrome's (no trust_anchors, 16 extensions)."""
    s = run_with_store(MemoryStore(), "c1", ja4="t13d1516h2_8daaf6152771_806a8c22fdea")
    assert s.verdict == Verdict.WARN and s.score == 10
    assert "Chromium build" in s.reason and "not Google Chrome's" in s.reason
    assert s.details["ja4_chromium_build"] is True


def test_known_chrome_153_ja4_passes_without_warning():
    s = run_with_store(MemoryStore(), "c1", ja4=CH153_JA4)
    assert s.verdict == Verdict.PASS


def test_rarity_not_applied_to_other_families():
    c = ctx(SAFARI_JA3, "t13d2014h2_a09f3c656075_e7c285222651", SAFARI_UA, _hdr("1"))
    assert run(c).verdict == Verdict.PASS
