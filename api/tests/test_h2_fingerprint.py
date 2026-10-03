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


def run(fp, ua=CHROME_UA, proto="h2", headers=None):
    c = RequestContext(
        method="GET",
        path="/",
        client_ip="1.1.1.1",
        headers=headers or [],
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


SAFARI_MAC_FP = "2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p"
SAFARI_IOS_FP = "2:0;3:100;4:2097152;8:1;9:1|10420225|0|m,s,a,p"
OLD_SAFARI_FP = "2:0;3:100;4:2097152|10485760|0|m,s,p,a"
SAFARI_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/18.3 Safari/605.1.15"
)
IOS_UA = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/604.1"
)
IOS_BROWSER_UAS = [
    IOS_UA.replace("Version/18.3", "CriOS/131.0.6778.103"),
    IOS_UA.replace("Version/18.3", "FxiOS/135.0"),
    IOS_UA.replace("Version/18.3", "Version/18.0 EdgiOS/131.0.2903.92"),
]


def test_safari_macos_and_ios_profiles_pass():
    for ua in (SAFARI_UA, IOS_UA):
        for fp in (SAFARI_MAC_FP, SAFARI_IOS_FP):
            s = run(fp, ua)
            assert s.verdict == Verdict.PASS and s.score == 0, (ua, fp)


def test_ios_browsers_compared_with_safari_profile():
    for ua in IOS_BROWSER_UAS:
        assert run(SAFARI_IOS_FP, ua).verdict == Verdict.PASS, ua
        assert run(CHROME_FP, ua).verdict == Verdict.FAIL, ua


def test_pre_2024_safari_profile_no_longer_matches():
    assert run(OLD_SAFARI_FP, SAFARI_UA).verdict != Verdict.PASS


def test_safari_fp_with_chrome_ua_fails():
    assert run(SAFARI_MAC_FP, CHROME_UA).verdict == Verdict.FAIL


def test_firefox_current_profile_without_priority_tree():
    assert run("1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s", FF_UA).verdict == Verdict.PASS


def test_absent_window_update_accepts_00_and_0():
    assert parse_h2("1:65536|00|0|m,a,s,p")["window_update"] == 0
    assert parse_h2("1:65536|0|0|m,a,s,p")["window_update"] == 0
    assert parse_h2("1:65536|-|0|m,a,s,p")["window_update"] == 0


def test_absent_window_update_is_deviation_and_canonical_form_is_00():
    for wu in ("00", "0"):
        s = run(f"1:65536;2:0;4:6291456;6:262144|{wu}|0|m,a,s,p")
        assert s.details["breakdown"]["window_update"] == 20
        assert s.details["window_update_absent"] is True
        assert s.details["akamai_string"] == "1:65536;2:0;4:6291456;6:262144|00|0|m,a,s,p"


def test_akamai_string_in_details_roundtrips_for_present_window_update():
    s = run(CHROME_FP)
    assert s.details["akamai_string"] == CHROME_FP and s.details["window_update_absent"] is False


def test_paper_firefox53_example_parses():
    fp = "1:65536;4:131072;5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1|m,p,a,s"
    p = parse_h2(fp)
    assert p["window_update"] == 12517377 and p["pseudo"] == "m,p,a,s"
    assert p["priority"].startswith("3:0:0:201")


def test_labeled_lab_notation_is_not_accepted_as_akamai_format():
    labeled = "S[1:65536;2:0;4:6291456;6:262144]|WU[15663105]|P[0]|PS[m,a,s,p]"
    assert run(labeled).verdict == Verdict.FAIL  # lab convenience only, never scored


def test_headers_priority_is_echoed_not_scored():
    s = run(CHROME_FP, headers=[("x-h2-headers-priority", "1:0:256")])
    assert s.verdict == Verdict.PASS and s.details["headers_priority"] == "1:0:256"
