import asyncio
import json

import pytest
from app.contract import EndpointClass, RequestContext, Verdict
from app.modules.version_consistency import VersionConsistencyModule, js_brand_major
from app.store import MemoryStore

JA3_CHROME = (
    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,"
    "27-65037-0-23-65281-10-11-35-16-5-13-18-51-45-43-17613-21,4588-29-23-24,0"
)
EXTS = "grease,27,65037,0,23,65281,10,11,35,16,5,13,18,51,45,43,17613,21,grease"
SEC = {
    131: '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    133: '"Google Chrome";v="133", "Not_A Brand";v="8", "Chromium";v="133"',
    153: '"Google Chrome";v="153", "Not_A Brand";v="8", "Chromium";v="153"',
}


def ua(major: int) -> str:
    return (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
        f"Chrome/{major}.0.0.0 Safari/537.36"
    )


def make(user_agent, *, sech=None, groups="grease,4588,29,23,24", alps="17613", sigalgs="",
         zstd=True, priority=True, proto="h2", ja3=JA3_CHROME, store=None, sid=""):
    h = [("x-ja3-grease", "1"), ("x-tls-exts", EXTS), ("x-tls-groups", groups),
         ("x-tls-alps", alps), ("x-tls-sigalgs", sigalgs),
         ("accept-encoding", "gzip, deflate, br, zstd" if zstd else "gzip, deflate, br")]
    if sech:
        h.append(("sec-ch-ua", sech))
    if priority:
        h.append(("priority", "u=0, i"))
    return RequestContext(
        method="GET", path="/", client_ip="1.2.3.4", headers=h, header_order=[], cookies={},
        user_agent=user_agent, ja3=ja3, ja4="t13d1516h2_8daaf6152771_d8a2da3f94cd",
        http_proto=proto, store=store, session_id=sid,
    )


def run(c):
    return asyncio.run(VersionConsistencyModule().evaluate(c))


def test_module_metadata():
    m = VersionConsistencyModule()
    assert m.default_enabled and m.category == "passive" and m.confidence.value == "high"
    want = {EndpointClass.PAGE, EndpointClass.PROTECTED, EndpointClass.TRANSACTIONAL}
    assert want == m.applies_to


def test_real_chrome_133_agrees():
    s = run(make(ua(133), sech=SEC[133]))
    assert s.verdict == Verdict.PASS
    layers = s.details["layers"]
    assert layers["agree"] is True and layers["disagreements"] == []
    assert (layers["ua_major"], layers["sech_major"], layers["tls_min"]) == (133, 133, 133)


def test_real_chrome_153_with_ml_dsa_agrees():
    s = run(make(ua(153), sech=SEC[153], sigalgs="0904,0905,0906,0403,0804"))
    assert s.verdict == Verdict.PASS and s.details["layers"]["tls_min"] == 150


def test_curl_cffi_chrome131_profile_is_consistent_with_its_own_ua():
    # chrome131 impersonation: ML-KEM 4588, legacy ALPS 17513, zstd.
    c = make(ua(131), sech=SEC[131], alps="17513")
    s = run(c)
    layers = s.details["layers"]
    assert s.verdict == Verdict.PASS
    assert (layers["tls_min"], layers["tls_max"]) == (131, 132)


def test_curl_cffi_chrome131_with_newer_ua_fails():
    s = run(make(ua(133), sech=SEC[133], alps="17513"))
    assert s.verdict == Verdict.FAIL and s.score == 80
    assert "ALPS 17513" in s.reason and "133" in s.reason


def test_playwright_153_with_ua_overridden_to_131_fails():
    s = run(make(ua(131), sech=SEC[153], sigalgs="0904,0905,0906,0403"))
    assert s.verdict == Verdict.FAIL
    d = s.details["layers"]["disagreements"]
    assert any("ML-DSA" in x for x in d)
    assert any("sec-ch-ua says 153" in x for x in d)
    assert s.details["layers"]["agree"] is False


def test_ua_without_hints_but_newer_tls_fails():
    s = run(make(ua(120), alps="17613"))
    assert s.verdict == Verdict.FAIL and "17613" in s.reason


def test_kyber_group_caps_at_130():
    sech = SEC[133].replace("133", "135")
    s = run(make(ua(135), sech=sech, groups="grease,25497,29", alps="none"))
    assert s.verdict == Verdict.FAIL and "Kyber" in s.reason


def test_zstd_and_priority_set_header_minimum():
    s = run(make(ua(120), alps="none", groups="29,23"))
    assert s.verdict == Verdict.FAIL
    assert s.details["layers"]["hdr_min"] == 124
    ok = run(make(ua(124), alps="none", groups="29,23"))
    assert ok.verdict == Verdict.PASS and ok.details["layers"]["hdr_min"] == 124


def test_priority_on_http11_is_not_a_version_marker():
    s = run(make(ua(120), alps="none", groups="29,23", zstd=False, proto="http/1.1"))
    assert s.verdict == Verdict.PASS and s.details["layers"]["hdr_min"] is None


def test_ua_vs_sec_ch_ua_mismatch_alone_fails():
    s = run(make(ua(131), sech=SEC[133], alps="none", groups="29", zstd=False, priority=False))
    assert s.verdict == Verdict.FAIL and "sec-ch-ua says 133" in s.reason


def test_only_ml_dsa_violation_is_warn_medium():
    s = run(make(ua(140), sech=SEC[133].replace("133", "140"), alps="none", groups="29",
                 sigalgs="0904,0905,0906,0403"))
    assert s.verdict == Verdict.WARN and s.score == 40 and "medium" in s.reason


def test_ml_dsa_not_trusted_in_non_chrome_shaped_hello():
    go_ja3 = (
        "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49161-49172-49162,"
        "0-5-10-11-13-16-18-23-43-45-51-65281,29-23-24-25,0"
    )
    c = make(ua(131), alps="none", groups="29,23", sigalgs="0904,0905,0906", ja3=go_ja3,
             zstd=False, priority=False)
    c.headers = [(k, "0") if k == "x-ja3-grease" else (k, v) for k, v in c.headers]
    c.headers = [(k, v) for k, v in c.headers if k != "x-tls-exts"]
    s = run(c)
    assert s.verdict == Verdict.PASS and s.details["layers"]["tls_family"] == "go"
    assert s.details["layers"]["tls_min"] is None


@pytest.mark.parametrize(
    "user_agent",
    [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
        "Version/18.3 Safari/605.1.15",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) CriOS/131.0.6778.103 Mobile/15E148 Safari/604.1",
        "python-requests/2.32.0",
    ],
)
def test_non_chromium_uas_are_skipped_even_with_ml_kem(user_agent):
    s = run(make(user_agent))  # Firefox also sends group 4588: must not be flagged
    assert s.verdict == Verdict.SKIP and s.details["layers"]["applicable"] is False


def test_ua_only_has_nothing_to_compare():
    c = make(ua(150), alps="", groups="", zstd=False, priority=False)
    c.ja3 = ""
    c.headers = [(k, v) for k, v in c.headers if k != "x-tls-exts"]
    s = run(c)
    assert s.verdict == Verdict.PASS and "nothing to compare" in s.reason


# --- JavaScript layer (sensor navigator.brands) -------------------------------------------


def sensor_store(brands):
    store = MemoryStore()
    asyncio.run(store.set("sensor:sid1", json.dumps({"navigator": {"brands": brands}})))
    return store


def test_js_brands_agree_passes():
    store = sensor_store(["Google Chrome/133", "Not_A Brand/8", "Chromium/133"])
    s = run(make(ua(133), sech=SEC[133], store=store, sid="sid1"))
    assert s.verdict == Verdict.PASS and s.details["layers"]["js_major"] == 133


def test_js_brands_disagree_fails():
    store = sensor_store(["Google Chrome/153", "Chromium/153"])
    s = run(make(ua(133), sech=SEC[133], store=store, sid="sid1"))
    assert s.verdict == Verdict.FAIL and "navigator.userAgentData says 153" in s.reason


def test_missing_sensor_leaves_js_layer_empty():
    s = run(make(ua(133), sech=SEC[133], store=MemoryStore(), sid="nosensor"))
    assert s.verdict == Verdict.PASS and s.details["layers"]["js_major"] is None


def test_js_brand_parsing_variants():
    assert js_brand_major({"navigator": {"brands": ["Chromium/153", "Not A/8"]}}) == 153
    assert js_brand_major({"brands": [{"brand": "Google Chrome", "version": "153.0.1"}]}) == 153
    assert js_brand_major({"navigator": {"brands": []}}) is None
    assert js_brand_major({"navigator": {}}) is None
    assert js_brand_major(None) is None
