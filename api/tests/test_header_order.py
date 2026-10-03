import asyncio

import pytest
from app.contract import RequestContext, Verdict
from app.modules.header_order import (
    CHROME_FETCH,
    CHROME_NAV,
    HeaderOrderModule,
    lcs_len,
    parse_sec_ch_ua,
    parse_ua,
)

# Realistic Chrome value sets per major (reduced UA, current client hints).
SEC_CH = {
    131: '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    153: '"Google Chrome";v="153", "Not_A Brand";v="8", "Chromium";v="153"',
    154: '"Google Chrome";v="154", "Chromium";v="154", "Not A(Brand";v="99"',
}


def chrome_ua(major: int = 153) -> str:
    return (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
        f"Chrome/{major}.0.0.0 Safari/537.36"
    )


def chrome_values(major: int = 153) -> dict[str, str]:
    return {
        "sec-ch-ua": SEC_CH.get(major, SEC_CH[153].replace("153", str(major))),
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "upgrade-insecure-requests": "1",
        "user-agent": chrome_ua(major),
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
        "image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "sec-fetch-site": "none",
        "sec-fetch-mode": "navigate",
        "sec-fetch-user": "?1",
        "sec-fetch-dest": "document",
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": "en-US,en;q=0.9",
        "priority": "u=0, i",
    }


def run(order, ua=None, proto="h2", values=None, drop=(), **overrides):
    """Evaluate a request whose header names are `order`, with realistic Chrome values."""
    vals = {**chrome_values(), **(values or {}), **overrides}
    if ua is not None:
        vals["user-agent"] = ua
    hs = [(h.lower(), vals.get(h.lower(), "x")) for h in order if h.lower() not in drop]
    c = RequestContext(
        method="GET", path="/", client_ip="1.1.1.1", headers=hs, header_order=list(order),
        cookies={}, user_agent=vals["user-agent"], http_proto=proto,
    )
    return asyncio.run(HeaderOrderModule().evaluate(c))


def test_chrome_navigation_passes():
    assert run(["host", *CHROME_NAV]).verdict == Verdict.PASS


def test_chrome_fetch_passes():
    assert run(CHROME_FETCH, accept="*/*").verdict == Verdict.PASS


def test_chrome_153_and_154_client_hints_pass():
    for major in (131, 153, 154):
        vals = chrome_values(major)
        s = run(CHROME_NAV, values=vals, proto="h2")
        assert s.verdict == Verdict.PASS, (major, s.reason)


def test_curl_cffi_chrome131_headers_pass_on_h2():
    vals = chrome_values(131)
    order = [h for h in CHROME_NAV if h not in ("sec-fetch-user", "priority", "cookie")]
    assert run(order, values=vals).verdict == Verdict.PASS


def test_python_requests_fails():
    order = ["Host", "User-Agent", "Accept-Encoding", "Accept", "Connection"]
    vals = {"user-agent": "python-requests/2.32.0", "accept-encoding": "gzip, deflate",
            "accept": "*/*", "connection": "keep-alive"}
    s = run(order, proto="http/1.1", values=vals)
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
    s = run([h.title() for h in CHROME_NAV if h != "priority"], proto="http/1.1")
    assert s.verdict == Verdict.PASS


def test_shuffled_order_scores():
    s = run(list(reversed(CHROME_NAV)))
    assert s.verdict != Verdict.PASS and s.details["similarity"] < 0.5


def test_no_order_warns():
    s = run([])
    assert s.verdict == Verdict.WARN and s.score == 40


def test_lcs():
    assert lcs_len(list("abcd"), list("acbd")) == 3


# --- Chrome version consistency (audit 1.2 case 3) -------------------------------------------


def test_chrome_123_plus_without_zstd_is_mismatch():
    s = run(CHROME_NAV, **{"accept-encoding": "gzip, deflate, br"})
    assert s.details["breakdown"]["missing_zstd"] == 35
    assert s.verdict == Verdict.WARN and "zstd" in s.reason


def test_chrome_122_without_zstd_is_fine():
    vals = chrome_values(122)
    s = run(CHROME_NAV, values={**vals, "accept-encoding": "gzip, deflate, br"})
    assert "missing_zstd" not in s.details["breakdown"]
    assert s.verdict == Verdict.PASS


def test_zstd_with_q_value_accepted():
    s = run(CHROME_NAV, **{"accept-encoding": "gzip, deflate, br;q=0.9, zstd;q=0.8"})
    assert "missing_zstd" not in s.details["breakdown"]


def test_priority_on_http11_flagged():
    s = run(["Host", *CHROME_NAV], proto="http/1.1")
    assert s.details["breakdown"]["priority_on_http1"] == 30
    assert "HTTP/1.1" in s.reason


def test_priority_on_h2_not_flagged():
    assert "priority_on_http1" not in run(CHROME_NAV, proto="h2").details["breakdown"]


def test_full_build_ua_is_not_reduced():
    ua = chrome_ua().replace("153.0.0.0", "153.0.7339.80")
    s = run(CHROME_NAV, ua=ua)
    assert s.details["breakdown"]["reduced_ua"] == 30 and "reduced" in s.reason


def test_unfrozen_platform_token_flagged():
    ua = (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/153.0.0.0 Safari/537.36"
    )
    assert run(CHROME_NAV, ua=ua).details["breakdown"]["reduced_ua"] == 30


def test_android_chrome_reduced_ua_passes():
    ua = (
        "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/153.0.0.0 Mobile Safari/537.36"
    )
    s = run(CHROME_NAV, ua=ua, **{"sec-ch-ua-mobile": "?1", "sec-ch-ua-platform": '"Android"'})
    assert s.verdict == Verdict.PASS


def test_ua_and_sec_ch_ua_major_mismatch():
    s = run(CHROME_NAV, ua=chrome_ua(131), **{"sec-ch-ua": SEC_CH[153]})
    assert s.details["breakdown"]["ua_sec_ch_ua_major"] == 40
    assert "131" in s.reason and "153" in s.reason


def test_edge_uses_chromium_brand_major():
    ua = chrome_ua(153) + " Edg/153.0.3000.10"
    brands = '"Microsoft Edge";v="153", "Chromium";v="153", "Not_A Brand";v="8"'
    assert run(CHROME_NAV, ua=ua, **{"sec-ch-ua": brands}).verdict == Verdict.PASS


def test_headless_chrome_ua_is_strong_flag():
    ua = chrome_ua(153).replace("Chrome/", "HeadlessChrome/")
    s = run(CHROME_NAV, ua=ua)
    assert s.verdict == Verdict.FAIL and s.details["breakdown"]["headless_token"] == 60


def test_headless_brand_in_sec_ch_ua_is_strong_flag():
    brands = '"HeadlessChrome";v="153", "Chromium";v="153", "Not_A Brand";v="8"'
    s = run(CHROME_NAV, **{"sec-ch-ua": brands})
    assert s.verdict == Verdict.FAIL and "sec-ch-ua brands" in s.reason


@pytest.mark.parametrize(
    ("ua", "expected"),
    [
        (chrome_ua(131), (131, False, False)),
        (chrome_ua(153).replace("153.0.0.0", "153.0.7339.80"), (153, True, False)),
        (chrome_ua(153).replace("Chrome/", "HeadlessChrome/"), (153, False, True)),
        ("Mozilla/5.0 (Windows NT 10.0; rv:138.0) Gecko/20100101 Firefox/138.0",
         (None, False, False)),
    ],
)
def test_parse_ua(ua, expected):
    p = parse_ua(ua)
    assert (p["major"], p["full"], p["headless"]) == expected


def test_parse_sec_ch_ua():
    assert parse_sec_ch_ua(SEC_CH[154]) == {
        "Google Chrome": 154, "Chromium": 154, "Not A(Brand": 99,
    }
    assert parse_sec_ch_ua("") == {}
