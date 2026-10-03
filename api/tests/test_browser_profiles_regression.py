"""Regression: every current mainstream browser passes the TLS, H2, header-order and
version-consistency modules.

Guards against the defects in docs/research/akamai-audit-2026-10.md (Safari scored 85 on TLS
and 75 on H2) and against false positives of the v2 cross-layer checks. TLS inputs are the
fields the modules read: ``ja3``, ``ja4`` and the edge-injected ``x-ja3-grease`` /
``x-tls-exts`` / ``x-tls-groups`` / ``x-tls-alps`` / ``x-tls-sigalgs`` headers. The hellos and
header sets are RECONSTRUCTED fixtures built from published shapes, not live captures.
"""

import asyncio

import pytest
from app.contract import RequestContext, Signal, Verdict
from app.modules.h2_fingerprint import H2FingerprintModule
from app.modules.header_order import HeaderOrderModule
from app.modules.tls_fingerprint import TlsFingerprintModule
from app.modules.version_consistency import VersionConsistencyModule

CHROME_WIN_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/133.0.0.0 Safari/537.36"
)
CHROME_MAC_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/133.0.0.0 Safari/537.36"
)
CHROME_153_WIN_UA = CHROME_WIN_UA.replace("133.0.0.0", "153.0.0.0")
CHROME_153_MAC_UA = CHROME_MAC_UA.replace("133.0.0.0", "153.0.0.0")
FIREFOX_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0"
SAFARI_MAC_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/18.3 Safari/605.1.15"
)
SAFARI_IOS_UA = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/604.1"
)
CRIOS_UA = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) CriOS/131.0.6778.103 Mobile/15E148 Safari/604.1"
)

# Chrome 133: ALPS 17613 + ECH 65037 + compress_certificate, no 3DES; permuted ext order.
CHROME_TLS = {
    "ja3": (
        "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,"
        "27-65037-0-23-65281-10-11-35-16-5-13-18-51-45-43-17613-21,4588-29-23-24,0"
    ),
    "ja4": "t13d1516h2_8daaf6152771_d8a2da3f94cd",
    "grease": "1",
    "exts": "grease,27,65037,0,23,65281,10,11,35,16,5,13,18,51,45,43,17613,21,grease",
    "groups": "grease,4588,29,23,24",
    "alps": "17613",
    "sigalgs": "0403,0804,0401,0503,0805,0501,0806,0601",
}
# Chrome 153: JA4 t13d1517h2_..._cb7bf5808d99, ML-DSA signature schemes first (Chrome 150+).
CHROME_153_TLS = {
    **CHROME_TLS,
    "ja4": "t13d1517h2_8daaf6152771_cb7bf5808d99",
    "sigalgs": "0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601",
}
FIREFOX_TLS = {
    "ja3": (
        "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-"
        "157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-27,4588-29-23-24-25-256-257,0"
    ),
    "ja4": "t13d1717h2_5b57614c22b0_3cbfd9057e0d",
    "grease": "0",
    "exts": "0,23,65281,10,11,35,16,5,34,51,43,13,45,28,27",
    "groups": "4588,29,23,24,25,256,257",
    "alps": "none",
    "sigalgs": "0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201",
}
# Safari 18.3 (macOS and iOS share the hello): Chrome prefix, compress_certificate 27 and
# padding 21, no ALPS/ECH, legacy tail -53-47-49160-49170-10; JA4 family t13d2014h2_a09f3c656075.
SAFARI_TLS = {
    "ja3": (
        "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-"
        "53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0"
    ),
    "ja4": "t13d2014h2_a09f3c656075_e7c285222651",
    "grease": "1",
    "exts": "grease,0,23,65281,10,11,16,5,13,18,51,45,43,27,21,grease",
    "groups": "grease,29,23,24,25",
    "alps": "none",
    "sigalgs": "0403,0804,0401,0503,0805,0501,0806,0601,0201",
}
PYTHON_TLS = {
    "ja3": (
        "771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158,"
        "0-11-10-35-22-23-13-43-45-51,29-23-30-25-24,0-1-2"
    ),
    "ja4": "t13d1012h1_a1b2c3d4e5f6_0123456789ab",
    "grease": "0",
    "exts": "0,11,10,35,22,23,13,43,45,51",
}

CHROME_H2 = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
FIREFOX_H2 = "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s"
SAFARI_MAC_H2 = "2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p"
SAFARI_IOS_H2 = "2:0;3:100;4:2097152;8:1;9:1|10420225|0|m,s,a,p"

# Chrome (and Safari/Firefox) hellos on desktop do not carry sec-ch-ua except Chrome.
SEC_CH_UA = '"Google Chrome";v="133", "Not_A Brand";v="8", "Chromium";v="133"'
SEC_CH_UA_153 = '"Google Chrome";v="153", "Not_A Brand";v="8", "Chromium";v="153"'

# Realistic HTTP request headers (names in wire order) per browser, h2 navigation.
_ACCEPT_CHROME = (
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,"
    "*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
)


def chrome_request(ua: str, sec_ch_ua: str, platform: str) -> list[tuple[str, str]]:
    return [
        ("sec-ch-ua", sec_ch_ua), ("sec-ch-ua-mobile", "?0"),
        ("sec-ch-ua-platform", f'"{platform}"'), ("upgrade-insecure-requests", "1"),
        ("user-agent", ua), ("accept", _ACCEPT_CHROME), ("sec-fetch-site", "none"),
        ("sec-fetch-mode", "navigate"), ("sec-fetch-user", "?1"), ("sec-fetch-dest", "document"),
        ("accept-encoding", "gzip, deflate, br, zstd"), ("accept-language", "en-US,en;q=0.9"),
        ("priority", "u=0, i"),
    ]


def firefox_request(ua: str) -> list[tuple[str, str]]:
    return [
        ("user-agent", ua),
        ("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
        ("accept-language", "en-US,en;q=0.5"), ("accept-encoding", "gzip, deflate, br, zstd"),
        ("upgrade-insecure-requests", "1"), ("sec-fetch-dest", "document"),
        ("sec-fetch-mode", "navigate"), ("sec-fetch-site", "none"), ("sec-fetch-user", "?1"),
        ("priority", "u=0, i"), ("te", "trailers"),
    ]


def safari_request(ua: str) -> list[tuple[str, str]]:
    return [
        ("sec-fetch-dest", "document"), ("user-agent", ua),
        ("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
        ("sec-fetch-site", "none"), ("sec-fetch-mode", "navigate"),
        ("accept-language", "en-US,en;q=0.9"), ("priority", "u=0, i"),
        ("accept-encoding", "gzip, deflate, br"),
    ]

BROWSERS = [
    pytest.param(CHROME_WIN_UA, CHROME_TLS, CHROME_H2, SEC_CH_UA, id="chrome-windows"),
    pytest.param(CHROME_MAC_UA, CHROME_TLS, CHROME_H2, SEC_CH_UA, id="chrome-macos"),
    pytest.param(CHROME_153_WIN_UA, CHROME_153_TLS, CHROME_H2, SEC_CH_UA_153, id="chrome153-win"),
    pytest.param(CHROME_153_MAC_UA, CHROME_153_TLS, CHROME_H2, SEC_CH_UA_153, id="chrome153-mac"),
    pytest.param(FIREFOX_UA, FIREFOX_TLS, FIREFOX_H2, "", id="firefox"),
    pytest.param(SAFARI_MAC_UA, SAFARI_TLS, SAFARI_MAC_H2, "", id="safari18-macos"),
    pytest.param(SAFARI_IOS_UA, SAFARI_TLS, SAFARI_IOS_H2, "", id="safari18-ios"),
    pytest.param(CRIOS_UA, SAFARI_TLS, SAFARI_IOS_H2, "", id="chrome-on-ios"),
]


def make_ctx(
    ua: str, tls: dict[str, str], h2: str = "", sec_ch_ua: str = "",
    request: list[tuple[str, str]] | None = None,
) -> RequestContext:
    headers = [("x-ja3-grease", tls["grease"]), ("x-tls-exts", tls["exts"])]
    for name, key in (("x-tls-groups", "groups"), ("x-tls-alps", "alps"),
                      ("x-tls-sigalgs", "sigalgs")):
        if key in tls:
            headers.append((name, tls[key]))
    if sec_ch_ua:
        headers.append(("sec-ch-ua", sec_ch_ua))
    order: list[str] = []
    if request is not None:
        headers += [(k, v) for k, v in request if k != "sec-ch-ua"]
        order = [k for k, _ in request]
    return RequestContext(
        method="GET", path="/", client_ip="1.2.3.4", headers=headers, header_order=order,
        cookies={}, user_agent=ua, ja3=tls["ja3"], ja4=tls["ja4"],
        h2_fingerprint=h2, http_proto="h2",
    )


def request_for(ua: str, brands: str) -> list[tuple[str, str]]:
    """Realistic headers of the browser the UA claims."""
    if "Firefox/" in ua and "FxiOS" not in ua:
        return firefox_request(ua)
    if brands:
        return chrome_request(ua, brands, "Windows" if "Windows" in ua else "macOS")
    return safari_request(ua)


def tls_signal(c: RequestContext) -> Signal:
    return asyncio.run(TlsFingerprintModule().evaluate(c))


def h2_signal(c: RequestContext) -> Signal:
    return asyncio.run(H2FingerprintModule().evaluate(c))


def header_signal(c: RequestContext) -> Signal:
    return asyncio.run(HeaderOrderModule().evaluate(c))


def version_signal(c: RequestContext) -> Signal:
    return asyncio.run(VersionConsistencyModule().evaluate(c))


@pytest.mark.parametrize(("ua", "tls", "h2", "brands"), BROWSERS)
def test_browser_passes_tls_and_h2(
    ua: str, tls: dict[str, str], h2: str, brands: str
) -> None:
    c = make_ctx(ua, tls, h2, brands)
    t, h = tls_signal(c), h2_signal(c)
    assert (t.verdict, t.score) == (Verdict.PASS, 0), t.reason
    assert (h.verdict, h.score) == (Verdict.PASS, 0), h.reason


@pytest.mark.parametrize(("ua", "tls", "h2", "brands"), BROWSERS)
def test_browser_passes_header_order_and_version_consistency(
    ua: str, tls: dict[str, str], h2: str, brands: str
) -> None:
    c = make_ctx(ua, tls, h2, brands, request=request_for(ua, brands))
    ho, vc = header_signal(c), version_signal(c)
    assert ho.verdict == Verdict.PASS, (ho.reason, ho.details.get("breakdown"))
    assert vc.verdict in {Verdict.PASS, Verdict.SKIP}, vc.reason
    if vc.verdict == Verdict.PASS:
        assert vc.details["layers"]["agree"] is True
    t = tls_signal(c)
    assert (t.verdict, t.score) == (Verdict.PASS, 0), t.reason


def test_chrome_153_layers_agree_and_tls_window_is_150_plus() -> None:
    c = make_ctx(CHROME_153_WIN_UA, CHROME_153_TLS, CHROME_H2, SEC_CH_UA_153,
                 request=request_for(CHROME_153_WIN_UA, SEC_CH_UA_153))
    layers = version_signal(c).details["layers"]
    assert (layers["ua_major"], layers["sech_major"], layers["tls_min"]) == (153, 153, 150)


@pytest.mark.parametrize("grease", ["1", "0"])
def test_safari_tls_passes_regardless_of_grease(grease: str) -> None:
    tls = {**SAFARI_TLS, "grease": grease}
    assert tls_signal(make_ctx(SAFARI_MAC_UA, tls)).verdict == Verdict.PASS


def test_negative_python_requests_tls_with_chrome_ua_fails() -> None:
    s = tls_signal(make_ctx(CHROME_WIN_UA, PYTHON_TLS, sec_ch_ua=SEC_CH_UA))
    assert s.verdict == Verdict.FAIL and s.score == 85


def test_negative_chrome_tls_with_safari_ua_fails() -> None:
    s = tls_signal(make_ctx(SAFARI_MAC_UA, CHROME_TLS))
    assert s.verdict == Verdict.FAIL and s.score == 85


def test_negative_safari_tls_with_desktop_chrome_ua_fails() -> None:
    for ua in (CHROME_WIN_UA, CHROME_MAC_UA):
        s = tls_signal(make_ctx(ua, SAFARI_TLS, sec_ch_ua=SEC_CH_UA))
        assert s.verdict == Verdict.FAIL and s.score == 85


def test_negative_h2_profiles_do_not_cross() -> None:
    assert h2_signal(make_ctx(CHROME_WIN_UA, CHROME_TLS, SAFARI_MAC_H2)).verdict == Verdict.FAIL
    assert h2_signal(make_ctx(SAFARI_MAC_UA, SAFARI_TLS, CHROME_H2)).verdict == Verdict.FAIL


def test_negative_chrome_153_tls_with_ua_overridden_to_131_fails_version_consistency() -> None:
    ua = CHROME_153_WIN_UA.replace("153.0.0.0", "131.0.0.0")
    c = make_ctx(ua, CHROME_153_TLS, CHROME_H2, SEC_CH_UA_153,
                 request=chrome_request(ua, SEC_CH_UA_153, "Windows"))
    s = version_signal(c)
    assert s.verdict == Verdict.FAIL and s.details["layers"]["agree"] is False
