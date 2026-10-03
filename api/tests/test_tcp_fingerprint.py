import asyncio

from app.contract import Confidence, RequestContext, Verdict
from app.modules.tcp_fingerprint import DEFERRED_REASON, TcpFingerprintModule


def run(flags=None, headers=None):
    c = RequestContext(
        method="GET", path="/", client_ip="1.2.3.4", headers=headers or [], header_order=[],
        cookies={}, user_agent="Mozilla/5.0 (Windows NT 10.0) Chrome/153.0.0.0",
        flags=flags or {},
    )
    return asyncio.run(TcpFingerprintModule().evaluate(c))


def test_stub_metadata():
    m = TcpFingerprintModule()
    assert m.default_enabled is False and m.confidence == Confidence.LOW
    assert m.flags[0].name == "tcp_fingerprint" and m.flags[0].default is False


def test_always_skips_with_the_deferral_reason():
    for flags in ({}, {"tcp_fingerprint": True}):
        s = run(flags)
        assert s.verdict == Verdict.SKIP and s.score == 0
        assert s.reason == "deferred: needs raw SYN capture; Docker TTL caveat" == DEFERRED_REASON
        assert s.details["implemented"] is False


def test_docstring_explains_both_blockers():
    from app.modules import tcp_fingerprint

    doc = tcp_fingerprint.__doc__ or ""
    assert "NET_RAW" in doc and "TTL" in doc and "NAT" in doc
