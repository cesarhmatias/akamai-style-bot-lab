import asyncio

import app.modules.botnet_cluster as bc
import pytest
from app.contract import Confidence, RequestContext, Verdict
from app.store import MemoryStore

JA4 = "t13d1516h2_8daaf6152771_02713d6af862"
H2 = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
ORDER = ["sec-ch-ua", "user-agent", "accept"]


@pytest.fixture
def now(monkeypatch):
    t = [5_000_000.0]
    monkeypatch.setattr(bc, "_clock", lambda: t[0])
    for v in ("LAB_CLUSTER_MIN_IPS", "LAB_CLUSTER_WINDOW_MIN", "LAB_CLUSTER_BAD_RATE"):
        monkeypatch.delenv(v, raising=False)
    return t


def ev(store, ip="203.0.113.1", ja4=JA4, h2=H2, order=ORDER, flag=True):
    c = RequestContext(
        method="GET", path="/", client_ip=ip, headers=[], header_order=order, cookies={},
        user_agent="x", ja4=ja4, h2_fingerprint=h2, store=store,
        flags={"botnet_cluster": flag},
    )
    return asyncio.run(bc.BotnetClusterModule().evaluate(c))


def test_module_is_low_confidence_flag_gated_and_default_off():
    m = bc.BotnetClusterModule()
    assert m.default_enabled is False and m.confidence == Confidence.LOW
    spec = m.flags[0]
    assert spec.name == "botnet_cluster" and spec.default is False
    assert spec.confidence == Confidence.LOW


def test_skips_when_flag_off(now):
    s = ev(MemoryStore(), flag=False)
    assert s.verdict == Verdict.SKIP and "unverified" in s.reason


def test_skips_without_transport_fingerprint(now):
    assert ev(MemoryStore(), ja4="", h2="").verdict == Verdict.SKIP


def test_many_ips_but_never_high_rate_is_not_flagged(now):
    s = MemoryStore()
    for i in range(10):
        now[0] += 120  # well under the high-rate gate
        sig = ev(s, ip=f"198.18.0.{i + 1}")
        assert sig.verdict == Verdict.PASS and sig.details["cluster_bad"] is False


def test_high_rate_marks_cluster_bad_but_one_ip_passes(now):
    s = MemoryStore()
    for _ in range(61):
        sig = ev(s)
    assert sig.details["cluster_bad"] is True and sig.verdict == Verdict.PASS
    assert "spans only 1 IP" in sig.reason


def test_new_ips_joining_a_bad_cluster_are_flagged(now):
    s = MemoryStore()
    for _ in range(60):
        ev(s, ip="203.0.113.1")
    assert ev(s, ip="198.18.0.2").verdict == Verdict.PASS  # 2 IPs < K=3
    sig = ev(s, ip="198.18.0.3")
    assert sig.verdict == Verdict.FAIL and sig.score == 70
    assert "Inherits botnet cluster flag" in sig.reason and sig.details["cluster_ips"] == 3


def test_different_fingerprint_is_a_different_cluster(now):
    s = MemoryStore()
    for _ in range(60):
        ev(s, ip="203.0.113.1")
    ev(s, ip="198.18.0.2")
    other = ev(s, ip="198.18.0.3", ja4="t13d1517h2_8daaf6152771_cb7bf5808d99")
    assert other.verdict == Verdict.PASS and other.details["cluster_ips"] == 1


def test_header_order_changes_the_cluster_key():
    def c(order):
        return RequestContext(method="GET", path="/", client_ip="1.1.1.1", headers=[],
                              header_order=order, cookies={}, user_agent="x", ja4=JA4)

    assert bc.cluster_key(c(["A", "b"])) == bc.cluster_key(c(["a", "B"]))
    assert bc.cluster_key(c(["a", "b"])) != bc.cluster_key(c(["b", "a"]))


def test_ips_expire_out_of_the_window(now, monkeypatch):
    monkeypatch.setenv("LAB_CLUSTER_WINDOW_MIN", "1")
    s = MemoryStore()
    for _ in range(60):
        ev(s, ip="203.0.113.1")
    ev(s, ip="198.18.0.2")
    now[0] += 30
    assert ev(s, ip="198.18.0.3").verdict == Verdict.FAIL
    now[0] += 61
    sig = ev(s, ip="198.18.0.4")  # earlier IPs aged out of the 1-minute window
    assert sig.details["cluster_ips"] == 1
