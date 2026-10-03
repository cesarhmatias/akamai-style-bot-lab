import asyncio

import app.modules.ip_reputation as m
import pytest
from app.contract import RequestContext, Verdict
from app.store import MemoryStore


@pytest.fixture
def now(monkeypatch):
    t = [1_000_000.0]
    monkeypatch.setattr(m, "_clock", lambda: t[0])
    monkeypatch.delenv("LAB_BAD_CIDRS", raising=False)
    return t


def ctx(store, ip="203.0.113.7"):
    return RequestContext(
        method="GET", path="/", client_ip=ip, headers=[], header_order=[], cookies={},
        user_agent="x", store=store,
    )


def ev(store, ip="203.0.113.7"):
    return asyncio.run(m.IpReputationModule().evaluate(ctx(store, ip)))


def test_normal_harness_run_passes(now):
    s = MemoryStore()
    for _ in range(40):
        assert ev(s).verdict == Verdict.PASS


def test_burst_fails_then_blocks(now):
    s = MemoryStore()
    verdicts = [ev(s).verdict for _ in range(100)]
    assert Verdict.FAIL in verdicts and verdicts[-1] == Verdict.BLOCK
    assert verdicts[0] == Verdict.PASS


def test_recovers_after_window_and_reputation_decays(now):
    s = MemoryStore()
    for _ in range(60):
        ev(s)
    now[0] += 15
    sig = ev(s)
    assert sig.verdict == Verdict.WARN and "abusive" in sig.reason
    now[0] += 600
    assert ev(s).verdict == Verdict.PASS


def test_datacenter_warns(now):
    sig = ev(MemoryStore(), "34.80.1.1")
    assert sig.verdict == Verdict.WARN and sig.score == 40


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.1.2.3", "172.18.0.5", "192.168.1.9", "::1"])
def test_private_is_residential(now, ip):
    assert ev(MemoryStore(), ip).verdict == Verdict.PASS


def test_env_bad_cidrs(now, monkeypatch):
    monkeypatch.setenv("LAB_BAD_CIDRS", "100.64.0.0/10, bogus")
    assert ev(MemoryStore(), "100.64.1.1").verdict == Verdict.WARN


def test_bad_ip(now):
    assert ev(MemoryStore(), "nope").verdict == Verdict.WARN


def test_ips_isolated(now):
    s = MemoryStore()
    for _ in range(100):
        ev(s, "198.18.0.1")
    assert ev(s, "203.0.113.9").verdict == Verdict.PASS
