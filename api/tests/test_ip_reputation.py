import asyncio

import app.modules.ip_reputation as m
import pytest
from app.contract import RequestContext, Verdict
from app.store import MemoryStore

CHROME_JA4 = "t13d1516h2_8daaf6152771_d8a2da3f94cd"


@pytest.fixture
def now(monkeypatch):
    t = [1_000_000.0]
    monkeypatch.setattr(m, "_clock", lambda: t[0])
    for var in (
        "LAB_BAD_CIDRS", "LAB_RATE_IDENTIFIER", "LAB_RATE_BURST_WINDOW",
        "LAB_RATE_BURST_THRESHOLD", "LAB_RATE_AVG_THRESHOLD", "LAB_PENALTY_BOX_SECONDS",
    ):
        monkeypatch.delenv(var, raising=False)
    return t


def ctx(store, ip="203.0.113.7", ua="x", ja4="", flags=None, path="/", query=None):
    return RequestContext(
        method="GET", path=path, client_ip=ip, headers=[], header_order=[], cookies={},
        user_agent=ua, ja4=ja4, store=store, flags=flags or {}, query=query or {},
    )


def ev(store, **kw):
    return asyncio.run(m.IpReputationModule().evaluate(ctx(store, **kw)))


def test_normal_harness_run_passes_even_unthrottled(now):
    # 80 sequential requests inside one second (worst case for a fast local harness).
    s = MemoryStore()
    for _ in range(80):
        assert ev(s).verdict == Verdict.PASS


def test_normal_harness_run_with_protected_paths_stays_below_reputation_threshold(now):
    s = MemoryStore()
    for i in range(80):
        now[0] += 0.7
        assert ev(s, path="/protected/all").verdict == Verdict.PASS, i


def test_burst_denies_and_enters_penalty_box(now):
    s = MemoryStore()
    out = [ev(s) for _ in range(130)]
    assert out[0].verdict == Verdict.PASS
    first = next(i for i, x in enumerate(out) if x.verdict == Verdict.BLOCK)
    assert first == 100  # > 20 hits/s over the 5 s window means the 101st hit in one second
    assert "burst" in out[first].reason and "penalty box 600s" in out[first].reason
    assert "penalty box" in out[-1].reason
    assert out[-1].details["penalty_remaining_s"] > 0


def test_penalty_box_persists_then_expires(now):
    s = MemoryStore()
    for _ in range(101):
        ev(s)
    now[0] += 599
    assert ev(s).verdict == Verdict.BLOCK
    now[0] += 2
    assert ev(s).verdict == Verdict.PASS


def test_penalty_box_env_override_is_flagged_as_lab_convenience(now, monkeypatch):
    monkeypatch.setenv("LAB_PENALTY_BOX_SECONDS", "30")
    s = MemoryStore()
    for _ in range(101):
        last = ev(s)
    assert last.verdict == Verdict.BLOCK and last.details["penalty_below_akamai_minimum"] is True
    now[0] += 31
    assert ev(s).verdict == Verdict.PASS


def test_penalty_seconds_is_clamped_to_akamai_range(monkeypatch):
    monkeypatch.delenv("LAB_PENALTY_BOX_SECONDS", raising=False)
    assert m.penalty_seconds() == (600, False)
    monkeypatch.setenv("LAB_PENALTY_BOX_SECONDS", "999999")
    assert m.penalty_seconds() == (86400, False)
    monkeypatch.setenv("LAB_PENALTY_BOX_SECONDS", "0")
    assert m.penalty_seconds() == (1, True)
    monkeypatch.setenv("LAB_PENALTY_BOX_SECONDS", "junk")
    assert m.penalty_seconds() == (600, False)


def test_burst_window_and_threshold_are_configurable(now, monkeypatch):
    monkeypatch.setenv("LAB_RATE_BURST_WINDOW", "1")
    monkeypatch.setenv("LAB_RATE_BURST_THRESHOLD", "5")
    s = MemoryStore()
    out = [ev(s).verdict for _ in range(7)]
    assert out[:5] == [Verdict.PASS] * 5 and out[5] == Verdict.BLOCK


def test_burst_window_is_clamped_to_1_5_seconds(now, monkeypatch):
    monkeypatch.setenv("LAB_RATE_BURST_WINDOW", "99")
    assert ev(MemoryStore()).details["burst_window_s"] == 5


def test_slow_requests_do_not_trip_the_burst_threshold(now, monkeypatch):
    monkeypatch.setenv("LAB_RATE_BURST_WINDOW", "5")
    s = MemoryStore()
    for _ in range(300):
        now[0] += 1.0  # 1 hit/s forever: under the 2 hits/s average too
        assert ev(s).verdict == Verdict.PASS


def test_average_threshold_over_two_minutes(now, monkeypatch):
    monkeypatch.setenv("LAB_RATE_AVG_THRESHOLD", "1")  # 120 hits per 2 min
    s = MemoryStore()
    verdicts = []
    for _ in range(300):
        now[0] += 0.5  # 2 hits/s: fine for the burst limit, above the 1 hit/s average
        verdicts.append(ev(s))
    first = next(v for v in verdicts if v.verdict == Verdict.BLOCK)
    assert "average" in first.reason and "over 2 min" in first.reason


def test_ips_isolated(now):
    s = MemoryStore()
    for _ in range(110):
        ev(s, ip="198.18.0.1")
    assert ev(s, ip="198.18.0.1").verdict == Verdict.BLOCK
    assert ev(s, ip="203.0.113.9").verdict == Verdict.PASS


# --- client identifiers ----------------------------------------------------------------------


def test_identifier_ip_useragent_separates_user_agents(now, monkeypatch):
    monkeypatch.setenv("LAB_RATE_IDENTIFIER", "ip-useragent")
    s = MemoryStore()
    for _ in range(110):
        ev(s, ua="bot/1")
    assert ev(s, ua="bot/1").verdict == Verdict.BLOCK
    other = ev(s, ua="Mozilla/5.0 browser")
    assert other.verdict == Verdict.PASS and other.details["identifier"] == "ip-useragent"


def test_identifier_ip_ignores_user_agent(now):
    s = MemoryStore()
    for _ in range(110):
        ev(s, ua="bot/1")
    assert ev(s, ua="Mozilla/5.0 browser").verdict == Verdict.BLOCK


def test_identifier_tls_fingerprint_is_shared_across_ips(now):
    s = MemoryStore()
    flags = {"rate_id_tls_fingerprint": True}
    for i in range(110):
        ev(s, ip=f"198.18.0.{i % 200 + 1}", ja4=CHROME_JA4, flags=flags)
    other_ip = ev(s, ip="198.18.9.9", ja4=CHROME_JA4, flags=flags)
    assert other_ip.verdict == Verdict.BLOCK
    assert other_ip.details["client_id"] == f"ja4:{CHROME_JA4}"
    unseen = ev(s, ip="198.18.9.9", ja4="t13d0000h2_aaaaaaaaaaaa_bbbbbbbbbbbb", flags=flags)
    assert unseen.verdict == Verdict.PASS


def test_flag_overrides_env_identifier(now, monkeypatch):
    monkeypatch.setenv("LAB_RATE_IDENTIFIER", "tls-fingerprint")
    sig = ev(MemoryStore(), flags={"rate_id_ip_useragent": True})
    assert sig.details["identifier"] == "ip-useragent"


def test_invalid_env_identifier_falls_back_to_ip(now, monkeypatch):
    monkeypatch.setenv("LAB_RATE_IDENTIFIER", "cookie:foo")
    assert ev(MemoryStore()).details["identifier"] == "ip"


# --- client reputation categories ------------------------------------------------------------


def test_webscrp_threshold_at_160_protected_hits(now):
    s = MemoryStore()
    seen = []
    for _ in range(170):
        now[0] += 0.7  # slow enough to stay under both rate controls
        seen.append(ev(s, path="/protected/all"))
    assert seen[100].details["reputation_categories"]["WEBSCRP"] == 6
    assert seen[100].verdict == Verdict.WARN
    first_fail = next(i for i, x in enumerate(seen) if x.verdict == Verdict.FAIL)
    assert first_fail == 140  # the 141st protected hit: ceil(141 / 20) = 8
    assert "WEBSCRP" in seen[first_fail].reason and seen[first_fail].score == 75


def test_webatck_from_attack_looking_requests(now):
    s = MemoryStore()
    assert ev(s, path="/protected/all", query={"q": "' OR 1=1 --"}).verdict == Verdict.PASS
    sig = ev(s, path="/protected/all", query={"file": "../../etc/passwd"})
    assert sig.verdict == Verdict.FAIL and "WEBATCK" in sig.reason


def test_dosatck_rises_after_repeated_rate_denies(now, monkeypatch):
    monkeypatch.setenv("LAB_PENALTY_BOX_SECONDS", "5")
    monkeypatch.setenv("LAB_RATE_BURST_THRESHOLD", "3")
    monkeypatch.setenv("LAB_RATE_BURST_WINDOW", "1")
    s = MemoryStore()
    for _ in range(2):
        for _ in range(5):
            ev(s)
        now[0] += 6  # box expired
    sig = ev(s)
    assert sig.verdict == Verdict.FAIL and "DOSATCK 8/10" in sig.reason


def test_scantl_counter_hook(now):
    s = MemoryStore()
    for _ in range(8):
        asyncio.run(m.record_scan_probe(s, "203.0.113.7"))
    sig = ev(s)
    assert sig.verdict == Verdict.FAIL and "SCANTL" in sig.reason


def test_category_scores_mapping():
    assert m.category_scores({}) == dict.fromkeys(m.CATEGORIES, 0)
    assert m.category_scores({"WEBSCRP": 160})["WEBSCRP"] == 8
    assert m.category_scores({"WEBSCRP": 9999})["WEBSCRP"] == 10
    assert m.category_scores({"WEBATCK": 2, "DOSATCK": 1}) == {
        "DOSATCK": 4, "SCANTL": 0, "WEBATCK": 8, "WEBSCRP": 0,
    }


# --- hosting ASN (assumption flag) and customer list -----------------------------------------


def test_datacenter_range_is_ignored_without_the_assumption_flag(now):
    sig = ev(MemoryStore(), ip="34.80.1.1")
    assert sig.verdict == Verdict.PASS


def test_datacenter_warns_only_with_hosting_asn_penalty_flag(now):
    sig = ev(MemoryStore(), ip="34.80.1.1", flags={"hosting_asn_penalty": True})
    assert sig.verdict == Verdict.WARN and sig.score == 40
    assert sig.details["assumption"] is True and "ASSUMPTION" in sig.reason


def test_flag_declared_low_and_default_off():
    specs = {f.name: f for f in m.IpReputationModule.flags}
    asn = specs["hosting_asn_penalty"]
    assert asn.confidence.value == "low" and asn.default is False
    assert not specs["rate_id_ip_useragent"].default
    assert not specs["rate_id_tls_fingerprint"].default


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.1.2.3", "172.18.0.5", "192.168.1.9", "::1"])
def test_private_is_residential(now, ip):
    assert ev(MemoryStore(), ip=ip, flags={"hosting_asn_penalty": True}).verdict == Verdict.PASS


def test_env_bad_cidrs_models_customer_client_list(now, monkeypatch):
    monkeypatch.setenv("LAB_BAD_CIDRS", "100.64.0.0/10, bogus")
    sig = ev(MemoryStore(), ip="100.64.1.1")  # no flag needed: customer-configured
    assert sig.verdict == Verdict.WARN and "customer client list" in sig.reason


def test_bad_ip(now):
    assert ev(MemoryStore(), ip="nope").verdict == Verdict.WARN
