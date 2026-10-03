"""Account Protector: per-username profile, risk factors, Akamai-User-Risk header."""

from __future__ import annotations

import httpx
import pytest
from app.main import create_app
from app.modules.account_protector import AccountProtector, net16, net24, ua_family, username_of
from app.store import MemoryStore

CHROME_WIN = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36"
)
FIREFOX_LINUX = "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0"
JA4_CHROME = "t13d1516h2_8daaf6152771_02713d6af862"
JA4_OTHER = "t13d1715h2_5b57614c22b0_3d5424432f57"


def test_helpers() -> None:
    assert ua_family(CHROME_WIN) == "chrome-windows" and ua_family(FIREFOX_LINUX) == "firefox-linux"
    assert net24("203.0.113.9") == "203.0.113" and net16("203.0.113.9") == "203.0"
    assert net24("2001:db8:1:2::1") == "2001:db8:1" and net16("2001:db8:1::1") == "2001:db8"
    assert username_of(b'{"username": " Ann@X.com "}') == "ann@x.com"
    assert username_of(b"nope") == "" and username_of(b"[1]") == ""


@pytest.fixture
async def http():  # type: ignore[no-untyped-def]
    app = create_app(store=MemoryStore(), modules=[AccountProtector()])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        await c.put("/api/policy", json={"params": {"delay_seconds": 0.01}})
        yield c


async def login(
    c: httpx.AsyncClient,
    user: str,
    ip: str = "203.0.113.5",
    ua: str = CHROME_WIN,
    ja4: str = JA4_CHROME,
) -> dict:
    r = await c.post(
        "/api/login",
        json={"username": user},
        headers={"x-client-ip": ip, "user-agent": ua, "x-ja4": ja4},
    )
    rep = (await c.get(f"/api/requests/{r.headers['x-lab-report-id']}")).json()
    rep["_status"] = r.status_code
    return rep


def signal(rep: dict) -> dict:
    return next(s for s in rep["signals"] if s["module"] == "account_protector")


async def test_first_login_then_familiar_login(http: httpx.AsyncClient) -> None:
    first = await login(http, "ann")
    assert (
        signal(first)["verdict"] == "pass" and signal(first)["details"]["user_risk"]["status"] == 0
    )
    h = first["origin_headers"]["Akamai-User-Risk"]
    assert (
        h.startswith("uuid=")
        and f"requestid={first['id']};status=0;score=0;general=gnew_user;" in h
    )
    assert h.endswith("allow=0;action=allow")
    again = await login(http, "ann")
    s = signal(again)
    assert s["verdict"] == "pass" and s["details"]["user_risk"]["allow"] == 1
    trust = again["origin_headers"]["Akamai-User-Risk"]
    assert (
        "udbp:chrome-windows" in trust and "unp:203.0.113" in trust and "udfp:t13d1516h2" in trust
    )
    assert "general=gknown_user" in trust and "status=4" in trust


async def test_new_device_and_network_raise_risk(http: httpx.AsyncClient) -> None:
    await login(http, "bob")
    dev = await login(http, "bob", ua=FIREFOX_LINUX, ja4=JA4_OTHER)
    s = signal(dev)
    assert s["verdict"] == "warn" and s["score"] == 35 and "unewdev" in s["details"]["risk_factors"]
    net = await login(http, "bob", ip="203.0.114.8")  # same /16, new /24, within minutes: no travel
    assert signal(net)["score"] == 20 and signal(net)["details"]["risk_factors"] == ["unewnet"]


async def test_impossible_travel(http: httpx.AsyncClient) -> None:
    await login(http, "cat")
    far = await login(http, "cat", ip="198.51.100.9")
    s = signal(far)
    assert "utravel" in s["details"]["risk_factors"] and s["score"] == 60  # travel 40 + new net 20
    assert s["verdict"] == "fail"
    assert "risk=unewnet|utravel" in far["origin_headers"]["Akamai-User-Risk"]


async def test_disposable_email_domain(http: httpx.AsyncClient) -> None:
    rep = await login(http, "x@mailinator.com")
    s = signal(rep)
    assert s["verdict"] == "warn" and s["score"] == 35
    assert "risk=udisp" in rep["origin_headers"]["Akamai-User-Risk"]
    ok = await login(http, "y@example.com")
    assert signal(ok)["score"] == 0


async def test_risky_login_does_not_poison_the_profile(http: httpx.AsyncClient) -> None:
    await login(http, "dan")
    bad = await login(http, "dan", ip="198.51.100.9", ua=FIREFOX_LINUX, ja4=JA4_OTHER)
    assert signal(bad)["score"] >= 40 and bad["action"] in {"serve_alternate", "challenge", "deny"}
    again = await login(http, "dan", ip="198.51.100.9", ua=FIREFOX_LINUX, ja4=JA4_OTHER)
    assert "unewdev" in signal(again)["details"]["risk_factors"]  # still unknown


async def test_only_login_is_evaluated(http: httpx.AsyncClient) -> None:
    r = await http.post("/api/checkout", json={})
    rep = (await http.get(f"/api/requests/{r.headers['x-lab-report-id']}")).json()
    assert signal(rep)["verdict"] == "skip" and "Akamai-User-Risk" not in rep["origin_headers"]
    r = await http.get("/protected/account_protector")
    assert r.status_code == 200  # skip on a non-login path


async def test_hour_anomaly_after_enough_history(http: httpx.AsyncClient) -> None:
    import json as _json

    from app.modules.account_protector import AccountProtector as AP

    await login(http, "eve")
    store = http._transport.app.state.store  # type: ignore[attr-defined]
    key = AP._key("eve")
    prof = _json.loads(await store.get(key))
    import time as _t

    other = (_t.gmtime().tm_hour + 5) % 24
    prof["hours"] = [other, (other + 1) % 24, (other + 2) % 24, (other + 3) % 24, (other + 4) % 24]
    await store.set(key, _json.dumps(prof))
    rep = await login(http, "eve")
    assert "uhour" in signal(rep)["details"]["risk_factors"]
