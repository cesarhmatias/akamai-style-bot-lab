"""AVF step-up: armed only by the strict segment, collected on demand, re-scored."""

from __future__ import annotations

import httpx
import pytest
from app.contract import Verdict
from app.main import create_app
from app.modules.avf_stepup import AvfStepup, analyze
from app.store import MemoryStore
from test_actions import Scored

SID = "e" * 32 + "~deadbeef"
CHROME_WIN = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0"
GOOD = {
    "webgl": {"vendor": "Google Inc. (NVIDIA)", "renderer": "ANGLE (NVIDIA, Direct3D11)"},
    "audio": "124.043478",
    "fonts": 11,
}


def test_analyze() -> None:
    assert analyze(GOOD, CHROME_WIN) == (0, [])
    swift = {**GOOD, "webgl": {"vendor": "Google Inc.", "renderer": "ANGLE (SwiftShader)"}}
    assert analyze(swift, CHROME_WIN)[0] == 35
    mesa = {**GOOD, "webgl": {"vendor": "x", "renderer": "Mesa Intel"}}
    assert any("contradicts" in f for f in analyze(mesa, CHROME_WIN)[1])
    empty = {"webgl": {}, "audio": "", "fonts": "n/a"}
    score, findings = analyze(empty, CHROME_WIN)
    assert score == 70 and len(findings) == 3


@pytest.fixture
async def http():  # type: ignore[no-untyped-def]
    app = create_app(store=MemoryStore(), modules=[Scored(), AvfStepup()])
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://t",
        cookies={"bm_sz": SID},
        headers={"user-agent": CHROME_WIN},
    ) as c:
        yield c


async def sig(http: httpx.AsyncClient, score: str) -> dict:
    r = await http.get("/protected/avf_stepup", headers={"x-score": score})
    return next(s for s in r.json()["report"]["signals"] if s["module"] == "avf_stepup")


async def test_not_requested_until_strict_then_script_then_rescored(
    http: httpx.AsyncClient,
) -> None:
    assert "stepup.js" not in (await http.get("/")).text  # nobody asked
    assert (await sig(http, "0"))["verdict"] == "skip"
    # a cautious request does not arm it
    await http.get("/protected/all", headers={"x-score": "10"})
    assert "stepup.js" not in (await http.get("/")).text
    # a strict one does
    strict = await http.get("/protected/all", headers={"x-score": "40"})
    assert strict.json()["report"]["segment"] == "strict"
    assert "/akam/avf_stepup/stepup.js" in (await http.get("/")).text
    miss = await sig(http, "0")
    assert miss["verdict"] == "warn" and miss["score"] == 30 and miss["details"]["requested"]
    js = await http.get("/akam/avf_stepup/stepup.js")
    assert "WEBGL_debug_renderer_info" in js.text and "OfflineAudioContext" in js.text
    ok = await http.post("/akam/avf_stepup/data", json=GOOD)
    assert ok.json() == {"ok": True, "stepup_score": 0, "findings": []}
    after = await sig(http, "0")
    assert after["verdict"] == "pass" and after["score"] == 0
    assert "stepup.js" not in (await http.get("/")).text  # collected: stop asking


async def test_suspicious_data_scores_and_validation(http: httpx.AsyncClient) -> None:
    assert (await http.post("/akam/avf_stepup/data", json=GOOD)).status_code == 403  # not asked
    await http.get("/protected/all", headers={"x-score": "40"})
    assert (await http.post("/akam/avf_stepup/data", json={"x": 1})).status_code == 400
    assert (await http.post("/akam/avf_stepup/data", content=b"nope")).status_code == 400
    bad = {"webgl": {"vendor": "g", "renderer": "SwiftShader"}, "audio": "0", "fonts": 1}
    r = await http.post("/akam/avf_stepup/data", json=bad)
    assert r.json()["stepup_score"] == 80
    s = await sig(http, "0")
    assert s["verdict"] == Verdict.FAIL and s["score"] == 80


async def test_challenge_interstitial_also_carries_the_script(http: httpx.AsyncClient) -> None:
    await http.get("/protected/all", headers={"x-score": "40"})
    page = await http.get("/protected/all", headers={"x-score": "40", "accept": "text/html"})
    # no challenge module in this app, so the 428 JSON is returned; the landing page proves
    # the snippet path used by interstitials (page_markup)
    assert page.status_code == 428
    assert "stepup.js" in (await http.get("/", headers={"accept": "text/html"})).text
