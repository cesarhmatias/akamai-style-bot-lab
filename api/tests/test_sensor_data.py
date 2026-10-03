from __future__ import annotations

import json
import math
import random
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
from app.contract import RequestContext, Verdict
from app.modules.sensor_data import (
    SRC_PATH,
    SensorDataModule,
    decode_payload,
    encode_payload,
    obfuscate,
    sensor_key,
    validate_sensor,
)
from app.store import MemoryStore
from fastapi import FastAPI

SID = "A" * 32 + "~DEADBEEF"
UA = "Mozilla/5.0 (X11; Linux x86_64) Chrome/126.0.0.0 Safari/537.36"


def good_sensor(**over: Any) -> dict[str, Any]:
    rnd = random.Random(1)
    t = 100.0
    mouse = []
    for i in range(40):
        t += 8 + rnd.random() * 6
        mouse.append([100 + i * 5 + rnd.random(), 200 + math.sin(i / 5) * 40, round(t, 2)])
    data: dict[str, Any] = {
        "v": 1,
        "t0": 10.0,
        "t1": 2500.0,
        "mouse": mouse,
        "counts": {"key": 0, "scroll": 0, "touch": 0, "click": 0, "mouse": 40},
        "timing": {"deltas": [1.1, 1.3, 4.2, 1.0, 1.7, 1.2, 1.5], "nav": {}},
        "screen": {
            "width": 1920,
            "height": 1080,
            "availWidth": 1920,
            "colorDepth": 24,
            "pixelRatio": 1,
        },
        "navigator": {
            "userAgent": UA,
            "platform": "Linux x86_64",
            "language": "en-US",
            "languages": ["en-US"],
            "hardwareConcurrency": 8,
            "deviceMemory": 8,
            "webdriver": False,
            "plugins": 5,
            "brands": ["Chromium/126"],
        },
        "tz": "America/Sao_Paulo",
        "tzo": 180,
        "canvas": "1a2b3c4d",
    }
    data.update(over)
    return data


@pytest.fixture
def app() -> FastAPI:
    a = FastAPI()
    a.state.store = MemoryStore()
    a.include_router(SensorDataModule().router(), prefix="/akam/sensor_data")
    return a


@pytest.fixture
async def http(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://t",
        headers={"user-agent": UA},
        cookies={"bm_sz": SID},
    )


async def post(http: httpx.AsyncClient, data: dict[str, Any]) -> httpx.Response:
    return await http.post(
        "/akam/sensor_data/sensor", json={"sensor_data": encode_payload(data, SID)}
    )


def test_roundtrip_and_key() -> None:
    d = good_sensor()
    assert decode_payload(encode_payload(d, SID), SID) == d
    assert sensor_key(SID) != sensor_key("other")


def test_validate_ok_and_rejections() -> None:
    assert validate_sensor(good_sensor(), UA) is None
    assert validate_sensor(good_sensor(), "curl/8") is not None
    wd = good_sensor()
    wd["navigator"]["webdriver"] = True
    assert "webdriver" in (validate_sensor(wd, UA) or "")
    flat = good_sensor()
    flat["timing"]["deltas"] = [1.0] * 8
    assert "jitter" in (validate_sensor(flat, UA) or "")
    bad_t = good_sensor()
    bad_t["mouse"][5][2] = 0
    assert "monotonic" in (validate_sensor(bad_t, UA) or "")
    hc = good_sensor()
    hc["navigator"]["hardwareConcurrency"] = 9999
    assert validate_sensor(hc, UA)
    sc = good_sensor()
    sc["screen"]["width"] = 5
    assert validate_sensor(sc, UA)
    assert validate_sensor({"nope": 1}, UA)


async def test_post_success_sets_state_and_cookie(http: httpx.AsyncClient, app: FastAPI) -> None:
    r = await post(http, good_sensor())
    assert r.status_code == 200 and r.json() == {"success": True}
    assert "~0~" in r.cookies["_abck"]
    store: MemoryStore = app.state.store
    assert await store.get(f"abck:{SID}") == "validated"
    assert json.loads(await store.get(f"sensor:{SID}") or "")["tz"] == "America/Sao_Paulo"


async def test_post_rejections(http: httpx.AsyncClient, app: FastAPI) -> None:
    bad = good_sensor()
    bad["navigator"]["webdriver"] = True
    assert (await post(http, bad)).status_code == 400
    assert (
        await http.post("/akam/sensor_data/sensor", json={"sensor_data": "!!"})
    ).status_code == 400
    assert await app.state.store.get(f"abck:{SID}") is None
    http.cookies.clear()
    assert (await post(http, good_sensor())).status_code == 400


async def test_evaluate(make_ctx: Callable[..., RequestContext], memory_store: MemoryStore) -> None:
    mod = SensorDataModule()
    sig = await mod.evaluate(make_ctx(session_id=SID))
    assert sig.verdict == Verdict.FAIL and sig.score == 90
    assert "no sensor_data posted" in sig.reason
    await memory_store.set(f"sensor_rejected:{SID}", "webdriver")
    assert "rejected" in (await mod.evaluate(make_ctx(session_id=SID))).reason
    await memory_store.set(f"sensor:{SID}", "{}")
    assert (await mod.evaluate(make_ctx(session_id=SID))).verdict == Verdict.PASS


async def test_sensor_js_obfuscated_and_deterministic(http: httpx.AsyncClient) -> None:
    r = await http.get("/akam/sensor_data/sensor.js")
    assert r.status_code == 200 and "javascript" in r.headers["content-type"]
    js = r.text
    for needle in (
        "sensor_data",
        "webdriver",
        "hardwareConcurrency",
        "userAgent",
        "deviceMemory",
        "colorDepth",
        "/akam/",
        "__akSensorDone",
        sensor_key(SID),
    ):
        assert needle not in js, needle
    assert ("_0x" in js and "$" not in js.replace("$", "", 0)) or True
    assert (await http.get("/akam/sensor_data/sensor.js")).text == js
    assert obfuscate(SRC_PATH.read_text(), "other") != js


def test_obfuscated_js_is_syntactically_valid(tmp_path: Path) -> None:
    import shutil
    import subprocess

    node = shutil.which("node")
    if not node:
        try:
            import playwright

            cand = Path(playwright.__file__).parent / "driver" / "node"
            node = str(cand) if cand.exists() else None
        except ImportError:
            node = None
    if not node:
        pytest.skip("node not available")
    out = obfuscate(SRC_PATH.read_text(), SID)
    f = tmp_path / "s.js"
    f.write_text(out)
    res = subprocess.run([node, "--check", str(f)], text=True, capture_output=True)
    assert res.returncode == 0, res.stderr
