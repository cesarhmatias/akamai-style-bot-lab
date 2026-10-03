from __future__ import annotations

import json
import math
import random
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
from app.contract import RequestContext, Verdict
from app.main import create_app
from app.modules.abck_cookie import AbckCookieModule
from app.modules.js_integrity import JsIntegrityModule
from app.modules.sensor_data import (
    PATH_SEGMENTS,
    PayloadError,
    SensorCodec,
    SensorDataModule,
    obfuscate,
    validate_sensor,
)
from app.session import ABCK_RE
from app.store import MemoryStore
from browser_stub import MOUSE_DRIVER, run_js

UA = "Mozilla/5.0 (X11; Linux x86_64) Chrome/126.0.0.0 Safari/537.36"
NATIVE_GETTER = {"where": "proto", "accessor": True, "native": True, "name_ok": True}
NATIVE_INTEGRITY: dict[str, Any] = {
    "nav": {
        k: NATIVE_GETTER
        for k in (
            "webdriver",
            "userAgent",
            "platform",
            "languages",
            "hardwareConcurrency",
            "plugins",
        )
    },
    "fts_native": True,
    "globals": [],
    "chrome": {"present": True, "keys": ["app", "csi", "loadTimes"]},
}


def good_sensor(**over: Any) -> dict[str, Any]:
    rnd = random.Random(1)
    t = 100.0
    mouse = []
    for i in range(40):
        t += 8 + rnd.random() * 6
        mouse.append([100 + i * 5 + rnd.random(), 200 + math.sin(i / 5) * 40, round(t, 2)])
    data: dict[str, Any] = {
        "v": 2,
        "t0": 10.0,
        "t1": 2500.0,
        "mouse": mouse,
        "keys": [],
        "touch": [],
        "scroll": [],
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
        "integrity": NATIVE_INTEGRITY,
        "tz": "America/Sao_Paulo",
        "tzo": 180,
        "canvas": "1a2b3c4d",
    }
    data.update(over)
    return data


def module_abck(r: httpx.Response) -> str:
    """The _abck the SENSOR module set (first Set-Cookie; main.finalize_cookies may add more)."""
    for h in r.headers.get_list("set-cookie"):
        if h.startswith("_abck="):
            return h.split(";")[0].split("=", 1)[1]
    raise AssertionError("no _abck Set-Cookie")


class Lab:
    """A lab app with one browser-like client (cookie jar) and helpers."""

    def __init__(self, mod: SensorDataModule | None = None) -> None:
        self.store = MemoryStore()
        self.mod = mod or SensorDataModule()
        self.app = create_app(
            store=self.store, modules=[self.mod, AbckCookieModule(), JsIntegrityModule()]
        )

    def client(self, **headers: str) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app),
            base_url="http://t",
            headers={"user-agent": UA, **headers},
        )

    async def start(self, c: httpx.AsyncClient) -> tuple[str, str]:
        """Load the landing page; return (sid, per-session sensor path)."""
        html = (await c.get("/", headers={"accept": "text/html"})).text
        sid = c.cookies["bm_sz"]
        m = re.search(r'<script type="text/javascript" src="(/[^"]+)"></script>', html)
        assert m, html
        return sid, m.group(1)

    def payload(self, sid: str, data: dict[str, Any], idx: int = 0) -> dict[str, str]:
        return {"sensor_data": self.mod.codec.encode(data, sid, idx)}


@pytest.fixture
def lab() -> Lab:
    return Lab()


# ---- codec and path ---------------------------------------------------------------------


def test_codec_roundtrip_and_session_binding() -> None:
    codec = SensorCodec(b"s" * 32, "build001")
    d = good_sensor()
    assert codec.decode(codec.encode(d, "sidA", 1), "sidA") == (1, d)
    assert codec.key("sidA") != codec.key("sidB")
    assert codec.prefix_hash("sidA") != codec.prefix_hash("sidB")
    with pytest.raises(PayloadError, match="not minted"):
        codec.decode(codec.encode(d, "sidA"), "sidB")  # session A payload in session B
    other_build = SensorCodec(b"s" * 32, "build002")
    with pytest.raises(PayloadError, match="not minted"):
        other_build.decode(codec.encode(d, "sidA"), "sidA")  # another script build
    other_secret = SensorCodec(b"t" * 32, "build001")
    with pytest.raises(PayloadError):
        other_secret.decode(codec.encode(d, "sidA"), "sidA")


def test_codec_rejects_bad_payloads() -> None:
    codec = SensorCodec(b"s" * 32, "b")
    good = codec.encode({"a": 1}, "sid")
    prefix = good.rsplit(";", 1)[0]
    for bad in (
        "garbage",
        good.replace("lab3", "3", 1),
        good.replace(";0;1;0;", ";0;1;9;", 1),
        f"{prefix};!!notbase64",
        f"{prefix};{'QUJD'}",  # valid base64, wrong xor -> not json
    ):
        with pytest.raises(PayloadError):
            codec.decode(bad, "sid")
    plain = good.split(";")
    plain[5] = (
        __import__("base64")
        .b64encode(bytes(b ^ ord(codec.key("sid")[i % 32]) for i, b in enumerate(b'["list"]')))
        .decode()
    )
    with pytest.raises(PayloadError, match="not an object"):
        codec.decode(";".join(plain), "sid")


def test_path_shape_rotates_per_session_and_build() -> None:
    codec = SensorCodec(b"s" * 32, "b1")
    p = codec.path("sidA")
    assert re.fullmatch(r"(/[A-Za-z0-9]+){9}", p)
    assert tuple(len(s) for s in p.strip("/").split("/")) == PATH_SEGMENTS
    assert p == codec.path("sidA") != codec.path("sidB")
    assert p != SensorCodec(b"s" * 32, "b2").path("sidA")


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
    assert "interaction lists" in (validate_sensor(good_sensor(keys="x"), UA) or "")


def test_validate_does_not_couple_to_integrity() -> None:
    # a tampered getter does not reject the sensor: js_integrity scores it, _abck stays decoupled
    tampered = good_sensor()
    tampered["integrity"] = {**NATIVE_INTEGRITY, "globals": ["__playwright_x"], "fts_native": False}
    assert validate_sensor(tampered, UA) is None


# ---- page integration and script serving ------------------------------------------------


async def test_page_injects_per_session_path_and_old_routes_are_gone(lab: Lab) -> None:
    async with lab.client() as c:
        sid, path = await lab.start(c)
        assert path == lab.mod.codec.path(sid)
        async with lab.client() as c2:
            _, path2 = await lab.start(c2)
        assert path2 != path
        assert (await c.get("/akam/sensor_data/sensor.js")).status_code == 404
        assert (await c.post("/akam/sensor_data/sensor", json={})).status_code == 404
    assert SensorDataModule.client_scripts == []


async def test_script_served_obfuscated_deterministic_and_session_scoped(lab: Lab) -> None:
    async with lab.client() as c:
        sid, path = await lab.start(c)
        r = await c.get(path)
        assert r.status_code == 200 and "javascript" in r.headers["content-type"]
        js = r.text
        for needle in (
            *("sensor_data", "webdriver", "hardwareConcurrency", "userAgent", "deviceMemory"),
            *("colorDepth", "__akSensorDone", "native code", "playwright"),
            *(path, lab.mod.codec.key(sid)),
        ):
            assert needle not in js, needle
        assert (await c.get(path)).text == js
        assert obfuscate("var $a = 'x';", "one") != obfuscate("var $a = 'x';", "two")
        # another session cannot fetch this session's script path
        async with lab.client() as other:
            await lab.start(other)
            assert (await other.get(path)).status_code == 404
        # no cookie at all -> 404 (a fresh session id is minted, its path differs)
        async with lab.client() as bare:
            assert (await bare.get(path)).status_code == 404


async def test_cdp_flag_changes_served_script(lab: Lab) -> None:
    async with lab.client() as c:
        sid, path = await lab.start(c)
        assert (await c.get(path)).text == lab.mod.render_script(sid, cdp=False)
        await lab.store.set("flag:cdp_probes", "1")
        assert (await c.get(path)).text == lab.mod.render_script(sid, cdp=True)
        assert lab.mod.render_script(sid, cdp=True) != lab.mod.render_script(sid, cdp=False)


# ---- POST protocol ----------------------------------------------------------------------


async def test_post_success_sets_state_and_refreshes_cookie(lab: Lab) -> None:
    async with lab.client() as c:
        sid, path = await lab.start(c)
        before = c.cookies["_abck"]
        r = await c.post(path, json=lab.payload(sid, good_sensor()))
        assert r.status_code == 200 and r.json() == {"success": True, "more": 0}
        new = module_abck(r)
        m = ABCK_RE.match(new)
        assert m and m.group(2) == "-1"  # default mode: flag stays -1, server holds the truth
        assert new.split("~")[0] == before.split("~")[0]  # same id, new blob
        assert new != before
        assert "Max-Age=31536000" in r.headers.get_list("set-cookie")[0]
        assert await lab.store.get(f"abck:{sid}") == "validated"
        assert await lab.store.get(f"sensor:n:{sid}") == "1"
        stored = json.loads(await lab.store.get(f"sensor:{sid}") or "")
        assert stored["tz"] == "America/Sao_Paulo" and stored["navigator"]["brands"]
        integ = json.loads(await lab.store.get(f"sensor:integrity:{sid}") or "")
        assert integ["integrity"]["fts_native"] is True
        assert json.loads(await lab.store.get(f"abck:bind:{sid}") or "")["ua"] == UA


async def test_one_to_three_posts_then_rejected(lab: Lab) -> None:
    async with lab.client() as c:
        sid, path = await lab.start(c)
        for i in range(3):
            r = await c.post(path, json=lab.payload(sid, good_sensor(), i))
            assert r.status_code == 200, (i, r.text)
        assert await lab.store.get(f"sensor:n:{sid}") == "3"
        r = await c.post(path, json=lab.payload(sid, good_sensor(), 0))
        assert r.status_code == 429 and "too many" in r.json()["reason"]


async def test_replayed_or_out_of_order_post_rejected(lab: Lab) -> None:
    async with lab.client() as c:
        sid, path = await lab.start(c)
        assert (await c.post(path, json=lab.payload(sid, good_sensor(), 0))).status_code == 200
        r = await c.post(path, json=lab.payload(sid, good_sensor(), 0))  # verbatim replay
        assert r.status_code == 400 and "post index" in r.json()["reason"]
        r = await c.post(path, json=lab.payload(sid, good_sensor(), 2))  # skipped an index
        assert r.status_code == 400
        assert await lab.store.get(f"sensor:n:{sid}") == "1"


async def test_payload_from_session_a_rejected_in_session_b(lab: Lab) -> None:
    async with lab.client() as a, lab.client() as b:
        sid_a, _ = await lab.start(a)
        sid_b, path_b = await lab.start(b)
        r = await b.post(path_b, json=lab.payload(sid_a, good_sensor()))
        assert r.status_code == 400 and "not minted" in r.json()["reason"]
        assert await lab.store.get(f"abck:{sid_b}") is None
        # the same payload shape minted for B works
        assert (await b.post(path_b, json=lab.payload(sid_b, good_sensor()))).status_code == 200


async def test_payload_from_another_script_build_rejected(lab: Lab) -> None:
    other = SensorDataModule(secret=lab.mod.secret, build="deadbeef")
    async with lab.client() as c:
        sid, path = await lab.start(c)
        r = await c.post(path, json={"sensor_data": other.codec.encode(good_sensor(), sid)})
        assert r.status_code == 400 and "not minted" in r.json()["reason"]
        assert "not minted" in (await lab.store.get(f"sensor_rejected:{sid}") or "")


async def test_post_rejections(lab: Lab) -> None:
    async with lab.client() as c:
        sid, path = await lab.start(c)
        bad = good_sensor()
        bad["navigator"]["webdriver"] = True
        r = await c.post(path, json=lab.payload(sid, bad))
        assert r.status_code == 400 and "webdriver" in r.json()["reason"]
        # the integrity block of a rejected post is still kept for js_integrity
        assert await lab.store.get(f"sensor:integrity:{sid}")
        assert await lab.store.get(f"sensor:{sid}") is None
        assert (await c.post(path, json={"sensor_data": "!!"})).status_code == 400
        assert (await c.post(path, json={"nope": 1})).status_code == 400
        assert (await c.post(path, content=b"not json")).status_code == 400
        big = await c.post(path, content=b"x" * 600_000)
        assert big.status_code == 413
        assert await lab.store.get(f"abck:{sid}") is None
        c.cookies.delete("bm_sz")
        assert (await c.post(path, json=lab.payload(sid, good_sensor()))).status_code in {400, 404}


async def test_n_posts_flag_needs_three_posts_and_never_shows_tilde0(lab: Lab) -> None:
    await lab.store.set("flag:abck_n_posts", "1")
    async with lab.client() as c:
        sid, path = await lab.start(c)
        for i, more in enumerate((2, 1, 0)):
            r = await c.post(path, json=lab.payload(sid, good_sensor(), i))
            assert r.json() == {"success": True, "more": more}
            assert "~0~" not in module_abck(r)
            assert (await lab.store.get(f"abck:{sid}") == "validated") is (i == 2)


async def test_tilde0_flag_flips_cookie_on_validation(lab: Lab) -> None:
    await lab.store.set("flag:abck_tilde0_mode", "1")
    async with lab.client() as c:
        sid, path = await lab.start(c)
        before = c.cookies["_abck"]
        r = await c.post(path, json=lab.payload(sid, good_sensor()))
        m = ABCK_RE.match(module_abck(r))
        assert m and m.group(2) == "0"
        assert m.group(1) == before.split("~")[0].upper()  # the id stays stable across refreshes


async def test_changed_fingerprint_cannot_keep_posting(lab: Lab) -> None:
    ja4_a = "t13d1516h2_8daaf6152771_02713d6af862"
    async with lab.client(**{"x-ja4": ja4_a}) as c:
        sid, path = await lab.start(c)
        assert (await c.post(path, json=lab.payload(sid, good_sensor(), 0))).status_code == 200
        r = await c.post(
            path,
            json=lab.payload(sid, good_sensor(), 1),
            headers={"x-ja4": "t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb"},
        )
        assert r.status_code == 400 and "fingerprint changed" in r.json()["reason"]


# ---- scoring ----------------------------------------------------------------------------


async def test_evaluate(make_ctx: Callable[..., RequestContext], memory_store: MemoryStore) -> None:
    mod = SensorDataModule()
    sid = "A" * 32 + "~YAAQ1~2~3"
    sig = await mod.evaluate(make_ctx(session_id=sid))
    assert sig.verdict == Verdict.FAIL and sig.score == 90
    assert "no sensor_data posted" in sig.reason
    await memory_store.set(f"sensor_rejected:{sid}", "webdriver")
    assert "rejected" in (await mod.evaluate(make_ctx(session_id=sid))).reason
    await memory_store.set(f"sensor:{sid}", "{}")
    assert (await mod.evaluate(make_ctx(session_id=sid))).verdict == Verdict.PASS


async def test_page_snippets_need_a_session(make_ctx: Callable[..., RequestContext]) -> None:
    mod = SensorDataModule()
    assert await mod.page_snippets(make_ctx(session_id="")) == []
    [snippet] = await mod.page_snippets(make_ctx(session_id="sid1"))
    assert mod.codec.path("sid1") in snippet


async def test_handle_dynamic_ignores_other_paths_and_methods(
    make_ctx: Callable[..., RequestContext],
) -> None:
    mod = SensorDataModule()

    def req(method: str, path: str) -> Any:
        return type("Req", (), {"method": method, "url": type("U", (), {"path": path})()})()

    ctx = make_ctx(session_id="sid1")
    own = mod.codec.path("sid1")
    assert await mod.handle_dynamic(req("GET", "/nope"), ctx) is None
    assert await mod.handle_dynamic(req("PUT", own), ctx) is None
    assert await mod.handle_dynamic(req("GET", own), make_ctx(session_id="")) is None


# ---- the real JS, executed in node ------------------------------------------------------


async def test_obfuscated_js_runs_in_node_and_its_post_is_accepted(
    lab: Lab, tmp_path: Path
) -> None:
    async with lab.client() as c:
        sid, path = await lab.start(c)
        js = (await c.get(path)).text
        out = run_js(tmp_path, [js], MOUSE_DRIVER)
        assert out["flush"] == "function" and out["done"] is True and out["events"] == ["ak:sensor"]
        assert len(out["posts"]) == 1 and out["posts"][0]["url"] == path
        # the stub UA is Chrome/131; send the same UA so validate_sensor accepts
        stub_ua = (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36"
        )
        r = await c.post(
            path,
            content=out["posts"][0]["body"],
            headers={"user-agent": stub_ua, "content-type": "application/json"},
        )
        assert r.status_code == 200, r.text
        data = json.loads(await lab.store.get(f"sensor:{sid}") or "")
        assert data["integrity"]["nav"]["webdriver"]["native"] is True
        assert data["integrity"]["chrome"]["present"] is True and "cdp" not in data["integrity"]
        assert data["counts"]["mouse"] == 20 and len(data["mouse"]) == 20
        assert (
            "Chromium/131" in data["navigator"]["brands"]
            and data["navigator"]["webdriver"] is False
        )


async def test_js_integrity_native_stub_passes_and_playwright_override_is_flagged(
    lab: Lab, tmp_path: Path
) -> None:
    mod = JsIntegrityModule()
    verdicts: dict[str, tuple[Verdict, list[str]]] = {}
    for mode in ("native", "playwright", "no-chrome"):
        async with lab.client() as c:
            sid, path = await lab.start(c)
            workdir = tmp_path / mode
            workdir.mkdir()
            out = run_js(workdir, [(await c.get(path)).text], MOUSE_DRIVER, mode=mode)
            await lab.store.set(f"sensor:integrity:{sid}", json.dumps(_integrity_of(out, sid, lab)))
            ctx = RequestContext(
                method="GET", path="/", client_ip="1.1.1.1", headers=[], header_order=[],
                cookies={}, user_agent=UA, session_id=sid, store=lab.store,
            )  # fmt: skip
            sig = await mod.evaluate(ctx)
            verdicts[mode] = (sig.verdict, sig.details["failed"])
    assert verdicts["native"] == (Verdict.PASS, [])
    assert verdicts["playwright"][0] == Verdict.FAIL
    assert "webdriver_getter" in verdicts["playwright"][1]
    assert "window_chrome" in verdicts["no-chrome"][1]


def _integrity_of(out: dict[str, Any], sid: str, lab: Lab) -> dict[str, Any]:
    _, data = lab.mod.codec.decode(json.loads(out["posts"][0]["body"])["sensor_data"], sid)
    return {"integrity": data["integrity"], "navigator": data["navigator"]}


async def test_js_records_keystroke_timings_without_key_identities(
    lab: Lab, tmp_path: Path
) -> None:
    driver = """
    var t = 1000;
    'hello world'.split('').forEach(function (ch, i) {
      var code = 'Key' + ch.toUpperCase();
      t += 120 + (i * 37) % 90;
      ev('keydown', {code: code, repeat: false, timeStamp: t});
      ev('keyup', {code: code, timeStamp: t + 70 + (i * 13) % 40});
    });
    ev('touchstart', {changedTouches: [{clientX: 5, clientY: 6}], timeStamp: 1.5});
    ev('wheel', {timeStamp: 2000});
    ev('click', {});
    window.__akSensorFlush();
    drain();
    result = {posts: calls.filter(function (c) { return c.fetch; })
                          .map(function (c) { return c.init.body; })};
    """
    async with lab.client() as c:
        sid, path = await lab.start(c)
        out = run_js(tmp_path, [(await c.get(path)).text], driver)
        _, data = lab.mod.codec.decode(json.loads(out["posts"][0])["sensor_data"], sid)
    assert data["counts"]["key"] == 11 and data["counts"]["click"] == 1
    assert len(data["keys"]) == 11 and all(len(k) == 2 and k[1] > 0 for k in data["keys"])
    assert "KeyH" not in json.dumps(data) and "hello" not in json.dumps(data)
    assert data["touch"] == [[0, 5, 6, 1.5]] and data["scroll"] == [2000]
    assert data["motion"]["dm"] is False and data["focus"]["has"] is True


async def test_js_posts_again_when_the_server_asks_for_more(lab: Lab, tmp_path: Path) -> None:
    driver = MOUSE_DRIVER.replace("drain();", "window.__more = 1; drain();")
    async with lab.client() as c:
        sid, path = await lab.start(c)
        out = run_js(tmp_path, [(await c.get(path)).text], driver)
        idxs = [
            lab.mod.codec.decode(json.loads(p["body"])["sensor_data"], sid)[0] for p in out["posts"]
        ]
    assert idxs == [0, 1, 2]  # capped at three posts per session
    assert out["done"] is True and out["events"] == ["ak:sensor"]  # finished exactly once
