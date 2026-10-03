from __future__ import annotations

import copy
import json
from collections.abc import Callable
from typing import Any

from app.contract import EndpointClass, RequestContext, Verdict
from app.modules.js_integrity import JsIntegrityModule, analyze_integrity
from app.store import MemoryStore

SID = "D" * 32 + "~YAAQJS~1~2"
CHROME_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)
NATIVE = {"where": "proto", "accessor": True, "native": True, "name_ok": True}
GETTERS = ("webdriver", "userAgent", "platform", "languages", "hardwareConcurrency", "plugins")
mod = JsIntegrityModule()


def probe_result(**over: Any) -> dict[str, Any]:
    """What a stock desktop Chrome's sensor reports: every getter native, no automation globals."""
    data: dict[str, Any] = {
        "nav": {k: dict(NATIVE) for k in GETTERS},
        "fts_native": True,
        "globals": [],
        "chrome": {"present": True, "keys": ["app", "csi", "loadTimes"]},
    }
    data.update(over)
    return data


def nav(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "userAgent": CHROME_UA,
        "webdriver": False,
        "brands": ["Google Chrome/131", "Chromium/131", "Not_A Brand/24"],
        "plugins": 5,
    }
    base.update(over)
    return base


def playwright_override() -> dict[str, Any]:
    """Object.defineProperty(Navigator.prototype,'webdriver',{get:()=>false}): the descriptor
    stays on the prototype but the getter is a script arrow function named 'get'."""
    data = probe_result()
    data["nav"]["webdriver"] = {
        "where": "proto",
        "accessor": True,
        "native": False,
        "name_ok": False,
    }
    return data


def test_native_shaped_probe_result_passes() -> None:
    score, probes, reasons = analyze_integrity(probe_result(), nav())
    assert score == 0 and reasons == []
    assert all(p["status"] == "pass" for p in probes.values())
    assert probes["webdriver_getter"]["note"].startswith("native getter")


def test_playwright_style_non_native_webdriver_getter_is_flagged() -> None:
    score, probes, reasons = analyze_integrity(playwright_override(), nav())
    assert score >= 50
    assert probes["webdriver_getter"]["status"] == "fail"
    assert probes["webdriver_getter"]["confidence"] == "high"
    assert any("not native" in r for r in reasons)


def test_webdriver_defined_on_the_instance_is_flagged() -> None:
    data = probe_result()
    data["nav"]["webdriver"] = {"where": "own", "accessor": True, "native": False, "name_ok": False}
    score, probes, reasons = analyze_integrity(data, nav())
    assert score >= 50 and "descriptor on own" in probes["webdriver_getter"]["note"]
    assert any("Navigator.prototype" in r for r in reasons)


def test_other_tampered_getters_and_patched_tostring() -> None:
    data = probe_result(fts_native=False)
    data["nav"]["languages"] = {"where": "own", "accessor": True, "native": False, "name_ok": False}
    score, probes, _ = analyze_integrity(data, nav())
    assert probes["navigator_getters"]["note"] == "languages"
    assert probes["function_tostring"]["status"] == "fail" and score >= 50


def test_headless_markers_and_automation_globals() -> None:
    headless_ua = nav(userAgent=CHROME_UA.replace("Chrome/", "HeadlessChrome/"))
    assert analyze_integrity(probe_result(), headless_ua)[0] >= 80
    brands = nav(brands=["HeadlessChrome/131", "Chromium/131"])
    assert analyze_integrity(probe_result(), brands)[1]["headless_marker"]["status"] == "fail"
    score, probes, reasons = analyze_integrity(
        probe_result(globals=["__playwright__binding__", "__pwInitScripts"]), nav()
    )
    assert score >= 90 and "__pwInitScripts" in probes["automation_globals"]["note"]
    assert any("automation globals" in r for r in reasons)


def test_window_chrome_shape_and_client_hint_brands() -> None:
    absent = probe_result(chrome={"present": False, "keys": []})
    s, p, _ = analyze_integrity(absent, nav())
    assert p["window_chrome"]["status"] == "warn" and 20 <= s < 50
    partial = probe_result(chrome={"present": True, "keys": ["runtime"]})
    assert analyze_integrity(partial, nav())[1]["window_chrome"]["status"] == "warn"
    # UA overridden without client hints: Chrome UA but no brands
    s, p, _ = analyze_integrity(probe_result(), nav(brands=[]))
    assert p["client_hint_brands"]["status"] == "warn" and s < 20
    # Firefox / mobile UAs are not expected to have window.chrome
    firefox = nav(
        userAgent="Mozilla/5.0 (X11; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0"
    )
    assert (
        "window_chrome"
        not in analyze_integrity(probe_result(chrome={"present": False}), firefox)[1]
    )


def test_webdriver_true_and_missing_probe_block() -> None:
    assert analyze_integrity(probe_result(), nav(webdriver=True))[0] == 100
    score, probes, reasons = analyze_integrity(None, nav())  # hand-built payload, no probes
    assert score >= 80 and "integrity probes missing" in reasons[0]
    assert probes["webdriver_getter"]["note"] == "no probe data"


def test_cdp_probe_only_when_flag_enabled() -> None:
    hit = probe_result(cdp=True)
    off = analyze_integrity(hit, nav(), cdp_enabled=False)
    assert "cdp_stack_trap" not in off[1] and off[0] == 0
    score, probes, _ = analyze_integrity(hit, nav(), cdp_enabled=True)
    assert score >= 50 and probes["cdp_stack_trap"]["confidence"] == "low"
    clean = analyze_integrity(probe_result(cdp=False), nav(), cdp_enabled=True)
    assert clean[0] == 0 and clean[1]["cdp_stack_trap"]["status"] == "pass"


def test_module_metadata() -> None:
    assert mod.category == "js" and mod.confidence.value == "high" and mod.default_enabled
    assert (
        EndpointClass.TRANSACTIONAL in mod.applies_to and EndpointClass.MOBILE not in mod.applies_to
    )
    [flag] = mod.flags
    assert flag.name == "cdp_probes" and flag.default is False and flag.confidence.value == "low"


async def put_sensor(store: MemoryStore, key: str, integrity: Any, n: dict[str, Any]) -> None:
    await store.set(f"{key}:{SID}", json.dumps({"integrity": integrity, "navigator": n}))


async def test_evaluate_native_vs_playwright(
    make_ctx: Callable[..., RequestContext], memory_store: MemoryStore
) -> None:
    sig = await mod.evaluate(make_ctx(session_id=SID))
    assert (sig.verdict, sig.score) == (Verdict.FAIL, 90) and "no sensor" in sig.reason

    await put_sensor(memory_store, "sensor", probe_result(), nav())
    sig = await mod.evaluate(make_ctx(session_id=SID))
    assert sig.verdict == Verdict.PASS and sig.score == 0 and sig.details["failed"] == []
    assert sig.details["probes"]["webdriver_getter"]["status"] == "pass"

    await put_sensor(memory_store, "sensor", playwright_override(), nav())
    sig = await mod.evaluate(make_ctx(session_id=SID))
    assert sig.verdict == Verdict.FAIL and sig.score >= 50
    assert "webdriver_getter" in sig.details["failed"]
    assert "not native" in sig.reason


async def test_evaluate_uses_integrity_of_a_rejected_sensor(
    make_ctx: Callable[..., RequestContext], memory_store: MemoryStore
) -> None:
    await memory_store.set(f"sensor_rejected:{SID}", "navigator.webdriver is set (automation)")
    sig = await mod.evaluate(make_ctx(session_id=SID))
    assert sig.verdict == Verdict.FAIL and "webdriver is set" in sig.reason
    await put_sensor(memory_store, "sensor:integrity", probe_result(globals=["cdc_x"]), nav())
    sig = await mod.evaluate(make_ctx(session_id=SID))
    assert sig.verdict == Verdict.FAIL and "cdc_x" in sig.reason


async def test_evaluate_reads_cdp_flag_and_survives_junk(
    make_ctx: Callable[..., RequestContext], memory_store: MemoryStore
) -> None:
    await put_sensor(memory_store, "sensor", probe_result(cdp=True), nav())
    assert (await mod.evaluate(make_ctx(session_id=SID))).verdict == Verdict.PASS
    sig = await mod.evaluate(make_ctx(session_id=SID, flags={"cdp_probes": True}))
    assert sig.verdict == Verdict.FAIL and "Error.stack" in sig.reason
    await memory_store.set(f"sensor:{SID}", "not json")
    assert (await mod.evaluate(make_ctx(session_id=SID))).score == 90
    await memory_store.set(f"sensor:{SID}", json.dumps({"navigator": "x"}))
    assert (await mod.evaluate(make_ctx(session_id=SID))).score == 90


def test_probe_dicts_are_not_shared() -> None:
    a, b = probe_result(), probe_result()
    a["nav"]["webdriver"]["native"] = False
    assert b["nav"]["webdriver"]["native"] is True
    assert copy.deepcopy(a) == a
