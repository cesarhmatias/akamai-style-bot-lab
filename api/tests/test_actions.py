"""Policy actions enforced by the API: deny page, delay, slow, tarpit, serve_alternate,
safeguard, transactional and mobile endpoints, policy and reference endpoints."""

import html
import json
import time
from typing import Any, ClassVar

import httpx
import pytest
from app.contract import DetectionModule, EndpointClass, RequestContext, Signal, Verdict
from app.main import create_app
from app.store import MemoryStore

ALL = frozenset(EndpointClass)


class Scored(DetectionModule):
    """Score taken from the x-score header; records which classes evaluated it."""

    slug = "scored"
    title = "Scored"
    description = "score from x-score"
    category = "passive"
    applies_to: ClassVar[frozenset[EndpointClass]] = ALL

    def __init__(self) -> None:
        self.seen: list[str] = []

    async def evaluate(self, ctx: RequestContext) -> Signal:
        self.seen.append(ctx.endpoint_class.value)
        score = int(ctx.header("x-score") or 0)
        details: dict[str, Any] = {}
        if ctx.header("x-ttype"):
            details["telemetry_type"] = ctx.header("x-ttype")
        verdict = Verdict.PASS if score == 0 else Verdict.FAIL
        return self.signal(verdict, score, "scored by header", **details)


def mk() -> tuple[httpx.AsyncClient, Scored]:
    mod = Scored()
    app = create_app(store=MemoryStore(), modules=[mod])
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t"), mod


async def tiny(c: httpx.AsyncClient, **params: float) -> None:
    body = {"params": {"delay_seconds": 0.05, "slow_seconds": 0.1, "tarpit_seconds": 0.1, **params}}
    assert (await c.put("/api/policy", json=body)).status_code == 200


async def report(c: httpx.AsyncClient, r: httpx.Response) -> dict[str, Any]:
    return (await c.get(f"/api/requests/{r.headers['x-lab-report-id']}")).json()  # type: ignore[no-any-return]


async def test_protected_allow_monitor_deny_json_shape() -> None:
    c, _ = mk()
    async with c:
        r = await c.get("/protected/scored")
        j = r.json()
        assert r.status_code == 200 and j["ok"] and j["case"] == "scored"
        assert j["report"]["segment"] == "human" and j["report"]["action"] == "allow"
        assert j["report"]["is_human"] is True and j["data"]["product"]["price"] == 199.0
        r = await c.get("/protected/scored", headers={"x-score": "10"})
        assert r.status_code == 200 and r.json()["report"]["action"] == "monitor"
        r = await c.get("/protected/scored", headers={"x-score": "90"})
        j = r.json()
        assert r.status_code == 403 and not j["ok"] and j["report"]["action"] == "deny"
        assert j["reference"] == j["report"]["reference"] and r.headers["server"] == "AkamaiGHost"


async def test_inline_telemetry_uses_inline_bands() -> None:
    c, _ = mk()
    async with c:
        # 70 is aggressive for standard telemetry but only strict (challenge) for inline
        std = (await c.get("/protected/scored", headers={"x-score": "70"})).json()["report"]
        inl = (
            await c.get("/protected/scored", headers={"x-score": "70", "x-ttype": "inline"})
        ).json()["report"]
        assert std["segment"] == "aggressive" and inl["segment"] == "strict"
        assert inl["telemetry_type"] == "inline"


async def test_deny_page_text_and_reference_lookup() -> None:
    c, _ = mk()
    async with c:
        r = await c.get("/protected/scored", headers={"x-score": "90", "accept": "text/html"})
        assert r.status_code == 403 and r.headers["server"] == "AkamaiGHost"
        text = html.unescape(r.text)
        assert "Access Denied" in text
        assert (
            'You don\'t have permission to access "http://t/protected/scored" on this server.'
            in text
        )
        assert "Reference #18." in text
        ref = text.split("Reference #")[1].split("\n")[0].strip()
        a, b, ts, d = ref.split(".")
        assert a == "18" and len(b) == 8 and abs(int(ts) - time.time()) < 60 and len(d) == 7
        rep = await report(c, r)
        assert rep["reference"] == ref
        assert (await c.get(f"/api/reference/%2318.{ref[3:]}")).json()["id"] == rep["id"]
        assert (await c.get(f"/api/reference/{ref}")).json()["id"] == rep["id"]
        found = (await c.get("/api/requests", params={"reference": "#" + ref})).json()
        assert [x["id"] for x in found] == [rep["id"]]
        assert (await c.get("/api/reference/18.nope")).status_code == 404


async def test_ghost_header_flag_off() -> None:
    c, _ = mk()
    async with c:
        await c.put("/api/flags/akamai_ghost_server_header", json={"value": False})
        r = await c.get("/protected/scored", headers={"x-score": "90", "accept": "text/html"})
        assert r.status_code == 403 and r.headers.get("server") != "AkamaiGHost"


async def test_delay_and_slow_return_real_content_after_waiting() -> None:
    c, _ = mk()
    async with c:
        await tiny(c, delay_seconds=0.3, slow_seconds=0.4)
        await c.put(
            "/api/policy",
            json={"actions": {"protected": {"cautious": "delay", "strict": "slow"}}},
        )
        t = time.monotonic()
        r = await c.get("/protected/scored", headers={"x-score": "10"})
        assert time.monotonic() - t >= 0.29
        assert r.status_code == 200 and r.json()["report"]["action"] == "delay"
        assert not r.json()["report"]["blocked"]
        t = time.monotonic()
        r = await c.get("/protected/scored", headers={"x-score": "40"})
        assert time.monotonic() - t >= 0.3
        j = r.json()
        assert r.status_code == 200 and j["report"]["action"] == "slow" and j["data"]["product"]


async def test_tarpit_holds_then_minimal_response() -> None:
    c, _ = mk()
    async with c:
        await tiny(c, tarpit_seconds=0.3)
        await c.put("/api/policy", json={"actions": {"protected": {"strict": "tarpit"}}})
        t = time.monotonic()
        r = await c.get("/protected/scored", headers={"x-score": "40"})
        assert time.monotonic() - t >= 0.29
        assert r.status_code == 403 and r.content == b""
        rep = await report(c, r)
        assert rep["action"] == "tarpit" and rep["blocked"] is True


async def test_serve_alternate_is_silent_with_canary() -> None:
    c, _ = mk()
    async with c:
        await c.put("/api/policy", json={"actions": {"protected": {"strict": "serve_alternate"}}})
        r = await c.get("/protected/scored", headers={"x-score": "40"})
        assert r.status_code == 200
        j = r.json()
        assert j["ok"] is True and "report" not in j  # silent degradation
        rep = await report(c, r)
        assert rep["action"] == "serve_alternate" and rep["blocked"] is False
        assert rep["canary"] and rep["canary"] == j["data"]["product"]["ref"]
        assert j["data"]["product"]["price"] != 199.0 and j["data"]["product"]["stock"] != 3
        assert (await c.get(f"/api/canary/{rep['canary']}")).json()["id"] == rep["id"]
        assert (await c.get("/api/canary/nope")).status_code == 404
        # HTML flavour: perturbed page with a hidden canary element
        r = await c.get(
            "/protected/scored", headers={"x-score": "40", "accept": "text/html,*/*;q=0.8"}
        )
        rep2 = await report(c, r)
        assert r.status_code == 200 and f'data-ref="{rep2["canary"]}"' in r.text
        assert "display:none" in r.text and "report" not in r.text.lower().replace("reference", "")


async def test_safeguard_after_k_challenges() -> None:
    c, _ = mk()
    async with c:
        await c.put("/api/policy", json={"params": {"safeguard_failures": 2}})
        acts = []
        for _ in range(4):
            r = await c.get("/protected/scored", headers={"x-score": "40"})
            acts.append(await report(c, r))
        assert [a["action"] for a in acts] == ["challenge", "challenge", "safeguard", "safeguard"]
        assert acts[2]["is_safeguard"] and not acts[2]["blocked"]
        assert (await c.get("/protected/scored", headers={"x-score": "40"})).status_code == 200


async def test_challenge_without_provider_is_428_json() -> None:
    c, _ = mk()
    async with c:
        r = await c.get("/protected/scored", headers={"x-score": "40"})
        j = r.json()
        assert r.status_code == 428 and not j["ok"] and j["report"]["action"] == "challenge"
        assert j["error"] == "no_challenge_provider"


async def test_page_stays_up_for_bots_and_policy_roundtrip() -> None:
    c, _ = mk()
    async with c:
        r = await c.get("/", headers={"x-score": "95"})
        assert r.status_code == 200 and "Protected Storefront" in r.text
        pol = (await c.get("/api/policy")).json()
        assert pol["bands"]["standard"]["strict"] == [21, 60]
        assert "serve_alternate" in pol["choices"]["actions"]
        bad = await c.put("/api/policy", json={"actions": {"protected": {"strict": "explode"}}})
        assert bad.status_code == 422
        assert (await c.delete("/api/policy")).status_code == 200
        await c.put("/api/policy", json={"actions": {"page": {"aggressive": "deny"}}})
        assert (await c.get("/", headers={"x-score": "95"})).status_code == 403
        await c.post("/api/reset")  # keeps the policy
        assert (await c.get("/", headers={"x-score": "95"})).status_code == 403


async def test_login_checkout_mobile_evaluate_their_class() -> None:
    c, mod = mk()
    async with c:
        r = await c.post("/api/login", json={"username": "ann"})
        j = r.json()
        assert (
            r.status_code == 200
            and j["user"] == "ann"
            and j["report"]["endpoint_class"] == "transactional"
        )
        assert (await c.post("/api/login", json={})).status_code == 400
        r = await c.post("/api/checkout", json={"qty": 2})
        j = r.json()
        assert j["order"]["total"] == 398.0 and j["order"]["order_id"].startswith("ord-")
        r = await c.get("/mobile/api/items", headers={"x-score": "10"})
        j = r.json()
        assert j["path"] == "/items" and j["report"]["endpoint_class"] == "mobile"
        assert j["report"]["telemetry_type"] == "native"
        r = await c.post("/mobile/api/orders", content=b"{}")
        assert r.status_code == 200
        assert mod.seen == ["transactional", "transactional", "mobile", "mobile"]


async def test_checkout_serve_alternate_perturbs_order_and_hides_report() -> None:
    c, _ = mk()
    async with c:
        r = await c.post("/api/checkout", json={"qty": 1}, headers={"x-score": "40"})
        j = r.json()
        rep = await report(c, r)
        assert rep["action"] == "serve_alternate" and "report" not in j
        assert j["order"]["total"] != 199.0 and j["order"]["ref"] == rep["canary"]
        r = await c.post("/api/checkout", json={"qty": 1}, headers={"x-score": "90"})
        assert r.status_code == 403 and r.json()["report"]["action"] == "deny"


async def test_login_serve_alternate_and_report_json_roundtrip() -> None:
    c, _ = mk()
    async with c:
        r = await c.post("/api/login", json={"username": "bob"}, headers={"x-score": "40"})
        assert json.loads(r.text)["token"].startswith("cnry-")


@pytest.mark.parametrize("path", ["/protected/all", "/protected/scored"])
async def test_report_header_always_present(path: str) -> None:
    c, _ = mk()
    async with c:
        for score in ("0", "40", "90"):
            r = await c.get(path, headers={"x-score": score})
            assert r.headers["x-lab-report-id"]
