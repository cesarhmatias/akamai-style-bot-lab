"""Interactive tile challenge: markup, verification rules, no-rechallenge marker, AJAX injection."""

from __future__ import annotations

import random
import re
from typing import Any

import httpx
import pytest
from app.main import create_app
from app.modules.interactive_challenge import InteractiveChallenge, check_interaction
from app.store import MemoryStore
from test_actions import Scored

SID = "c" * 32 + "~deadbeef"


class Clock:
    t = 5000.0

    def __call__(self) -> float:
        return self.t


def good_clicks(seq: list[int], **over: Any) -> dict[str, Any]:
    clicks = [
        {
            "i": i,
            "t": 600 + 450 * n + 37 * n * n,
            "x": 10,
            "y": 10,
            "trusted": True,
            "detail": 1,
            "inside": True,
            **over,
        }
        for n, i in enumerate(seq)
    ]
    moves = [[10 * k, 5 * k, 20 * k] for k in range(8)]
    return {"clicks": clicks, "moves": moves, "keys": [], "total": 3000}


REC = {"sequence": [4, 1, 7]}


def test_check_interaction_accepts_human_like() -> None:
    ok, reason, _ = check_interaction(REC, good_clicks([4, 1, 7]))
    assert ok and reason == "ok"


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (lambda b: b.update(clicks=b["clicks"][::-1]), "wrong_sequence"),
        (lambda b: b["clicks"][0].update(trusted=False), "untrusted_events"),
        (lambda b: b["clicks"][0].update(t=50), "too_fast"),
        (lambda b: b["clicks"][1].update(t=b["clicks"][0]["t"] + 10), "too_fast"),
        (
            lambda b: [c.update(t=1000 + 300 * n) for n, c in enumerate(b["clicks"])],
            "machine_regular_timing",
        ),
        (lambda b: b["clicks"][2].update(inside=False), "click_outside_tile"),
        (lambda b: b.update(moves=[[1, 1, 1]]), "no_pointer_path"),
        (lambda b: b.update(clicks="x"), "bad_request"),
    ],
)
def test_check_interaction_rejections(mutate: Any, reason: str) -> None:
    body = good_clicks([4, 1, 7])
    mutate(body)
    ok, got, _ = check_interaction(REC, body)
    assert not ok and got == reason


def test_keyboard_completion_needs_key_events() -> None:
    body = good_clicks([4, 1, 7], detail=0)
    assert check_interaction(REC, body)[1] == "no_input_telemetry"
    body["keys"] = [["Tab", 10], ["Tab", 20], ["Enter", 30]]
    assert check_interaction(REC, body)[0]


@pytest.fixture
async def http() -> Any:
    clock = Clock()
    mod = InteractiveChallenge(rng=random.Random(3), clock=clock)
    app = create_app(store=MemoryStore(), modules=[Scored(), mod])
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://t", cookies={"bm_sz": SID}
    ) as c:
        await c.put("/api/policy", json={"params": {"challenge_provider": "interactive"}})
        c.clock = clock  # type: ignore[attr-defined]
        yield c


def sequence_from(page: str) -> list[int]:
    labels = re.findall(r'data-i="(\d+)">([^<]+)</button>', page)
    order = re.search(r"<b>(.*?)</b>", page).group(1).split(" &rarr; ")  # type: ignore[union-attr]
    by_label = {lab: int(i) for i, lab in labels}
    return [by_label[o] for o in order]


async def test_page_markup_and_full_solve(http: httpx.AsyncClient) -> None:
    r = await http.get("/protected/all", headers={"x-score": "40", "accept": "text/html"})
    assert r.status_code == 200 and "<title" not in r.text.lower() and len(r.text) < 4000
    for cls in (
        "sec-if-cpt-container",
        "scf-akamai-logo",
        "sec-bc-tile-parent",
        "sec-bc-text-container",
    ):
        assert cls in r.text
    token = re.search(r'data-token="(\w+)"', r.text).group(1)  # type: ignore[union-attr]
    seq = sequence_from(r.text)
    assert len(set(seq)) == 3
    ok = await http.post(
        "/akam/interactive_challenge/verify", json={"token": token, **good_clicks(seq)}
    )
    assert ok.status_code == 200 and ok.json()["norechallenge_seconds"] == 3000
    assert "sec_bc" in ok.cookies
    # no re-challenge for the next 50 minutes ...
    after = await http.get("/protected/all", headers={"x-score": "40"})
    assert after.json()["report"]["action"] == "monitor"
    assert (await http.get("/protected/interactive_challenge")).status_code == 200
    # ... and a challenge again once the marker is older than that
    http.clock.t += 3001  # type: ignore[attr-defined]
    again = await http.get("/protected/all", headers={"x-score": "40"})
    assert again.status_code == 428 or again.json()["report"]["action"] == "challenge"


async def test_failed_attempts_replay_and_wrong_session(http: httpx.AsyncClient) -> None:
    async def fresh() -> tuple[str, list[int]]:
        r = await http.get("/protected/all", headers={"x-score": "40", "accept": "text/html"})
        return re.search(r'data-token="(\w+)"', r.text).group(1), sequence_from(r.text)  # type: ignore[union-attr]

    token, seq = await fresh()
    bad = await http.post(
        "/akam/interactive_challenge/verify",
        json={"token": token, **good_clicks(seq, trusted=False)},
    )
    assert bad.status_code == 403 and bad.json()["error"] == "untrusted_events"
    replay = await http.post(
        "/akam/interactive_challenge/verify", json={"token": token, **good_clicks(seq)}
    )
    assert replay.json()["error"] == "unknown_or_replayed"
    token, seq = await fresh()
    http.cookies.set("bm_sz", "d" * 32 + "~00000000")
    other = await http.post(
        "/akam/interactive_challenge/verify", json={"token": token, **good_clicks(seq)}
    )
    assert other.json()["error"] == "wrong_session"
    assert (await http.post("/akam/interactive_challenge/verify", json={"x": 1})).status_code == 400
    # unsolved: the case's own signal is a gray 45 -> strict -> challenged again
    assert (await http.get("/protected/interactive_challenge")).status_code == 428


async def test_xhr_gets_428_json_with_overlay_url_and_page(http: httpx.AsyncClient) -> None:
    j = (await http.get("/protected/all", headers={"x-score": "40"})).json()
    assert j["provider"] == "interactive" and j["ok"] is False
    page = await http.get(j["challenge_url"])
    assert page.status_code == 200 and "sec-bc-tile-parent" in page.text
    assert (await http.get("/akam/interactive_challenge/page?token=zzz")).status_code == 404


async def test_behavioral_provider_html_only(http: httpx.AsyncClient) -> None:
    await http.put("/api/policy", json={"params": {"challenge_provider": "behavioral"}})
    page = await http.get("/protected/all", headers={"x-score": "40", "accept": "text/html"})
    assert "sec-bc-tile-parent" in page.text
    j = await http.get("/protected/all", headers={"x-score": "40"})
    assert j.json()["error"] == "no_challenge_provider"  # JSON form belongs to proof_of_work


async def test_ajax_injection_snippet_follows_flag(http: httpx.AsyncClient) -> None:
    assert "/akam/interactive_challenge/ajax_inject.js" in (await http.get("/")).text
    await http.put("/api/flags/ajax_challenge_injection", json={"value": False})
    assert "ajax_inject.js" not in (await http.get("/")).text
    for name in ("ajax_inject.js", "chlg_tiles.js"):
        js = await http.get(f"/akam/interactive_challenge/{name}")
        assert js.status_code == 200 and "javascript" in js.headers["content-type"]
    assert "428" in (await http.get("/akam/interactive_challenge/ajax_inject.js")).text
