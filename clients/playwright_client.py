"""Headless Chromium driven by Playwright, behaving like a (patient) human visitor.

Visits the landing page so the page scripts run, draws a curved, jittered mouse path made of
many individual ``mouse.move`` calls with small random sleeps, waits for every challenge
script to finish, then requests each case with the browser's own network stack: protected
resources by navigation, login/checkout/mobile calls by in-page ``fetch`` (so the page's
inline-telemetry wrapper attaches its header), and the tile game by clicking the tiles.

Representative DEFAULT configuration, deliberately not stealth-tuned: the User-Agent is
overridden to Chrome/131 and ``navigator.webdriver`` is hidden with ``Object.defineProperty``.
Both are common recipes and both are what the lab's version_consistency / header_order /
js_integrity checks look for, so the matrix shows what they catch. RESULTS.md explains how a
client would avoid each finding; none of that is applied here.
"""

from __future__ import annotations

import contextlib
import math
import random
import time
from typing import Any

from playwright.sync_api import Browser, BrowserContext, Page, Response, sync_playwright
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError

from .common import (
    CASE_TABLE,
    CASES,
    INTERSTITIAL_RETURN_TO,
    LAB_URL,
    MOBILE_PATH,
    REPORT_ID_HEADER,
    USERNAME,
    CaseResult,
    judge,
    row_env,
)

LABEL = "playwright"
SEED = 1337
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)
STEALTH_JS = "Object.defineProperty(Navigator.prototype, 'webdriver', {get: () => false});"
DONE_FLAGS = ["__akSensorDone", "__akPowDone", "__akPixelDone", "__akSbsdDone"]


def bezier_path(
    rng: random.Random, start: tuple[float, float], end: tuple[float, float], points: int = 70
) -> list[tuple[float, float]]:
    """Cubic Bezier from start to end with random control points, ease-in-out and jitter."""
    (x0, y0), (x3, y3) = start, end
    dx, dy = x3 - x0, y3 - y0
    norm = math.hypot(dx, dy) or 1.0
    nx, ny = -dy / norm, dx / norm
    bend1, bend2 = rng.uniform(-0.35, 0.35) * norm, rng.uniform(-0.35, 0.35) * norm
    x1, y1 = x0 + dx * 0.3 + nx * bend1, y0 + dy * 0.3 + ny * bend1
    x2, y2 = x0 + dx * 0.7 + nx * bend2, y0 + dy * 0.7 + ny * bend2
    path: list[tuple[float, float]] = []
    for i in range(1, points + 1):
        u = i / points
        t = u * u * (3 - 2 * u)  # ease in/out: speed varies along the stroke
        a, b, c, d = (1 - t) ** 3, 3 * (1 - t) ** 2 * t, 3 * (1 - t) * t**2, t**3
        x = a * x0 + b * x1 + c * x2 + d * x3 + rng.gauss(0, 0.8)
        y = a * y0 + b * y1 + c * y2 + d * y3 + rng.gauss(0, 0.8)
        path.append((x, y))
    return path


def human_mouse(page: Page, rng: random.Random) -> None:
    """Move through a few waypoints, one ``mouse.move`` per path point, 8-25 ms apart."""
    pos = (rng.uniform(80, 200), rng.uniform(80, 200))
    page.mouse.move(*pos)
    for target in [(620, 340), (260, 520), (840, 180)]:
        for x, y in bezier_path(rng, pos, target):
            page.mouse.move(x, y)
            time.sleep(rng.uniform(0.008, 0.025))
        pos = target


def settle_landing(page: Page, timeout_ms: int = 20_000) -> None:
    """Wait for the landing page's scripts (sensor, PoW, pixel, SBSD) like a patient visitor."""
    for flag in DONE_FLAGS:  # a flag that never flips just means that script did not finish
        with contextlib.suppress(Exception):
            page.wait_for_function(f"window.{flag} === true", timeout=timeout_ms)


def visit_landing(page: Page, rng: random.Random, *, first: bool = False) -> None:
    page.goto(LAB_URL + "/", wait_until="load")
    if first:
        human_mouse(page, rng)
    settle_landing(page)
    with contextlib.suppress(Exception):  # AVF step-up script: present only when requested
        page.wait_for_function("window.__akStepupDone === true", timeout=3_000)


def in_page_post(page: Page, path: str, body: dict[str, Any] | None) -> tuple[int, str | None]:
    """``fetch`` from the landing page, so the page's wrappers (inline telemetry) apply."""
    script = """async ([path, body]) => {
        const init = body === null ? {} : {method: 'POST', body: JSON.stringify(body),
            headers: {'Content-Type': 'application/json'}};
        const r = await fetch(path, init);
        await r.text();
        return [r.status, r.headers.get('x-lab-report-id')];
    }"""
    status, report_id = page.evaluate(script, [path, body])
    return int(status), report_id


def solve_tiles(page: Page, rng: random.Random) -> str | None:
    """Click the highlighted tiles in order with a curved, jittered pointer path.

    Returns the report id of the request the page re-issues after the game, or None."""
    page.wait_for_selector(".sec-bc-tile-parent button", timeout=10_000)
    order = [
        part.strip()
        for part in page.inner_text(".sec-bc-text-container b").split("\u2192")
        if part.strip()
    ]
    buttons = page.query_selector_all(".sec-bc-tile-parent button")
    tiles = {b.inner_text().strip(): b for b in buttons}
    pos = (rng.uniform(20, 80), rng.uniform(20, 80))
    page.mouse.move(*pos)
    time.sleep(rng.uniform(0.5, 0.9))  # a person reads the instructions first
    for n, label in enumerate(order):
        box = tiles[label].bounding_box()
        if box is None:
            return None
        target = (
            box["x"] + box["width"] * rng.uniform(0.3, 0.7),
            box["y"] + box["height"] * rng.uniform(0.3, 0.7),
        )
        for x, y in bezier_path(rng, pos, target, points=30):
            page.mouse.move(x, y)
            time.sleep(rng.uniform(0.008, 0.025))
        pos = target
        time.sleep(rng.uniform(0.12, 0.35))
        if n == len(order) - 1:
            with page.expect_navigation(timeout=20_000) as nav:
                page.mouse.click(*pos)
            resp = nav.value
            return resp.headers.get(REPORT_ID_HEADER) if resp else None
        page.mouse.click(*pos)
        time.sleep(rng.uniform(0.2, 0.6))
    return None


def new_context(browser: Browser) -> BrowserContext:
    """The client's one default configuration: UA override plus the webdriver JS override."""
    ctx = browser.new_context(
        ignore_https_errors=True,
        user_agent=USER_AGENT,
        viewport={"width": 1280, "height": 800},
        locale="en-US",
        extra_http_headers={"X-Lab-Client": LABEL},
    )
    ctx.add_init_script(STEALTH_JS)
    return ctx


def play_tile_game(browser: Browser, rng: random.Random) -> tuple[int, str | None]:
    """A visitor who arrives straight at the challenged URL in a fresh browser session.

    A fresh context matters: the engine downgrades ``challenge`` to monitor for a session that
    already holds a valid ``sec_cpt`` (the landing page's proactive solver earns one), so the
    tile game is only ever served to a session that has not solved another challenge."""
    ctx = new_context(browser)
    try:
        page = ctx.new_page()
        resp = page.goto(f"{LAB_URL}/protected/interactive_challenge", wait_until="load")
        status = resp.status if resp else 0
        if resp and resp.headers.get("content-type", "").startswith("text/html"):
            return status, solve_tiles(page, rng)
        return status, resp.headers.get(REPORT_ID_HEADER) if resp else None
    finally:
        ctx.close()


def play_interstitial(browser: Browser, case: str) -> CaseResult:
    """A fresh visitor (no cookies) is sent the cookieless interstitial by the gate; the page's
    own script solves it and reloads. The cell is the proof_of_work signal of the request the
    reload makes, i.e. after the interstitial attempt."""
    ctx = new_context(browser)
    try:
        page = ctx.new_page()
        verifies: list[Response] = []
        page.on("response", lambda r: verifies.append(r) if "/_sec/verify" in r.url else None)
        try:
            with page.expect_response(
                lambda r: r.url.endswith(INTERSTITIAL_RETURN_TO) and REPORT_ID_HEADER in r.headers,
                timeout=30_000,
            ) as info:
                page.goto(LAB_URL + INTERSTITIAL_RETURN_TO, wait_until="load")
        except PlaywrightTimeoutError:
            return judge(LABEL, case, 0, None, "no scored request after the interstitial")
        resp = info.value
        accepted = [v.status == 200 for v in verifies]  # the lab answers 403 on a bad solve
        note = "script ran in the browser, verify " + (
            "accepted" if accepted and all(accepted) else "rejected or never sent"
        )
        return judge(LABEL, case, resp.status, resp.headers.get(REPORT_ID_HEADER), note)
    finally:
        ctx.close()


def run(cases: list[str] | None = None) -> list[CaseResult]:
    rng = random.Random(SEED)
    wanted = cases or CASES
    out: dict[str, CaseResult] = {}
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        ctx = new_context(browser)
        page = ctx.new_page()
        visit_landing(page, rng, first=True)
        on_landing = True
        for case in wanted:
            kind = CASE_TABLE[case].endpoint
            with row_env(case):
                if kind == "interstitial":
                    out[case] = play_interstitial(browser, case)
                    continue
                if case == "interactive_challenge":
                    status, rid = play_tile_game(browser, rng)
                    note = "tile game played with a curved pointer path, in a fresh session"
                    out[case] = judge(LABEL, case, status, rid, note)
                    continue
                if kind == "protected" and case != "avf_stepup":
                    resp = page.goto(f"{LAB_URL}/protected/{case}", wait_until="load")
                    on_landing = False
                    status = resp.status if resp else 0
                    rid = resp.headers.get(REPORT_ID_HEADER) if resp else None
                    out[case] = judge(LABEL, case, status, rid)
                    continue
                # cases that need the storefront page: step-up script, login/checkout, mobile
                if not on_landing:
                    visit_landing(page, rng)
                    on_landing = True
                if case == "avf_stepup":
                    resp = page.goto(f"{LAB_URL}/protected/{case}", wait_until="load")
                    on_landing = False
                    out[case] = judge(
                        LABEL,
                        case,
                        resp.status if resp else 0,
                        resp.headers.get(REPORT_ID_HEADER) if resp else None,
                    )
                elif kind == "login":
                    status, rid = in_page_post(
                        page, "/api/login", {"username": USERNAME, "password": "hunter2-hunter2"}
                    )
                    out[case] = judge(LABEL, case, status, rid)
                elif kind == "checkout":
                    status, rid = in_page_post(page, "/api/checkout", {"qty": 1})
                    out[case] = judge(LABEL, case, status, rid)
                elif kind == "mobile":
                    status, rid = in_page_post(page, MOBILE_PATH, None)
                    out[case] = judge(
                        LABEL, case, status, rid, "browser has no native SDK header to send"
                    )
        browser.close()
    return [out[c] for c in wanted]
