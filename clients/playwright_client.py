"""Headless Chromium driven by Playwright, behaving like a (patient) human visitor.

Visits the landing page so the page scripts run, draws a curved, jittered mouse path made of
many individual ``mouse.move`` calls with small random sleeps, waits for every challenge
script to finish, then requests each protected case with the browser's own network stack.
"""

from __future__ import annotations

import math
import random
import time
from typing import Any

from playwright.sync_api import Page, sync_playwright

from .common import CASES, LAB_URL, CaseResult, protected_url, result_from_response

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


def run(cases: list[str] | None = None) -> list[CaseResult]:
    rng = random.Random(SEED)
    out: list[CaseResult] = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        ctx = browser.new_context(
            ignore_https_errors=True,
            user_agent=USER_AGENT,
            viewport={"width": 1280, "height": 800},
            locale="en-US",
            extra_http_headers={"X-Lab-Client": LABEL},
        )
        ctx.add_init_script(STEALTH_JS)
        page = ctx.new_page()
        page.goto(LAB_URL + "/", wait_until="load")
        human_mouse(page, rng)
        for flag in DONE_FLAGS:
            page.wait_for_function(f"window.{flag} === true", timeout=20_000)
        for case in cases or CASES:
            resp = page.goto(protected_url(case), wait_until="load")
            status = resp.status if resp else 0
            body: Any = None
            try:
                body = resp.json() if resp else None
            except Exception:
                body = None
            out.append(result_from_response(LABEL, case, status, body))
        browser.close()
    return out
