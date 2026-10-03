"""Google Chrome driven by Patchright, the undetected drop-in fork of Playwright.

The same visitor as the Playwright client (landing page, curved mouse path, in-page ``fetch``,
tile game, interstitial: :func:`clients.playwright_client.drive`), launched with Patchright's
documented best-practice setup and nothing else:

* ``channel="chrome"``: the installed Google Chrome, not the bundled Chromium build;
* headed (``headless=False``): new headless mode still says ``HeadlessChrome`` in the UA and the
  client hints, and Patchright does not change either;
* ``no_viewport=True``: the window's own size, no emulated viewport;
* no User-Agent override, no init script, no client-hint override.

Patchright itself drops ``--enable-automation``, adds
``--disable-blink-features=AutomationControlled`` (so ``navigator.webdriver`` is false natively),
avoids ``Runtime.enable`` and runs ``page.evaluate`` in an isolated world. That last point is why
the in-page ``fetch`` calls ask for the main world (``isolated_context=False``): only the page's
world has the inline-telemetry wrapper.

Headed needs a display: locally a Chrome window opens for the length of the run; CI runs the
matrix under ``xvfb-run``. ``PATCHRIGHT_HEADLESS=1`` runs new headless instead, for experiments
only: ``clients/expected_matrix.json`` assumes headed.
"""

from __future__ import annotations

import os
from typing import Any

from patchright.sync_api import TimeoutError as PatchrightTimeoutError
from patchright.sync_api import sync_playwright

from .common import CaseResult
from .playwright_client import BrowserFlavor, drive

LABEL = "patchright"
HEADLESS = os.environ.get("PATCHRIGHT_HEADLESS", "") == "1"


def launch(pw: Any) -> Any:
    return pw.chromium.launch(channel="chrome", headless=HEADLESS)


def new_context(browser: Any) -> Any:
    """Patchright's recommended context: real window size, nothing spoofed. ``X-Lab-Client``
    only labels the report; ``header_order`` ignores it."""
    return browser.new_context(
        ignore_https_errors=True,
        no_viewport=True,
        extra_http_headers={"X-Lab-Client": LABEL},
    )


PATCHRIGHT = BrowserFlavor(
    label=LABEL,
    start=sync_playwright,
    launch=launch,
    new_context=new_context,
    timeout_error=PatchrightTimeoutError,
    main_world={"isolated_context": False},
)


def run(cases: list[str] | None = None) -> list[CaseResult]:
    return drive(PATCHRIGHT, cases)
