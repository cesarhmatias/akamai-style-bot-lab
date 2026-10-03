# `interactive_challenge`: tile mini-game and AJAX challenge injection

Category: behavioral · Module: `api/app/modules/interactive_challenge.py` · Protected URL:
`/protected/interactive_challenge` (never part of `/protected/all`: `applies_to` is empty) · Default: on
· Module tier: **MEDIUM** (concept HIGH, markup MEDIUM)

## What it is

A mini-game page: a grid of numbers or letters and a sequence the visitor must click in order. The page records pointer and
key telemetry; the server checks the answer **and** that the interaction is plausible for a person, then the page reloads
the original request. A solved session is not challenged again for 50 minutes. A helper script can also challenge `fetch`
and XHR calls.

## How real Akamai uses it

- Content Protector's opt-in interactive behavioral challenge (Akamai blog, 2026-03-10, [P], report §2.4) uses "five
  mini-game types using grids of numbers or letters", records mouse, touch and key telemetry, reloads the original request
  when done, and "won't re-challenge for at least 50 minutes".
- The page is recognisable by the classes `sec-if-cpt-container`, `scf-akamai-logo`, `sec-bc-tile-parent` and
  `sec-bc-text-container`, answers HTTP 200, has no `<title>` and is about 2.7 KB ([S], one 2026 scraper PR).
- Challenge injection rules let Akamai inject "AJAX challenge JavaScript" into HTML pages (`injectJavaScript`) so XHR and
  fetch calls can be challenged ([P], Terraform docs).

## Confidence

| Sub-feature | Tier | Flag (default) |
|---|---|---|
| Concept: tile game, telemetry, 50-minute no-rechallenge | HIGH | none |
| AJAX challenge injection | HIGH (concept) | `ajax_challenge_injection` (on) |
| Markup classes, 200 with no `<title>` | MEDIUM (approximation: one 2026 PR) | none |
| One game type (not five), lab styling, lab verification rules, the `sec_bc` cookie name | LAB-defined | none |

## How the lab simulates it

- `challenge_providers = {"interactive", "behavioral"}`. `interactive` serves the page for navigations and a 428 JSON (with
  `challenge_url`) for XHR; `behavioral` serves the page for navigations only (the JSON form of `behavioral` belongs to the
  sensor-based provider of `proof_of_work`). Select it with `challenge_provider` in `PUT /api/policy`.
- The page: a 3x3 grid (`GRID = 9`) of numbers 1-9 or letters, a sequence of 3 tiles (`NEED = 3`), the four marker classes,
  no `<title>`, a lab-styled `scf-akamai-logo` element (no real logo).
- `POST /akam/interactive_challenge/verify {token, clicks[], moves[], keys[], total}`: the token (`ichal:{token}`, 180 s) is
  single use (deleted even on failure) and bound to `bm_sz`. Checks: clicks match the sequence; every click `isTrusted`; the
  first click at least 250 ms after load and gaps of at least 80 ms; the gap spread not machine-regular (stdev at least
  2 ms); pointer clicks carry coordinates inside the tile and a path of at least 3 distinct pointer positions (keyboard-only
  completion needs 3 key events). Errors: `wrong_sequence`, `untrusted_events`, `too_fast`, `machine_regular_timing`,
  `click_outside_tile`, `no_pointer_path`, `no_input_telemetry`.
- Success sets the lab-defined cookie `sec_bc` and the store marker `ichal:ok:{sid}` for `norechallenge_seconds` (policy,
  default 3000 s, 50 minutes). While valid, the engine downgrades `challenge` actions to monitor.
- AJAX injection: `page_snippets` adds `/akam/interactive_challenge/ajax_inject.js` to HTML pages while the flag is on. It
  wraps `fetch` and `XMLHttpRequest`, renders a 428 challenge in an overlay iframe and retries once.
- As a case: solved and cookie valid => pass 0; otherwise fail 45 "interactive challenge not completed" (the `strict`
  segment for standard telemetry).

## How a scraper passes it

A real browser: click the tiles like a person. A script must synthesize **trusted** input with human-like timing and a
pointer path (the Playwright harness client does); calling `element.click()` or posting the answer directly is rejected.

## Observed results

| Client | Cell | Verdict and reason |
|---|---|---|
| naive | fail | fail 45, "interactive challenge not completed" (action challenge/strict) |
| curl_cffi | fail | fail 45, same (needs trusted pointer events) |
| Playwright | pass | pass 0, "interactive challenge solved, no re-challenge yet" (a curved, jittered path in a fresh session) |

The engine downgrades a `challenge` to monitor only when a module that serves the policy's `challenge_provider` reports the
session solved it (the engine passes the provider to `challenge_satisfied`). The tile game vouches for `interactive` and
`behavioral`; a `sec_cpt` earned from the landing page's proactive solver no longer waives it, so in the working-tree
`RESULTS.md` curl_cffi's row is `challenge/strict` (the committed one reads `monitor/strict`, from the earlier any-provider
rule). The harness still runs the Playwright case in a fresh browser session.

## Limits and caveats

- The plausibility rules are simple lab heuristics, not Akamai's models. The DOM and recorded events of the real challenge
  are unverified ([KNOWN_GAPS](../KNOWN_GAPS.md) item 6).
- One game type, not five.
