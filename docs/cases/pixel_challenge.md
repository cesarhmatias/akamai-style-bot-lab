# `pixel_challenge`: the `/akam/<n>/pixel_<hex>` beacon (and what `bm_sz` is not)

Category: js · Module: `api/app/modules/pixel_challenge.py` · Protected URL: `/protected/pixel_challenge`
· Default: on · Module tier: **MEDIUM** (both flags are LOW, off)

## What it is

A value embedded in the page HTML must be turned into pixel data and POSTed to a per-session beacon path. Unlike the
sensor it is replicable from pure HTTP by parsing the HTML, which is realistic. `bm_sz` is not part of this challenge: it
is a seed cookie (about four hours) issued on the first response, with the shape `HEX32~YAAQ<base64>~<int>~<int>`.

## How real Akamai uses it

(Report §1.2 case 7.) Public captures show `/akam/11/pixel_16cff819` (TikTok, 2019) and `/akam/11/pixel_49faa00b`
(Lowe's), still matched as `/akam/\d+/pixel_` in 2026 ([S]). Vendor docs add: the HTML assigns a value to the global
`bazadebezolkohpepadr`, a script loads from `/akam/<n>/<hex>`, the client POSTs pixel data to `/akam/<n>/pixel_<hex>`, and
the result is tied to `ak_bmsc` ([V]). Search snippets show a hidden `<noscript><img>` fallback, which the audit could not
confirm.

## Confidence

| Sub-feature | Tier | Flag (default) |
|---|---|---|
| Path shape, embedded global, script plus beacon | MEDIUM (approximation: 2019 captures, a 2026 PR, vendors) | none |
| Pixel POST body | LAB-defined; the real body is unknown ([KNOWN_GAPS](../KNOWN_GAPS.md) item 7) | none |
| Beacon result tied to `ak_bmsc` | LOW: unverified, vendor-sourced | `pixel_ties_ak_bmsc` (off) |
| `ak_bmsc` issued HttpOnly | LOW: unverified, vendor-sourced | `ak_bmsc_httponly` (off) |
| `<noscript><img>` fallback | not built (unconfirmed) | none |

## How the lab simulates it

- `page_snippets` embeds `bazadebezolkohpepadr=<int>;` (a 10-digit value derived from the session by HMAC) and
  `<script src="/akam/13/<hex>" defer>` (`n` is fixed at 13, `hex` is 8 hex chars per session).
- `handle_dynamic` serves the script at `GET /akam/13/<hex>` and accepts the beacon at `POST /akam/13/pixel_<hex>`. There
  is no router and no `/config` hand-out any more.
- Pixel data (lab-defined): form body `p=<ts_ms>.<digest>` with `digest = sha256("<value>.<hex>.<ts_ms>.<bm_sz>")[:32 hex]`
  and a +-120 s clock window. Errors: no `bm_sz` 400, malformed 400, stale 403, wrong digest 403. Success stores
  `pixel:{sid}` = `ok` (4 h).
- With `pixel_ties_ak_bmsc`, a successful beacon re-issues `ak_bmsc` (hash stored at `pixel:bmsc:{sid}`) and scoring then
  requires the client to present the new value: otherwise fail 70 "pixel solved but ak_bmsc was not updated (not tied)".
- Score: beacon received => pass 0; otherwise fail 70 "pixel beacon not received for this session".

## How a scraper passes it

From pure HTTP: (1) GET the page with cookies; (2) parse the integer from `bazadebezolkohpepadr=<int>;` and the hex from
`src="/akam/<n>/<hex>"`; (3) POST `p=<ts_ms>.<digest>` to `/akam/<n>/pixel_<hex>` with the same `bm_sz` cookie and keep any
`Set-Cookie` that comes back. A browser just runs the served script.

## Observed results

| Client | Cell | Verdict and reason |
|---|---|---|
| naive | fail | fail 70, "pixel beacon not received for this session" |
| curl_cffi | pass | pass 0, "pixel beacon received" (pure HTTP, parsed from the page HTML) |
| Playwright | pass | pass 0, "pixel beacon received" |

## Limits and caveats

- The lab does not know what the real pixel body contains or which cookie it changes.
- Cookie attributes (`ak_bmsc` HttpOnly, lifetimes) are unconfirmed ([KNOWN_GAPS](../KNOWN_GAPS.md) item 2).
- The `<noscript><img>` fallback is deferred; see KNOWN_GAPS.
