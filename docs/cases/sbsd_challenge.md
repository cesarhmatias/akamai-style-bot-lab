# `sbsd_challenge`: a second, per-issuance dynamic challenge (LOW)

Category: js · Module: `api/app/modules/sbsd_challenge.py` · Protected URL: `/protected/sbsd_challenge`
· Default: on (the lab device); the vendor-described flow is **off** (flag `sbsd_vendor_flow`) · Module tier: **LOW**

## What it is

A second challenge channel next to `_abck`: a per-issuance obfuscated script computes a value from browser-only state and
posts it back; cookies are issued on success.

## How real Akamai uses it

There is **no Akamai primary source**. Scraper-vendor docs (Hyper Solutions, xhrdev) expand SBSD as "State Based Scraping
Detection" and describe, all [V] (report §1.2 case 8):

- passive mode: a script at `/<random path>?v=<UUID>` on normal pages, then two POSTs (index 0 and 1) of `{"body": "..."}`
  to that path;
- blocking mode: a challenge page whose script adds `&t=<token>`, then one POST to `/<path>?t=<token>`;
- `sbsd_o` (or `bm_so`) is issued first and is an input to the payload; success leaves `bm_s`, `bm_ss`, `bm_sc` and
  `bm_lso` (names only; purposes and lifetimes are inconsistent across sources).

The link to Content Protector is speculation; nothing public connects them.

## Confidence

Tier **LOW** (report §3.1: "SBSD artifacts and modes: vendors only").

| Behaviour | Tier | Flag (default) |
|---|---|---|
| Original lab device (`/akam/sbsd_challenge/sbsd.js?v=<UUID>`, `POST /verify {t, v}`) | LAB: a teaching device, not a model of Akamai | on (no flag) |
| Vendor-described flow (random path, `sbsd_o` first, `{"body": ...}`, passive and blocking modes, vendor cookies) | LOW: unverified, vendor-sourced | `sbsd_vendor_flow` (off) |

## How the lab simulates it

Both flows use a randomized op-chain over document and navigator values (title length, UA length, UA characters, DOM
attributes, string characters; ops `add sub xor and or imul rotl xorshr`, 32-bit) that the script computes and the server
replays from the stored spec (`expected_answer`). Nothing is replayable between sessions or issuances.

- **Lab device (flag off)**: `GET /akam/sbsd_challenge/sbsd.js?v=<UUID>` stores the spec at `sbsd:spec:{sid}` (300 s, one
  live issuance per session, single use) and `POST /akam/sbsd_challenge/verify {t, v}` checks it. Errors: `no_challenge`,
  `stale_v`, `wrong_answer` (403). Success stores `sbsd:{sid}` = `ok` (3600 s) and sets `sbsd_o`.
- **Vendor flow (flag on)**: a per-session random multi-segment path claims GET and POST via `handle_dynamic`
  (`sbsd:path:{sid}`). The script response issues `sbsd_o` first; the script reads it and posts
  `{"body": base64(json{t, v, o, i})}` (lab-defined encoding). Passive mode needs index 0 then index 1; blocking mode
  (`GET /akam/sbsd_challenge/blocking` or the `sbsd` challenge provider) adds `&t=<token>` (`sbsd:tok:{sid}`) and needs
  one POST to `/<path>?t=<token>`. Errors include `sbsd_o_mismatch`, `bad_token`, `bad_index`. On success `bm_s`, `bm_ss`,
  `bm_sc` and `bm_lso` are set (vendor-only names, lab values; Max-Age 30 d, 1 h, 30 d, 30 d from weak disclosures).
- Score: solved => pass 0; otherwise fail 80 "SBSD challenge not solved for this session".

## How a scraper passes it

Execute the served script in a JS environment (the op chain reads title, UA and DOM values), keep `sbsd_o` in the vendor
flow, and post the body or bodies. A pure-HTTP client must reimplement the generated script, whose shape changes per
issuance.

## Observed results

| Client | Cell | Verdict and reason |
|---|---|---|
| naive | fail | fail 80, "SBSD challenge not solved for this session" |
| curl_cffi | fail | fail 80, same (the op chain needs a JS engine) |
| Playwright | pass | pass 0, "SBSD challenge solved" |

## Limits and caveats

- A determined client can port the generated JavaScript to Python or run a minimal JS engine.
- Everything about real SBSD is unverified ([KNOWN_GAPS](../KNOWN_GAPS.md) item 4).
