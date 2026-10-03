# `session_validation`: navigations versus XHR/JSON calls per session

Category: behavioral · Module: `api/app/modules/session_validation.py` · Protected URL: `/protected/session_validation`
· Default: on · Module tier: **MEDIUM** (the `bm_sv_cookies` extra is LOW, flag-gated, off)

## What it is

A real browser loads pages and then calls APIs from them. A scraper that hits JSON endpoints directly never builds that
chain. The module counts HTML navigations and XHR/JSON calls per session and flags API-only sessions and broken
`Referer` / `Sec-Fetch-Site` chains.

## How real Akamai uses it

Cookie-database descriptions (worded like vendor docs, [S, weak], report §2.7) say `bm_sv` is "used as part of the session
validation detection method to keep track of the number of HTML page requests and AJAX requests that the client makes"
(2 h) and `bm_mi` confirms "that requests are coming from a real browser using the browser validation detection method"
(2 h). The detection names and cookie purposes are LOW confidence (Bot Manager's API reference is login-gated); the
concept (catching API-only scrapers) is MEDIUM.

## Confidence

| Sub-feature | Tier | Flag (default) |
|---|---|---|
| Navigation vs XHR counting, broken-chain checks | MEDIUM (approximation; thresholds are the lab's own) | none |
| `bm_sv` / `bm_mi` cookies and requiring `bm_sv` on XHR | LOW: unverified, vendor-sourced (cookie databases) | `bm_sv_cookies` (off) |

## How the lab simulates it

Each evaluated request is classified from browser-set fetch metadata (`sec-fetch-mode` and `sec-fetch-dest`, falling back
to `accept`) as `nav` or `xhr`. Counters: `sv:nav:{sid}` and `sv:xhr:{sid}` (4 h), last navigation `sv:lastnav:{sid}`.
Findings (the score is `max + 0.25 * sum(others)`, capped at 100; 50 and above fails, 20-49 warns):

| Finding | Points |
|---|---|
| JSON/XHR/transactional call in a session with no navigation | 80 |
| XHR with `Sec-Fetch-Site` not `same-origin`/`same-site` | 60 |
| XHR without a `Referer` | 55 |
| XHR `Referer` host differs from the request host (and the browser did not assert same-origin) | 55 |
| browser UA with no `Sec-Fetch-*` metadata | 30 |
| more than 20 XHR calls per navigation | 40 |
| `bm_sv_cookies` on: XHR without a valid `bm_sv` | 30 |

With `bm_sv_cookies` on, `finalize_cookies` issues `bm_sv` and `bm_mi` (lab-defined MAC values) and the module requires
`bm_sv` on XHR. Applies to page, protected and transactional requests.

## How a scraper passes it

Load a page first (so the session has a navigation), then call APIs from that page's origin with `Sec-Fetch-Site:
same-origin` and a same-origin `Referer`. A pure-HTTP client that loads `/` first with a browser's fetch-metadata headers
also passes: this module catches API-only clients, not header spoofing.

## Observed results

| Client | Cell | Verdict and reason |
|---|---|---|
| naive | fail | fail 80, "JSON/transactional call in a session with no page navigation" |
| curl_cffi | pass | pass 0, "navigation/XHR chain consistent" |
| Playwright | pass | pass 0, "navigation/XHR chain consistent" |

## Limits and caveats

- Fetch-metadata headers are trivially forged by non-browser clients. Browsers omit them on plain HTTP to
  non-localhost origins, hence the soft WARN rather than a fail.
- Cookie purposes and lifetimes for `bm_sv` and `bm_mi` are unverified ([KNOWN_GAPS](../KNOWN_GAPS.md) item 2).
