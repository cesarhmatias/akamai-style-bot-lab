# `header_order`: header set, order, casing and Chrome-version consistency

Category: passive · Module: `api/app/modules/header_order.py` · Protected URL: `/protected/header_order`
· Default: on · Module tier: **HIGH** (Firefox and Safari baselines are MEDIUM)

## What it is

Browsers emit headers in a stack-specific, stable order and set (Chrome: `sec-ch-ua*` first, then
`upgrade-insecure-requests`, `user-agent`, `accept`, `sec-fetch-*`, `accept-encoding`, `accept-language`,
`priority`). HTTP client libraries use dict order and omit browser-only headers. Header *values* also change with
Chrome releases, so a request can contradict the version its own User-Agent claims.

## How real Akamai uses it

Akamai's detection-methods page lists "out-of-order headers and browser version mismatches" as transparent-detection
targets (report §1.2 case 3, [P]). The exact rules and thresholds are not public; the thresholds below are the lab's
own. The Chrome facts used are from Chromium documentation ([P]): `zstd` in `accept-encoding` since Chrome 123, the
RFC 9218 `priority` header since 124 on HTTP/2 and HTTP/3 only (curl_cffi's known issue #785 sends it on HTTP/1.1,
[S]), the reduced UA `Chrome/<major>.0.0.0` complete since 113, and `sec-ch-ua` brands carrying the UA's major.
Across vendors, `HeadlessChrome` tokens matter more in practice than order ([S], 2026 measurement).

## Confidence

| Sub-feature | Tier | Basis (report §3.1) |
|---|---|---|
| Out-of-order headers / version mismatch as a concept | HIGH | Akamai detection-methods page (2026) |
| Chrome changes (`zstd` 123, `priority` 124 h2/h3, UA reduction, `sec-ch-ua` major) | HIGH | Chromium docs plus independent reports |
| Chrome baseline order | HIGH (lab heuristic) | thresholds are lab-defined |
| Firefox and Safari baselines | MEDIUM (approximation) | reconstructed from published captures |

No flag; everything is on by default.

## How the lab simulates it

`ctx.header_order` (original casing, wire order, from the edge) is compared with the baseline of the claimed family
(Chrome for unknown UAs; navigation or fetch baseline, whichever is closer) using a longest-common-subsequence
ratio over the headers both sides know. `host`, `content-length`, `content-type`, `x-lab-client` and `connection` are
ignored. Points are summed and capped at 100:

| Check | Points |
|---|---|
| order: `(1 - similarity) * 60` | 0-60 |
| missing `sec-fetch-site/mode/dest` | 25 |
| missing `accept-language` | 15 |
| Chrome UA without `sec-ch-ua` | 10 |
| uppercase header names on h2 (malformed per RFC 9113, rarely fires) | 50 |
| python-requests tell-tales (python UA, `Accept: */*`, `gzip, deflate` without `br`, `Connection`) | 30 |
| Chrome >= 123 UA without `zstd` | 35 |
| `priority` header on HTTP/1.1 | 30 |
| desktop Chrome >= 113 UA that is not the reduced form | 30 |
| UA major differs from the `sec-ch-ua` Chromium/Chrome brand major | 40 |
| `HeadlessChrome` in the UA or brands | 60 |

Below 20 passes, 20-49 warns, 50 and above fails. No order data at all (not via the edge) is WARN 40.

## How a scraper passes it

Send exactly the browser's header set in the browser's order, with values consistent with the version the UA
claims. Impersonation libraries and real browsers do; mind that an impersonation profile freezes the version it
was captured from, and that overriding only the UA string on a different Chromium build breaks the major checks.

## Observed results

| Client | Cell | Verdict and reason |
|---|---|---|
| naive | fail | fail 85, "missing sec-fetch-* headers; missing accept-language; python-requests telltales: python UA, Accept: */*, accept-encoding without br, Connection header" |
| curl_cffi `chrome131` | pass | pass 0, "Header set and order match Chrome" |
| Playwright (UA overridden to Chrome 131) | fail | fail 100, "HeadlessChrome token in sec-ch-ua brands; UA says Chrome 131 but sec-ch-ua says 153" |
| Patchright (Google Chrome 152, headed, no UA override) | pass | pass 0, "Header set and order match Chrome"; in new headless it fails 60, "HeadlessChrome token in User-Agent" |

## Limits and caveats

- The Playwright failure is a property of the harness client's default recipe (a UA override on a newer bundled
  Chromium), not of Playwright itself; see `clients/results_notes.md` for how a client would pass.
- Firefox/Safari order baselines are heuristics. Casing only matters on HTTP/1.1.
- On HTTP/2 the order is per connection, not per request: the edge reuses the first stream's order for every later
  stream on the connection. A navigation on a connection a `fetch` opened is compared with a `fetch` order; with every
  off-by-default flag on, that gave the Patchright client a WARN 22 ("63% similar") on a genuine Chrome navigation
  (`docs/KNOWN_GAPS.md`, section 5).
- Akamai says its edge can request client hints (Accept-CH); the lab does not request high-entropy hints.
