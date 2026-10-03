# `h2_fingerprint`: HTTP/2 connection fingerprint

Category: passive · Module: `api/app/modules/h2_fingerprint.py` · Protected URL: `/protected/h2_fingerprint`
· Default: on · Module tier: **HIGH**

## What it is

The first frames of an HTTP/2 connection are fixed per stack: the SETTINGS frame (ids and values, in order), the
connection-level WINDOW_UPDATE, any PRIORITY frames, and the order of the pseudo-headers. Together they identify the
browser or library independently of anything written in headers.

## How real Akamai uses it

Akamai published this technique itself: Shuster, "Passive Fingerprinting of HTTP/2 Clients" (2017; report §1.2
case 2, [P]). The literal string is `S[;]|WU|P[,]|PS[,]`:

- **S**: SETTINGS `id:value` pairs in order of appearance, joined by `;`.
- **WU**: the WINDOW_UPDATE increment, `00` when the frame is absent.
- **P**: one `stream:exclusive:dep:weight` tuple per PRIORITY frame, joined by `,`, or `0` (weights print as the wire
  byte plus one).
- **PS**: pseudo-header letters `m`, `a`, `s`, `p`.

The paper's Firefox 53 example is `1:65536;4:131072;5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1|m,p,a,s`.
The bracketed `S[...]|WU[...]` form is notation, not the literal string. Which profiles Akamai scores today and with
what weights is not public.

## Confidence

| Sub-feature | Tier | Basis (report §3.1) |
|---|---|---|
| String format and semantics (S, WU `00`, P, PS) | HIGH | Akamai's own paper |
| Current Chrome and Firefox values | HIGH | maintainer captures (2025), the lab's own capture |
| Safari 18 values (`safari`, `safari-ios`) | MEDIUM (approximation) | two 2025 captures; Safari 26 may differ |
| Optional HEADERS-frame priority echo | not scored | reported in `details` only |

## How the lab simulates it

The edge emits `x-h2-fingerprint` in the paper's format (an absent WINDOW_UPDATE is written `00`; the module also
accepts `0` and `-`). `x-h2-fingerprint-labeled` (`S[..]|WU[..]|...`) is a lab convenience and is not read.

The string is parsed and compared per component with the profile of the browser the UA claims (non-browser UAs are
compared with Chrome):

| Profile | SETTINGS | WINDOW_UPDATE | Pseudo order |
|---|---|---|---|
| chrome | `1:65536;2:0;4:6291456;6:262144` | 15663105 | `m,a,s,p` |
| firefox | `1:65536;2:0;4:131072;5:16384` | 12517377 | `m,p,a,s` |
| safari (macOS) | `2:0;3:100;4:2097152;9:1` | 10420225 | `m,s,a,p` |
| safari-ios | `2:0;3:100;4:2097152;8:1;9:1` | 10420225 | `m,s,a,p` |

A Safari-claiming UA is scored against both Safari profiles and takes the best match. Deviation points: setting ids
or their order 30, setting values 25, WINDOW_UPDATE 20, pseudo-header order 25 (sum capped at 100). Score 0 passes,
below 50 warns, 50 and above fails ("H2 deviates from `<profile>` profile"). Other results: HTTP/1.1 with a
Chrome/Firefox/Safari UA fails 80; HTTP/1.1 with another UA fails 70; a malformed string fails 80. The first HEADERS
priority (`x-h2-headers-priority`) is echoed in `details["headers_priority"]` and never scored.

## How a scraper passes it

Use an HTTP/2 stack that mimics the claimed browser: `curl_cffi` with an `impersonate` profile, or a real browser.
Changing headers does nothing; `requests`/`httpx` in HTTP/1.1 mode fail immediately.

## Observed results

| Client | Cell | Verdict and reason |
|---|---|---|
| naive (`requests`) | fail | fail 70, "HTTP/1.1 client, not a browser stack" |
| curl_cffi `chrome131` | pass | pass 0, "H2 matches chrome profile", `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` |
| Playwright | pass | pass 0, "H2 matches chrome profile", same string |
| Patchright (Google Chrome 152) | pass | pass 0, "H2 matches chrome profile", same string |

## Limits and caveats

- Profiles are 2025 captures (Chrome 136-154 share one string, Firefox 138, Safari 18.x). Firefox no longer sends the
  PRIORITY tree from the 2017 example. Safari 26 is unverified ([KNOWN_GAPS](../KNOWN_GAPS.md) item 10).
- The edge fingerprints one connection and reuses its header order for later streams.
- HTTP/3 SETTINGS and QUIC parameters are not modelled; the audit found no evidence Akamai scores them (see
  KNOWN_GAPS, deferred features).
