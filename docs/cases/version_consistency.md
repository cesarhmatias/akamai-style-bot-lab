# `version_consistency`: cross-layer Chrome version agreement

Category: passive · Module: `api/app/modules/version_consistency.py` · Protected URL: `/protected/version_consistency`
· Default: on · Module tier: **HIGH** (the ML-DSA marker is MEDIUM and only yields a WARN)

## What it is

Every layer of a request independently leaks which Chrome release produced it. The TLS hello carries
release-specific groups and codepoints, the headers carry release-specific values, the User-Agent and `sec-ch-ua`
state a version outright, and the sensor script can read `navigator.userAgentData`. A genuine browser has all of
them agree; a spoofed UA, a stale impersonation profile or a UA override on a different build does not.

## How real Akamai uses it

"Browser version mismatches" are a named transparent-detection target on Akamai's detection-methods page
(report §2.2, [P]); Content Protector checks JavaScript-collected traits against protocol-level data (press release,
2024, [P]); the 2017 white paper correlates TCP, TLS and HTTP/2 ([P]). Akamai's concrete rules are not public, so the
markers and thresholds here are the lab's own, built on Chromium-documented release changes. Nothing is visible on the
client: it only sees a challenge or a block.

## Confidence

| Sub-feature | Tier | Basis (report §3.1) |
|---|---|---|
| Concept (cross-layer mismatch) | HIGH | Akamai detection-methods page, press release |
| TLS group 4588 (131+), Kyber (<=130), ALPS 17613 (133+) / 17513 (<=132), `zstd` (123+), `priority` on h2 (124+) | HIGH | Chromium docs plus independent reports |
| ML-DSA sigalgs in a Chrome-shaped hello (150+) | MEDIUM (approximation) | one issue plus client-library PRs |
| Penalty for an old but genuine browser | not implemented | report §3.1 LOW: no evidence found |

## How the lab simulates it

`details["layers"]` carries the result; the engine copies it to `ScoreReport.layers` and the dashboard's
"Cross-layer agreement" card shows AGREE or DISAGREE with the per-layer values.

- `tls_min` / `tls_max`: Chrome window from `chrome_tls_era()` (see `tls_fingerprint`). Only trusted when the hello is
  Chrome-shaped.
- `hdr_min`: `zstd` in `accept-encoding` => 123+; `priority` header over h2 => 124+.
- `ua_major` (`Chrome/<major>` in the UA), `sech_major` (Chromium or Google Chrome brand in `sec-ch-ua`) and
  `js_major` (the same brands as read by the sensor, from store key `sensor:{sid}`, absent until a sensor was posted).
- Every claimed major must lie inside `[max(tls_min, hdr_min), tls_max]` and the claimed majors must be equal.

| Outcome | Verdict | Score |
|---|---|---|
| non-Chromium UA (Firefox, Safari, iOS, tools) | skip | 0 |
| all layers agree, or only the UA states a version | pass | 0 |
| violation backed only by the MEDIUM ML-DSA marker | warn | 40 |
| any other violation or disagreement (precise reason in `reason`) | fail | 80 |

Applies to page, protected and transactional requests.

## How a scraper passes it

Be a real current browser, or an impersonation profile whose UA, hints and TLS come from the same release. Typical
failures: Playwright with a UA overridden to an old Chrome on a newer bundled Chromium (TLS says 150+, UA says 131);
curl_cffi `chrome131` with a newer UA (legacy ALPS 17513 caps the TLS window at 132 or below); a Chrome UA whose hints
disagree.

## Observed results

| Client | Cell | Verdict and reason |
|---|---|---|
| naive | pass | skip 0, "Not a Chromium UA: Chrome era markers do not apply" |
| curl_cffi `chrome131` | pass | pass 0, "Chrome version agrees across layers" |
| Playwright | fail | fail 80, "User-Agent claims Chrome 131 but ALPS 17613 => Chrome 133+; ... ML-DSA sigalgs ... => Chrome 150+; User-Agent says Chrome 131 but sec-ch-ua says 153; User-Agent says Chrome 131 but navigator.userAgentData says 153" |

## Limits and caveats

- Markers are release-window facts: the check rejects only what is provably inconsistent. A UA that is merely older
  than the real browser but inside every window is not flagged.
- The Chrome 150 ML-DSA marker rests on thin evidence; Go 1.27 also sends ML-DSA, so it only counts with other Chrome
  marks.
- Akamai's real rules are unknown ([KNOWN_GAPS](../KNOWN_GAPS.md) item 9).
