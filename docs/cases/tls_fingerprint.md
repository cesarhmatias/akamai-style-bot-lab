# `tls_fingerprint`: TLS ClientHello (JA3 / JA4) consistency

Category: passive · Module: `api/app/modules/tls_fingerprint.py` · Protected URL: `/protected/tls_fingerprint`
· Default: on · Module tier: **HIGH** (sub-checks carry their own tier, below)

## What it is

Before any HTTP byte is sent, a TLS client sends a ClientHello: version, cipher suites, extensions and their
order, supported groups, signature algorithms, ALPN. Every TLS stack (BoringSSL in Chrome, OpenSSL in Python and
curl, Go's `crypto/tls`, NSS in Firefox, Apple's stack in Safari) produces a recognisable hello, so a spoofed
`User-Agent` is exposed before the first header arrives. Two public formats summarise a hello:

- **JA3**: MD5 of `version,ciphers,extensions,groups,point-formats` (GREASE removed). Useless for Chrome, which
  shuffles its extension order on every connection.
- **JA4** (FoxIO): `t13d1516h2_<hash of ciphers>_<hash of sorted extensions + sigalgs>`. Sorting the extensions
  makes it stable against that permutation.

## How real Akamai uses it

- TLS is one of three passive layers (TCP/IP, TLS, HTTP) that Akamai says should be correlated to expose spoofed
  User-Agents and proxies (white paper, 06/2017, report §1.2 case 1, [P]). Its "cipher stunting" research tracked
  bots randomising cipher lists ([P], 2019).
- In 2026 JA4 can be forwarded to the origin in a header the customer names (JA4 settings API, beta), `TLS_FINGERPRINT`
  is a client-list type and `tls-fingerprint` a rate-control client identifier (report §1.2 case 1, [P]). The Bot
  Manager brief advertises "browser impersonation detection" ([P]).
- Akamai's own tables, thresholds and weights are not public. The Chrome era markers (ML-KEM group 4588, ALPS 17613,
  ML-DSA sigalgs, and Chrome 152's GREASE signature algorithm and `trust_anchors` extension) come from Chromium
  documentation and client-library issue trackers, not from Akamai: they are what a version-consistency check *can* use
  ([P]/[S], report §1.2 case 1).

## Confidence

| Sub-feature | Tier | Basis (report §3.1) |
|---|---|---|
| TLS family vs UA family (chrome, firefox, safari, openssl, go) | HIGH | Akamai docs and blogs 2019-2026 |
| Chrome era markers 4588 (131+), Kyber 25497 (<=130), ALPS 17613 (133+) / 17513 (<=132) | HIGH | Chromium docs plus independent reports |
| ML-DSA sigalgs `0904/0905/0906` => Chrome 150+ | MEDIUM (approximation) | one issue plus client-library PRs; no Chromium doc found |
| GREASE in `signature_algorithms`, `trust_anchors` (51764, 0xCA34) => Chrome 152+ | MEDIUM (approximation) | GREASE: two client-library issues plus the lab's own capture; `trust_anchors`: one PR, consistent with Chrome's JA4 going from 16 to 17 extensions; no Chromium doc read |
| Non-permuted extension order (WARN 25) | MEDIUM (approximation) | Akamai has not said it uses this check |
| Known Google Chrome JA4 table (WARN 10) | MEDIUM (approximation) | vendor database snapshot; goes stale |
| Safari 18 hello shape | MEDIUM | two 2025 captures; Safari 26 unverified |

No LOW sub-feature and no flag: everything here is on by default.

## How the lab simulates it

The Go edge (`edge/`) parses the raw ClientHello and injects `x-ja3`, `x-ja3-hash`, `x-ja4`, `x-ja3-grease`,
`x-tls-exts` (raw wire order), `x-tls-groups`, `x-tls-sigalgs`, `x-tls-alpn`, `x-tls-alps` and `x-tls-conn`
(client-sent copies are stripped). The module never matches an exact hash.

1. **Family** (`classify_tls`): structural marks that survive permutation. Chrome needs three or more of: GREASE,
   ALPS (17513/17613, counts double), `compress_certificate` (27), ECH grease (65037), cipher prefix
   `4865,4866,4867`. Firefox: ext 34 or 28 plus prefix `4865,4867,4866`. Safari/WebKit: Chrome-style prefix plus
   `compress_certificate`, no ALPS and no ECH, a legacy `...-49160-49170-10` tail, or JA4 cipher hash
   `a09f3c656075`. OpenSSL: prefix `4866,4867,4865` or a `h1`/`00` JA4 ALPN. Go: Chrome prefix without ALPS.
   The UA family is derived the same way; every iOS browser counts as Safari (WebKit).
2. **Verdicts**

   | Situation | Verdict | Score |
   |---|---|---|
   | Chrome hello and Chrome UA (or `sec-ch-ua` present) | pass | 0 |
   | Chrome hello, UA claims another family | fail | 85 |
   | Safari/Firefox hello matching its UA | pass | 0 |
   | Safari/Firefox hello, UA claims another family | fail | 85 |
   | openssl/go hello with a browser UA | fail | 85 |
   | openssl/go hello, non-browser UA | fail | 75 |
   | unrecognised hello, or no TLS fingerprint (bypassed the edge) | warn | 40 |

3. **Chrome-only WARNs** (only when the family check passed): the same raw extension order on 3 distinct
   connections for one `(client_ip, ja4)` => WARN 25 (store key `tlsorder:{ip}:{ja4}`, TTL 3600 s); a Chrome UA whose
   well-formed JA4 is outside the `KNOWN_CHROME_JA4` table (Google Chrome about 120-131, 133-149, 152-154) => WARN 10.
   The higher score wins. The table says "not Google Chrome's hello", not "never seen": other Chromium builds that send a
   Chrome UA land here too, and the reason names the one the lab knows (`t13d1516h2_8daaf6152771_806a8c22fdea`, which
   Scrapfly lists as Brave 153 on Linux and which Playwright's headless shell 153 also presents).
4. `chrome_tls_era()` is reused by `version_consistency` (see that case) and reported in `details["era"]`. Chrome 152
   markers count only when present: Chrome 152+ puts a GREASE value first in `signature_algorithms` (the edge's
   `x-tls-sigalgs` shows it as `grease`; JA4 drops it, otherwise the hash changes on every connection) and adds
   `trust_anchors`. The headless shell sends the GREASE value but no `trust_anchors`, so absence proves nothing.

## How a scraper passes it

Use a real, current browser, or an impersonation profile whose hello matches the UA it sends. Setting headers never
changes this signal. A hello whose UA family is consistent passes even when the browser is old: nothing here punishes
an old but consistent profile (the lab found no public evidence that Akamai does, report §3.1 LOW).

## Observed results

From the committed `RESULTS.md` (judged from the case's own signal):

| Client | Cell | Verdict and reason |
|---|---|---|
| naive (`requests`, OpenSSL) | fail | fail 75, "Non-browser TLS stack (openssl)", JA4 `t13d3112h1_e8f1e7e78f70_b26ce05bbdd6` |
| curl_cffi `chrome131` | pass | pass 0, "Chrome-like TLS matches Chrome UA", JA4 `t13d1516h2_8daaf6152771_02713d6af862` |
| Playwright (bundled headless shell) | warn | warn 10, "JA4 ...806a8c22fdea is a Chromium build's fingerprint (Brave 153 on Linux in public data), not Google Chrome's [medium]" |

The Playwright JA4 depends on the exact Chromium build, which is why CI pins the `playwright` version.

## Limits and caveats

- Heuristics, not an allow-list: a client that replays a Chrome-shaped hello passes.
- Fixtures are reconstructed values, not live captures; Safari 26 and Chrome 155+ are unverified
  ([KNOWN_GAPS](../KNOWN_GAPS.md) items 9 and 10).
- The known-Chrome table is a snapshot and ages every two weeks (Chrome moved to a two-week cadence with Chrome 153). A real
  Brave user on Linux gets the same WARN 10 as the headless shell, which is why the score stays low.
- The edge sees only the first hello of a connection; TLS resumption and multiple hosts are out of scope.
- HTTP/3 and QUIC fingerprints are not modelled (see KNOWN_GAPS, deferred features).
