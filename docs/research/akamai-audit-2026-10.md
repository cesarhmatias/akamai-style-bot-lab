# Akamai Bot Manager: accuracy audit and gap analysis for this lab

Research date: 2026-10-02. Scope: the ten cases in `docs/cases/`, their modules in `api/app/modules/`, and the Go
edge in `edge/`. Method: one search track per topic, primary sources first, each claim cross-checked against at
least one independent source where one exists. Two suspected lab defects were re-checked by running the lab's own
scoring functions on published browser fingerprints.

**Source tiers** (the tag follows each citation)

- **[P]** primary: Akamai TechDocs and API reference, Akamai blogs, product briefs, press releases and research;
  Chrome/Chromium documentation.
- **[S]** independent secondary: Microsoft, Auth0 and integrator docs, academic preprints, open-source issue trackers,
  sandbox captures, public bug reports that contain real cookie values.
- **[V]** scraper-vendor or bypass-tool docs and blogs. Weak. Used only to describe observable artifacts, always
  flagged, never the sole basis for a High-confidence finding.

This report covers observable artifacts and conceptual detection logic only. It contains no Akamai script code, keys
or encoding algorithms, and nothing in it requires sending automated traffic to a third-party site.

## Summary

- **Two lab defects block real Safari** (verified by running the lab code). Safari 18's TLS hello is classified as
  `chrome` (with GREASE) or `go` (without), so `tls_fingerprint` fails it at 85. The Safari HTTP/2 profile predates
  2024, so a real Safari 18 scores 75 in `h2_fingerprint`.
- **The HTTP/2 string format is right**, straight from Akamai's 2017 paper. The bracketed `S[…]|WU[…]|P[…]|PS[…]`
  form is notation, not the literal string, and the paper writes an absent WINDOW_UPDATE as `00`.
- **Several artifact shapes differ from real captures.** `bm_sz` looks like `HEX32~YAAQ…~int~int` and `_abck` like
  `HEX32~flag~YAAQ…~-1~-1~-1`. The sensor script sits on a randomized same-origin path, not a fixed `/akam/…` path. The
  pixel uses `/akam/<n>/pixel_<hex>` with its value embedded in the HTML.
- **`~0~` is a convention, not a rule.** Some deployments never show it and expect a fixed number of sensor posts.
- **Akamai's crypto challenge enforces a minimum wall-clock duration** (API field `cryptoChallengeDurationInSeconds`,
  up to 120 s) and has sibling `behavioral` and `adaptive` providers. The lab's proof of work is CPU-only.
- **Biggest missing concepts:** Bot Score segments with non-block actions (tarpit, slow, serve alternate content,
  safeguard), inline telemetry on protected requests, cross-layer "browser version mismatch" checks, JavaScript
  integrity probes (the Playwright client's `webdriver` override is detectable), and Content Protector's 2026
  interactive behavioral challenge with step-up data collection.
- **Fingerprints now age in weeks.** Chrome moved to a two-week stable cadence with Chrome 153 (2026-09-08). The lab's
  `chrome131` impersonation profile is about 23 majors old, and Chrome's JA4 changed at least twice in 2026.

## 1. Accuracy audit

### 1.1 Overview

| # | Case | Status | What to fix | Sources (dates) |
|---|---|---|---|---|
| 1 | `tls_fingerprint` | Needs correction | Add a Safari/WebKit family (real Safari fails today); use 2024–26 Chrome markers (ML-KEM group `4588`, ALPS `17613`, ML-DSA sigalgs) for version checks; flag a non-permuted extension order; refresh JA4 examples and the `chrome131` profile | [Akamai paper, 06/2017][wp17] [P]; [cipher stunting, 2019][stunt] [P]; [JA4 API, 2026-05-28][ja4api] [P]; [curl_cffi #530, 2025-04-05][cc530] [S]; [#500, 2025-02-15][cc500] [S]; [#854, 2026-09-10][cc854] [S] |
| 2 | `h2_fingerprint` | Outdated (Safari profile); format accurate | Safari 18 is `2:0;3:100;4:2097152;9:1\|10420225\|0\|m,s,a,p` (iOS adds `8:1`); absent WU is `00` in the paper; the labeled form is not Akamai's literal format; optionally record HEADERS-frame priority | [Akamai paper, 06/2017][wp17] [P]; [lexiforest, 2025-04-10][lexi] [S]; [curl_cffi #530][cc530] [S] |
| 3 | `header_order` | Needs correction | Add `zstd` (Chrome 123+); `priority` only on h2/h3 (Chrome 124+), so flag it on HTTP/1.1; reduced-UA format; UA major equals `sec-ch-ua` major; `HeadlessChrome` tokens | [detection methods, 2026-03-01][detm] [P]; [priority I2S, 2024-02-16][prio] [P]; [zstd I2S, 2024][zstd] [P]; [UA reduction][uar] [P]; [curl_cffi #785, 2026-06-19][cc785] [S] |
| 4 | `abck_cookie` | Needs correction | Real shape `HEX32~flag~YAAQ…~-1~-1~-1` (lab: 64 hex chars and two `-1`); add an "N posts, no `~0~`" mode; bind validated state to fingerprint continuity | [httpx #2287, 2022-06-30][httpx] [S]; [Coraza #1620, 2026-05-18][coraza] [S]; [Hyper docs][hyper] [V] |
| 5 | `sensor_data` | Needs correction | Randomized per-session same-origin script path; POST `{"sensor_data": …}` back to that path; 1–3 posts; version-prefixed payload keyed to the script build and `bm_sz`; add an inline-telemetry variant | [Bot Manager brief, 10/2023][bmbrief] [P]; [WSA dimensions, 2026-09-30][wsa] [P]; [Winney, 2019-12-30][winney] [S]; [Hyper docs][hyper] [V]; [v3 helper][v3] [V] |
| 6 | `proof_of_work` | Needs correction | Mandatory wait (`chlg_duration`); re-challenge interval; 428 JSON for XHR; `sec-cpt-if` iframe; verify under `/_sec/`; check `sec_cpt` (`~3~`); providers crypto/behavioral/adaptive; the arithmetic variant has no Akamai analogue | [challenge action API, 2026-06-02][chal] [P]; [brief, 10/2023][bmbrief] [P]; [any.run, 2020-06-19][anyrun20] [S]; [PriceStalker, 2026-09-26][ps] [S]; [Hyper 428][hyper428] [V] |
| 7 | `pixel_challenge` | Needs correction | `bm_sz` is a seed cookie, not a challenge. Pixel: value embedded in the HTML (`bazadebezolkohpepadr`), script `/akam/<n>/<hex>`, POST to `/akam/<n>/pixel_<hex>`, tied to `ak_bmsc`; drop `/config` | [any.run, 2019-11-04][anyrun19] [S]; [Winney, 2019-12-30][winney] [S]; [PriceStalker][ps] [S]; [crawlex, 2026-06-01][cxpixel] [V] |
| 8 | `sbsd_challenge` | Needs correction (low confidence) | Script `/<path>?v=<UUID>` (blocking mode adds `&t=`); POST `{"body": …}` to the same path (passive mode: 2 posts); `bm_so`/`sbsd_o` are issued first and used as input; cookies `bm_s`, `bm_ss`, `bm_sc`, `bm_lso` | [Hyper SBSD][hypersbsd] [V]; [xhrdev, 2026-09-21][xhr] [V]. No primary source |
| 9 | `behavioral` | Accurate (concept); needs expansion | Premier-only; evaluated on transactional endpoints; multi-modal (keys, touch, device motion); feeds the Bot Score; 2026 interactive behavioral challenge | [detection methods][detm] [P]; [Content Protector PR, 2024-02-06][cppr] [P]; [Akamai blog, 2026-03-10][avf] [P] |
| 10 | `ip_reputation` | Needs correction | Burst (1–5 s) and average (2 min) thresholds in hits/s; identifiers incl. `ip-useragent` and `tls-fingerprint`; penalty box of 10 min to 24 h; reputation categories scored 1–10; ASN and TLS client lists | [rate policy API, 2026-05-28][rate] [P]; [client lists, 2026-08-14][clists] [P]; [client reputation, 2026-03-01][crep] [P]; [penalty box, 2020-12-15][pbox] [P] |

### 1.2 Case notes

#### Case 1: `tls_fingerprint`

Documented and observed:

- Akamai treats TLS as one of three passive layers (TCP/IP, TLS, HTTP) and recommends correlating them to expose
  spoofed User-Agents and proxies ([Akamai white paper, 06/2017][wp17] [P]). Its "cipher stunting" research tracked
  bots that randomize cipher lists, with distinct TLS fingerprints jumping from tens of thousands to billions
  ([Akamai blog, 2019][stunt] [P]).
- In 2026, JA4 can be forwarded to the origin in a header you name (example `ja4-fingerprint`; beta; listed for Web
  Application Protector and Kona Site Defender) ([JA4 settings API, 2026-05-28][ja4api] [P]). `TLS_FINGERPRINT` is a
  client-list type ([client lists, 2026-08-14][clists] [P]) and `tls-fingerprint` a rate-control client identifier
  ([rate policy API, 2026-05-28][rate] [P]). The Bot Manager brief advertises "browser impersonation detection"
  ([brief, 10/2023][bmbrief] [P]).

What the lab gets right: comparing the TLS family with the claimed UA instead of allow-listing hashes, and relying on
JA4's sorted extensions, which survive Chrome's per-connection permutation.

Corrections:

1. **Real Safari fails (verified).** Safari 18.3's published hello has Chrome's TLS 1.3 cipher prefix
   (`4865-4866-4867`), `compress_certificate` (27) and padding (21), no ALPS, no ECH, and legacy CBC/3DES suites at the
   tail (`…-53-47-49160-49170-10`) ([curl_cffi #530, 2025-04-05][cc530] [S]). Run through `classify_tls`, it returns
   `chrome` when the GREASE flag is set and `go` when it isn't; against a Safari UA both mean fail 85. Add a `safari`
   family keyed on that shape. Safari's JA4 family is `t13d2014h2_a09f3c656075_*`, seen for Safari 16–18 on macOS and
   iOS ([Scrapfly JA4 DB, accessed 2026-10-02][ja4safari] [V]). Every iOS browser (CriOS, FxiOS, EdgiOS) runs on
   WebKit, so a Chrome-on-iOS UA legitimately arrives with a Safari hello.
2. **Use era markers.** Recent Chrome changes give version checks that survive permutation:
   - X25519MLKEM768 (`0x11EC` = 4588) replaced Kyber (`0x6399`) as the hybrid group in Chrome 131
     ([The Hacker News, 2024-09][thn] [S]).
   - ALPS moved to codepoint 17613 ([Intent to Ship, 2024-01-12][alps] [P]). Chrome 133 sends 17613, while
     curl_cffi's `chrome131` profile still sends 17513 ([curl_cffi #500, 2025-02-15][cc500] [S]).
   - Chrome 150 prepends ML-DSA signature schemes: its JA4_r signature list starts `0904,0905,0906,…`
     ([curl_cffi #854, 2026-09-10][cc854] [S]). Go 1.27 also advertises ML-DSA ([Go #81199][goiss] [S]), so treat it
     as an era marker only together with other Chrome marks.
   - Chrome's JA4 went from `t13d1516h2_8daaf6152771_02713d6af862` (about 120–131) and `…_d8a2da3f94cd` (about 133–149)
     to `t13d1517h2_8daaf6152771_cb7bf5808d99` on 152–154 ([Scrapfly JA4 DB][ja4db] [V]; [Clearcote, Chrome 153][cc153]
     [S]). `KNOWN_FINGERPRINTS["chrome-ja4"]` is only illustrative, but it is stale.
3. **Use permutation as a signal.** Chrome 110+ shuffles extension order on every connection. A "Chrome" that
   presents the same raw `x-tls-exts` order on every connection is not behaving like Chrome, and the edge already emits
   the data. Whether Akamai uses this exact check is not public.
4. **Profile age.** Chrome moved to a two-week stable cadence starting with Chrome 153 on 2026-09-08
   ([Chrome blog, 2026-03-03][twoweek] [P]). `chrome131` (November 2024) is about 23 majors behind. Akamai does not
   publish whether it penalizes old but genuine versions; the measurable risk is cross-layer version mismatch (§2.2).
5. **Rarity.** The lab's Playwright JA4 (`…_cca3cc876f32`) returned no public matches when searched on 2026-10-02;
   curl_cffi's did. Akamai says a bot detected at one customer is added to its known-bot library "for all customers
   within minutes" ([brief, 10/2023][bmbrief] [P]), so "fingerprint never seen in real traffic" is a fair lab signal.

#### Case 2: `h2_fingerprint`

The format, from the source ([Akamai white paper, 06/2017][wp17] [P]):

- Notation `S[;]|WU|P[,]#|PS[,]`. **S**: `id:value` pairs in order of appearance, joined with `;`. **WU**: the
  WINDOW_UPDATE increment, "'00' if the frame is not present". **P**: one
  `StreamID:Exclusivity_Bit:Dependant_StreamID:Weight` tuple per PRIORITY frame, joined with `,`, or `0` if there are
  none (weights print as the wire byte + 1, for example 201). **PS**: pseudo-header letters `m`, `a`, `s`, `p`.
- The paper's Firefox 53 example: `1:65536;4:131072;5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1|m,p,a,s`.
- The brackets describe list separators; the literal string has no `S[` or `WU[` labels. The edge's
  `x-h2-fingerprint` matches the paper. `x-h2-fingerprint-labeled` is a lab convenience and shouldn't be documented as
  Akamai's format. Modern tools print an absent WU as `0`; the paper says `00`. Accept both.

Current values:

| Client | Akamai string | Source |
|---|---|---|
| Chrome 136 (unchanged through 154) | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | [lexiforest, 2025-04-10][lexi] [S]; [Clearcote, Chrome 154][cc154] [S] |
| Firefox 138 | `1:65536;2:0;4:131072;5:16384\|12517377\|0\|m,p,a,s` | [lexiforest][lexi] [S] |
| Safari 18.4 (macOS) | `2:0;3:100;4:2097152;9:1\|10420225\|0\|m,s,a,p` | [lexiforest][lexi] [S] |
| Safari 18.3 (iOS) | `2:0;3:100;4:2097152;8:1;9:1\|10420225\|0\|m,s,a,p` | [curl_cffi #530, 2025-04-05][cc530] [S] |

- The Chrome and Firefox profiles match. Firefox no longer sends the PRIORITY-frame tree from the 2017 example.
- **The Safari profile is outdated (verified).** The lab's Safari profile (`2:0;3:100;4:2097152`, WU `10485760`,
  `m,s,p,a`) matches old Safari; the paper's Safari 10.1 sent `:method, :scheme, :path, :authority`. Scored with
  `compare()`, both Safari 18 strings get 75 (ids/order +30, WU +20, pseudo-order +25): fail. Setting 9 is
  `SETTINGS_NO_RFC7540_PRIORITIES` and 8 is `SETTINGS_ENABLE_CONNECT_PROTOCOL`.
- Optional extra: Chrome carries its priority in HEADERS-frame flags and, since Chrome 124, in the RFC 9218 `priority`
  header on HTTP/2 and HTTP/3 ([Intent to Ship, 2024-02-16][prio] [P]). `h2sniff.go` currently skips the HEADERS
  priority bytes. Recording them adds a component outside the Akamai string.

#### Case 3: `header_order`

- Akamai documents that transparent detection looks for request anomalies such as "out-of-order headers and browser
  version mismatches" ([detection methods, 2026-03-01][detm] [P]). The case is legitimate; the thresholds are the
  lab's own, which is fine.
- Updates for current Chrome:
  - `accept-encoding: gzip, deflate, br, zstd` since Chrome 123 ([Intent to Ship: zstd][zstd] [P]). A Chrome 123+ UA
    without `zstd` is a version mismatch.
  - `priority: u=0, i` on navigations since Chrome 124, on HTTP/2 and HTTP/3 only ([Intent to Ship, 2024-02-16][prio]
    [P]). curl_cffi's Chrome impersonation also sends it on HTTP/1.1, an open issue
    ([curl_cffi #785, 2026-06-19][cc785] [S]). Flag `priority` on h1.
  - The reduced UA has been complete since Chrome 113: `Chrome/<major>.0.0.0` with frozen platform tokens
    ([Chromium UA reduction][uar] [P]). A full build number in a desktop Chrome UA is a mismatch.
  - `sec-ch-ua` brands and their GREASE entry change with every release. Chrome 153 sends
    `"Google Chrome";v="153", "Not_A Brand";v="8", "Chromium";v="153"`; Chrome 154 reorders them and uses
    `"Not A(Brand";v="99"` ([Clearcote 153][cc153], [154][cc154] [S]). Check the UA major against the `sec-ch-ua`
    major.
  - Akamai has said its edge can request client hints (Accept-CH, Critical-CH, ALPS ACCEPT_CH) and that Bot Manager
    was being updated to read them ([Akamai developer blog, 2022-10-27][akuar] [P]). Akamai-fronted pages may ask for
    high-entropy hints such as `sec-ch-ua-full-version-list`.
- Casing only matters on HTTP/1.1. RFC 9113 makes uppercase field names on h2 a malformed request, so the h2 casing
  rule will rarely fire.
- Across vendors, a 2026 measurement found 75% of headless-only blocks disappeared once the UA headers were spoofed
  ([Gundelach et al., 2026-06-12][bamberg] [S]). Tokens such as `HeadlessChrome` in the UA and client hints matter
  more in practice than order.

#### Case 4: `abck_cookie`

- Real values: `_abck=97471718CACFA8B8712FA08864AE7E33~-1~YAAQF+ZlXwUI…=~-1~-1~-1` and, from the same response,
  `bm_sz=118A0D88115C5E503300B088C49F1D00~YAAQFuZlX70N…==~4273478~4404549` ([httpx #2287, 2022-06-30][httpx] [S]).
  A 2026 report shows a value of the form `<hex32>~0~yaaq…~-1`, lowercased by the reporter
  ([Coraza #1620, 2026-05-18][coraza] [S]). The shape: a 32-hex id, a state flag, a `YAAQ`-prefixed base64 blob (the
  same prefix appears in `bm_sz`), then `-1` fields (three in 2022).
- The lab generates `secrets.token_hex(32)`, which is 64 hex characters (should be 32), and two trailing `-1` fields.
- Validity: vendor docs say the cookie is valid once it contains `~0~`, and that on sites which never show it the client
  should post exactly 3 sensors ([Hyper getting started][hyper] [V]). A 2026 write-up calls `~0~` "a convention, not a
  guarantee" ([crawlex, 2026-06-04][cxabck] [V]). Model `~0~` as one mode, and add a mode where validity lives only on
  the server; the lab's store already models server-side truth.
- Lifecycle: issued with `bm_sz` and `ak_bmsc` on the first response, refreshed by `Set-Cookie` on sensor POST
  responses, with about a one-year lifetime ([Hyper][hyper] [V]; cookie databases [S]).
- Akamai frames cookie and JavaScript checks as active detection, which "employs an interaction to confirm the request
  is coming from a web browser" ([detection methods][detm] [P]). Names such as "Cookie Integrity Failed" circulate, but
  Akamai's detection list is in the login-gated Bot Manager API reference and could not be read.
- Worth adding: bind the validated state to fingerprint continuity (JA4 family, UA, IP prefix or ASN), and treat a
  validated `_abck` replayed under a different fingerprint as tampering. Akamai's exact binding rules are not public.

#### Case 5: `sensor_data`

- Delivery: a `<script>` near the end of `<body>` whose same-origin path is long, random and multi-segment (example
  `/yMOlMy/yS/3T/NVx6/a7xTRI1O5hJJ8/EDi7z45Ou1bfXb/dzldXmhnIQk/CjdBHQkD/Hn0`) and changes over time. The client POSTs
  `{"sensor_data":"…"}` to that same path, the response updates `_abck` with `Set-Cookie`, and 1–3 posts are typical
  ([Hyper getting started][hyper] [V]). In 2019 the same kind of script was served from `/resources/<hex>` and
  `/assets/<hex>` on Lowe's and FedEx ([Winney, 2019-12-30][winney] [S]). Akamai itself says "dynamic obfuscation of
  code and telemetry protects against reverse engineering" ([brief, 10/2023][bmbrief] [P]).
- Payload families, from community reverse engineering [V]: legacy 1.7 strings used `-1,2,-94,-NNN,` section markers
  (for example `-100` environment, `-108` keyboard, `-110` mouse, `-117` touch) ([crawlex, 2026-06-03][cxsensor] [V]).
  "v2" added encryption of the serialized string. "v3" (write-ups from about 2024) starts with
  `3;0;1;0;<bm_sz-derived hash>;…` and keys the encoding to the specific script file and the session's `bm_sz`, so a
  sensor made for one script or session can't be reused ([v3 helper][v3] [V]).
- Telemetry categories: device and browser fingerprint (canvas, WebGL, audio, fonts, screen, navigator); interaction
  (mouse, keys, touch, scroll, focus, device motion and orientation; desktop motion-sensor prompts in 2019 traced back to
  this script ([Winney][winney] [S])); timing; and integrity probes (webdriver, `window.chrome`, prototype tampering)
  ([crawlex][cxsensor] [V]).
- Inline telemetry: Akamai's analytics separate "Web client - standard telemetry" (first-party cookies) from "Web
  client - inline telemetry" (requests "to which Bot Manager attaches user telemetry directly") and native apps
  ([WSA dimensions, 2026-09-30][wsa] [P]), each with its own score thresholds ([brief][bmbrief] [P]). See §2.5.
- Lab changes: serve the script on a per-session random path and accept the POST there; add a version prefix; key the
  encoding to (script build id, `bm_sz`) so payloads don't transfer between sessions; accept or require 1–3 posts.

#### Case 6: `proof_of_work`

- Akamai's API lists challenge types `GOOGLE_RECAPTCHA`, `AKAMAI_WEB_CRYPTO` and `AKAMAI_MOBILE_CRYPTO`, with
  `challengeIntervalInSeconds` (1–7200), `cryptoChallengeDurationInSeconds` (up to 120), `allowFullCpuUtilization` and
  custom branding URLs ([create challenge action, 2026-06-02][chal] [P]). The brief describes "minimum-time-to-solve
  cryptographic puzzles" and a separate interstitial challenge that "requires clients to prove they support storing
  cookies and executing JavaScript. If not, Bot Manager enforces a time penalty" ([brief, 10/2023][bmbrief] [P]).
- Observed artifacts:
  - `/_sec/cp_challenge/sec-cpt-2.8.js` on a retail site in 2020 ([any.run, 2020-06-19][anyrun20] [S]).
  - Per vendor docs: a 428 Precondition Required JSON body for API calls, or an HTML page with iframe `sec-cpt-if`
    carrying `provider`, a base64 `challenge` JSON (`token`, `nonce`, `difficulty`, `timestamp`, `timeout`,
    `chlg_duration`, plus `count` for adaptive) and `data-duration`. Verification goes to
    `/_sec/verify?provider=crypto|adaptive` or `/_sec/cp_challenge/verify`, and a solved challenge leaves a `sec_cpt`
    cookie containing `~3~`. Providers are `crypto` (PoW plus mandatory wait), `behavioral` (sensor posts) and
    `adaptive` (both) ([Hyper 428][hyper428] [V]).
  - A 2026 scraper fix recognizes the behavioral interstitial by the classes `sec-if-cpt-container`,
    `scf-akamai-logo`, `sec-bc-tile-parent` and `sec-bc-text-container` (HTTP 200, about 2.7 KB, no `<title>`)
    ([PriceStalker PR #226, 2026-09-26][ps] [S]).
- Lab gaps: no minimum duration (a fast solver passes instantly), no 428, the `sec_cpt` cookie is never checked, and I
  found no Akamai analogue for the arithmetic "legacy" variant. Relabel it as lab-only or drop it.
- Fix: store `issued_at` with the challenge and reject a correct answer that arrives before `chlg_duration`; return
  428 JSON to `Accept: application/json` and the iframe page to navigations; support `count > 1`; re-challenge after
  the interval; validate `sec_cpt`.

#### Case 7: `pixel_challenge` (and `bm_sz`)

- The case conflates two things. `bm_sz` is a cookie issued on the first response (about four hours) with the shape
  `HEX32~YAAQ<base64>~<int>~<int>` ([httpx #2287][httpx] [S]); vendors describe it as an input to sensor encoding
  ([v3 helper][v3] [V]). It is not a challenge. The lab's `bm_sz` (`HEX32~HEX8`) has the wrong shape.
- Pixel artifacts: `/akam/11/pixel_16cff819` on TikTok in 2019 ([any.run, 2019-11-04][anyrun19] [S]) and
  `/akam/11/pixel_49faa00b` on Lowe's ([Winney][winney] [S]), still matched as `/akam/\d+/pixel_` in 2026
  ([PriceStalker][ps] [S]). Vendor docs add that the HTML assigns a value to the global `bazadebezolkohpepadr`, a script
  loads from `/akam/<n>/<hex>`, the client POSTs pixel data to `/akam/<n>/pixel_<hex>`, and the result is tied to
  `ak_bmsc` ([crawlex, 2026-06-01][cxpixel] [V]; [antibot.to][antibot] [V]). Search snippets also show a hidden
  `<noscript><img>` fallback styled `visibility:hidden; position:absolute; left:-999px`; I did not fetch a page that
  confirms it.
- Lab gaps: `/config` hands out the token (real deployments embed the value in the HTML); a GIF plus JSON beacon
  replaces the POST to `pixel_<id>`; the result isn't tied to `ak_bmsc`; and `ak_bmsc` isn't HttpOnly (vendors
  describe it as HttpOnly; Low confidence).

#### Case 8: `sbsd_challenge`

- No Akamai primary source found. Vendors expand SBSD as "State Based Scraping Detection"
  ([Hyper SBSD intro][hypersbsd] [V]).
- Artifacts (all [V]):
  - Passive mode: a script `/<random path>?v=<UUID>` on normal pages, then two POSTs (index 0 and 1) of
    `{"body":"…"}` back to that path. Blocking mode: a challenge page whose script adds `&t=<token>`, then one POST to
    `/<path>?t=<token>` ([Hyper SBSD flow][hypersbsdflow] [V]).
  - The `sbsd_o` cookie value (or `bm_so` if absent) is an input to the payload.
  - `bm_s`, `bm_so`, `bm_sc` or `bm_lso` in the cookie jar indicate SBSD, and some properties serve it from
    `/.well-known/sbsd` ([xhrdev, updated 2026-09-21][xhr] [V]). Site cookie disclosures list `bm_so` at 1 day, `bm_lso`
    and `bm_s` at 1 month, and `bm_ss` at 1 hour [S, weak].
- Lab mismatches: `sbsd_o` is set after success (it should be issued first and consumed); the body is `{t, v}` sent to
  `/verify` instead of `{"body": …}` sent to the script path; and there is only one mode.
- Speculation, unverified: the name and timing fit Content Protector (scraper-specific, launched 2024-02-06), but
  nothing public links them.

#### Case 9: `behavioral`

- Akamai's behavioral detection evaluates "movement patterns and other interaction details unique to humans" and is a
  Bot Manager Premier feature ([detection methods][detm] [P]). Content Protector analyzes user interaction
  (touchscreen, keyboard, mouse) and user behavior across the site ([Content Protector PR, 2024-02-06][cppr] [P]).
  Akamai's mobile SDK docs, as quoted in 2019, list "device characteristics, device orientation, accelerometer data"
  ([Winney][winney] [S]).
- In March 2026 Akamai added an opt-in interactive behavioral challenge with "five mini-game types using grids of
  numbers or letters" that records mouse, touch and key telemetry; users "won't be re-challenged for at least 50
  minutes" ([Akamai blog, 2026-03-10][avf] [P]).
- Results feed the Bot Score (0–100) and its response segments (§2.1).
- Lab gaps: mouse only, a 2 s window, evaluated on every page. Expand to keystroke timing, touch and device motion;
  evaluate on transactional endpoints (for example, telemetry captured while a login form is filled in); map the score
  into segments.

#### Case 10: `ip_reputation`

- Rate controls: `averageThreshold` is "the allowed hits per second during any two-minute interval" and
  `burstThreshold` the same "during any five-second interval" (`burstWindow` 1–5 s). Client identifiers are `ip`,
  `ip-useragent`, `api-key`, `cookie:<name>`, `request-header:<name>`, `tls-fingerprint` and `query-string:<name>`.
  Counters are `per_edge` or `region_aggregated`, `penaltyBoxDuration` runs from `TEN_MINUTES` to
  `TWENTY_FOUR_HOURS`, and conditions include `TlsFingerprintCondition` and `ClientReputationCondition`
  ([rate policy API, 2026-05-28][rate] [P]).
- Client Reputation: categories `DOSATCK`, `SCANTL`, `WEBATCK` and `WEBSCRP`, scored 1–10; Akamai's docs recommend a
  threshold of 8 or higher ([client reputation, 2026-03-01][crep] [P]). Shared-IP handling (`SHARED_ONLY`,
  `NON_SHARED`, `BOTH`) appears in Akamai's Terraform reputation-profile docs (seen in a search snippet; page not
  fetched). There is a public lookup at [akamai.com/clientrep-lookup][creplookup].
- Penalty box: a client that triggers a Deny keeps receiving the chosen action for 10 minutes
  ([Akamai blog, 2020-12-15][pbox] [P]).
- Client lists: IP, GEO, ASN, FILE_HASH, TLS_FINGERPRINT, USER_ID, DOMAIN and REQUEST_HEADER_NAME_VALUE
  ([client lists, 2026-08-14][clists] [P]).
- Microsoft documents Akamai blocking by connection volume, with the "Access Denied … Reference #18…" page and
  temporary blocks ([Microsoft Learn, 2026-02-12][mslearn] [S]).
- Lab gaps: fixed 10 s windows that count only scored requests, and a hard-coded "datacenter is bad" table. Akamai's
  reputation is derived from behavior observed across its network; customers add ASN or IP lists themselves. Whether
  Bot Manager applies a generic hosting-ASN penalty is not public.

## 2. Missing features

### 2.0 What changed recently (2024–2026)

- **Sensor and cookie generation:** the encoding is keyed to the script file and `bm_sz` ("v3" in write-ups from
  about 2024), script paths are per-session and random, a second channel (SBSD) exists whose introduction date is not
  documented, telemetry can travel inline on the protected request, and `~0~` is not universal.
- **New challenge types:** `behavioral` and `adaptive` sec-cpt providers; Content Protector's interactive behavioral
  challenge and step-up collection (AVF, March 2026); a Native App Traffic Protection SDK (2025).
- **Responses to TLS impersonation:** Akamai never names curl_cffi or uTLS. Its public answer is cross-layer
  consistency ("browser impersonation detection", "browser version mismatches", JavaScript-side traits checked against
  protocol data) plus JA4 exposure, TLS-fingerprint client lists and TLS-fingerprint rate limiting. Community issue
  trackers show the practical tells: a stale ALPS codepoint, missing ML-DSA signature schemes, and `priority` on
  HTTP/1.1.
- **Server-side versus client-side:** more edge signals are exposed to customers (JA4 header, TLS-fingerprint
  identifiers, the EdgeWorkers bot segment since December 2025). Client-side collection is becoming on-demand (AVF) and
  inline. Good bots get an identity path (Web Bot Auth, November 2025), and AI bots got three categories
  (September 2026).

The features below are ordered by value for an Akamai-fidelity lab.

### 2.1 Bot Score, response segments and non-block actions

- **What it is:** one 0–100 score combining every detection, with response segments. Akamai's UI example sets
  standard telemetry to Cautious 1–20 (Monitor), Strict 21–60 (Crypto Challenge) and Aggressive 61–100 (Deny), inline
  telemetry to 1–28, 29–80 and 81–100, and has a separate Native Mobile App row ([brief, 10/2023][bmbrief] [P]).
  EdgeWorkers adds `isHuman()` ("haven't triggered any detections, resulting in a bot score of zero") and
  `isSafeguardResponse()` ("set aside by Bot Manager for special handling to prevent a human user from getting
  endlessly trapped by bot detections") ([BotScore object, 2026-03-01][botscore] [P]), exposed in the
  `onBotSegmentAvailable` handler since 2025-12-05 ([changelog][onbot] [P]). Actions include monitor, allow, deny,
  delay, slow, tarpit, serve alternate content, challenge and conditional actions
  ([handle adversarial bots, 2026-09-30][adv] [P]; [Bot Manager brief][bmbrief] [P]; [Account Protector brief][apbrief]
  [P]).
- **Observable artifacts:** often nothing obvious. Responses get slower, content is subtly different, or a challenge
  appears; a 403 is only one possible outcome.
- **Verdict:** High. It tests whether a scraper notices silent degradation.
- **How to simulate:** map the aggregate score to segments with per-endpoint thresholds. Add `tarpit` (hold the
  connection), `slow` (delay the response), `serve_alternate` (200 with perturbed data plus a hidden canary that the
  report records) and `safeguard` (after K failed challenges in T minutes, let the session through under monitoring).

### 2.2 Cross-layer version consistency

- **What it is:** "browser version mismatches" are a named transparent-detection target
  ([detection methods][detm] [P]); Content Protector checks JavaScript-collected traits against protocol-level data
  ([PR, 2024-02-06][cppr] [P]); the 2017 paper correlates TCP, TLS and HTTP/2 ([white paper][wp17] [P]).
- **Observable artifacts:** none on the client; you only see a challenge or block.
- **Verdict:** High, and cheap.
- **How to simulate:** derive a minimum version from passive markers (TLS group 4588 → 131+, ALPS 17613 → 133+,
  ML-DSA signature schemes in a Chrome-shaped hello → 150+, `zstd` → 123+, `priority` on h2 → 124+) and compare it with
  the UA major, the `sec-ch-ua` major and the sensor's `navigator.userAgentData`. Then check your own Playwright run:
  the client pins the UA to `Chrome/131.0.0.0` while the bundled Chromium is a different build. Look in the dashboard
  for whether `sec-ch-ua` and the JA4 era agree with it; overriding the UA without client-hint metadata commonly leaves
  the hints reporting the real build.

### 2.3 JavaScript integrity and automation artifacts

- **What it is:** integrity probes inside the sensor (webdriver flag, `window.chrome`, prototype tampering)
  ([crawlex][cxsensor] [V]; [Edioff analysis][edioff] [V]). A 2026 measurement of 7,944 sites found `navigator.webdriver`
  read on 34% of them, `HeadlessChrome` brand values in client hints as a strong headless tell, and automation honeypot
  properties checked on 46% ([Gundelach et al., 2026-06-12][bamberg] [S]).
- **Observable artifacts:** only the properties the script reads; the results travel inside the payload.
- **Verdict:** High. The Playwright client passes by running
  `Object.defineProperty(Navigator.prototype, 'webdriver', {get: () => false})`, which replaces a native getter with a
  script function. Descriptor and `Function.prototype.toString` checks catch that.
- **How to simulate:** add probes to `sensor.src.js`: native-code checks on Navigator getters, where the `webdriver`
  descriptor lives, `HeadlessChrome` in the UA or brands, framework-injected globals, and the shape of `window.chrome`.
  Score them in `validate_sensor`.

### 2.4 Challenge providers, the 2026 interactive challenge, and AJAX challenge injection

- **What it is:** besides crypto, the `behavioral` and `adaptive` sec-cpt providers ([Hyper 428][hyper428] [V]).
  Content Protector's opt-in interactive behavioral challenge uses tile mini-games, reloads the original request when
  done, supports custom branding and doesn't re-challenge for at least 50 minutes ([Akamai blog, 2026-03-10][avf] [P]).
  Challenge injection rules control whether Akamai injects "AJAX challenge JavaScript" on HTML pages
  (`injectJavaScript`, with per-rule overrides) so that XHR and fetch calls can be challenged
  ([challenge injection rules, 2026-03-01][inject] [P]).
- **Observable artifacts:** 428 JSON on XHR; HTML with `sec-if-cpt-container` and `sec-bc-*` classes; a `sec_cpt`
  cookie ([PriceStalker][ps] [S]).
- **Verdict:** High.
- **How to simulate:** add a `provider` switch to `proof_of_work`; ship an injected helper script that catches 428 on
  fetch and renders the challenge; build a tile-grid page that records pointer and key events and sets a 50-minute
  no-rechallenge marker.

### 2.5 Inline telemetry and transactional endpoints

- **What it is:** telemetry attached to the protected request itself, next to standard (cookie) and native-app
  telemetry ([WSA dimensions][wsa] [P]). Account Protector's protected operations take per-type thresholds for
  `standard`, `inline`, `nativeSdkIos` and `nativeSdkAndroid` ([Akamai Terraform, 2026-03-01][apr] [P]), and Bot
  Manager has a transactional-endpoint resource keyed to API operations ([Terraform][tep] [P]). Vendors observe the
  inline form as an `akamai-bm-telemetry` request header with `&&&`-separated segments including `e=` and
  `sensor_data=` ([capbreaker][capb] [V]; [xiaoweigege][xwg] [V]).
- **Observable artifacts:** an extra request header on protected XHR or POST calls.
- **Verdict:** High. This is where replaying a cookie from a solved session stops working.
- **How to simulate:** mark `/api/login` and `/api/checkout` as transactional; require a fresh telemetry header bound
  to the session, a timestamp and a hash of the request; reject missing, stale or replayed telemetry; use different
  thresholds per telemetry type.

### 2.6 Advanced Validation Framework (step-up collection)

- **What it is:** "If a detection method lacks sufficient information to make a confident decision, the new AVF
  dynamically requests additional data from the device" ([Akamai blog, 2026-03-10][avf] [P]).
- **Observable artifacts:** an extra script or challenge that only gray-zone clients see.
- **Verdict:** Medium-High. It models the shift from always-on to on-demand collection.
- **How to simulate:** when the score lands in the strict segment, serve a step-up script that collects extra probes
  (WebGL, audio, fonts) or the tile challenge, then re-score.

### 2.7 Session validation (`bm_sv`) and browser validation (`bm_mi`)

- **What it is:** cookie-database descriptions, worded like vendor documentation. `bm_sv` is "used as part of the
  session validation detection method to keep track of the number of HTML page requests and AJAX requests that the
  client makes" (2 h). `bm_mi` is used "to confirm that requests are coming from a real browser using the browser
  validation detection method" (2 h) ([Cookiepedia: bm_sv][cpbmsv] [S, weak]).
- **Observable artifacts:** `bm_sv` and `bm_mi` cookies.
- **Verdict:** Medium. It catches API-only scrapers that never load pages.
- **How to simulate:** count navigations against XHR per session; flag sessions that call JSON endpoints without page
  loads or with broken `Referer`/`Sec-Fetch-Site` chains.

### 2.8 Native-app telemetry

- **What it is:** the Bot Manager Premier SDK sends sensor data in `X-acf-sensor-data`, "ONLY on HTTP requests to URLs
  configured for protection" ([OutSystems plugin README][cordova] [S]). Content Protector now has a Native App Traffic
  Protection SDK ([WSA changelog, 2025-08-11][natsdk] [P]; [Akamai blog, 2026-03-10][avf] [P]), and there is an
  `AKAMAI_MOBILE_CRYPTO` challenge type ([challenge action API][chal] [P]). Akamai's SDK docs moved behind a login.
- **Observable artifacts:** the `X-acf-sensor-data` request header on protected mobile API calls.
- **Verdict:** Medium; High if you scrape mobile APIs.
- **How to simulate:** a `/mobile/api/*` surface that requires `X-acf-sensor-data` (device id, app version, SDK
  version, sensor stream), plus a JSON crypto challenge.

### 2.9 Verdict headers to the origin

- **What it is:** `Akamai-Bot`, with an observed value of
  `Akamai-Categorized Bot (amazonbot):monitor:Web Search Engine Bots` ([udger][udger] [S]); `akamai-user-risk`, which
  Auth0 ingests alongside `akamai-bot` ([Auth0][auth0] [S]), for example
  `uuid=…;requestid=…;status=4;score=0;general=…;risk=;trust=udbp:…|udfp:…|udop:…|ugp:FR|unp:12322|utp:weekday_3;allow=0;action=monitor`
  ([nextreason, 2025-05-19][nextreason] [S]); the JA4 header ([JA4 API][ja4api] [P]); and the EdgeWorkers segments
  ([BotScore object][botscore] [P]).
- **Observable artifacts:** origin-side request headers only; clients never see them.
- **Verdict:** Medium. It makes the lab's verdicts consumable by an origin and lets you test origin-side logic.
- **How to simulate:** have the API add these headers to proxied requests and show them in the inspector.

### 2.10 Account Protector

- **What it is** (brief, 09/2024): user behavioral profiles ("previously observed locations, networks, devices, IP
  addresses, and activity time"), population profiles, source reputation, risk/trust/general indicators, email address
  and email domain intelligence (including disposable domains), account-opening abuse, header injection, and actions
  that include "cryptographic and behavioral challenge" and "serve alternate content"
  ([Account Protector brief, 09/2024][apbrief] [P]). Scores come from "user behavior profiling, population profiling,
  and reputation data" ([Akamai Terraform][apr] [P]).
- **Observable artifacts:** the `Akamai-User-Risk` origin header (§2.9) and challenges on login or signup.
- **Verdict:** Medium, for login and signup flows only.
- **How to simulate:** a login endpoint with a per-username profile (seen ASNs, UA families, geo, active hours). Risk
  rises for a new device, a new ASN or impossible travel. Emit `Akamai-User-Risk`.

### 2.11 Known bots, AI categories and signed agents

- **What it is:** a known-bot directory (1,750 bots in 2023) ([brief][bmbrief] [P]) and an "Impersonators of Known
  Bots" detection ([Terraform detection][tfdet] [P]). On 2026-09-03 Akamai split AI bots into AI training crawlers, AI
  search crawlers, and AI fetchers and agents ([Akamai blog][aicat] [P]). Since late 2025 Akamai verifies Web Bot Auth
  (HTTP Message Signatures, [RFC 9421][rfc9421]) and discusses Know Your Agent, Visa's Trusted Agent Protocol and
  Skyfire/TollBit monetization ([Akamai blog, 2025-11-20][agentic] [P]).
- **Observable artifacts:** signed requests carry `Signature` and `Signature-Input` (RFC 9421). The Web Bot Auth drafts
  add `Signature-Agent` and a key directory at `/.well-known/http-message-signatures-directory` (not fetched; Medium).
- **Verdict:** Medium.
- **How to simulate:** a UA claiming to be Googlebot or GPTBot must come from the right IP ranges or reverse DNS, or
  carry a valid signature. Otherwise classify it as an impersonator.

### 2.12 TCP/IP passive fingerprint

- **What it is:** in 2017 Akamai listed TCP/IP (p0f-style) fingerprinting as one of three passive layers and showed
  that correlating it with TLS and HTTP/2 exposes proxies ([white paper][wp17] [P]). Content Protector "evaluates how
  the client establishes the connection with the server at the different layers of the Open Systems Interconnection
  (OSI) model" ([PR, 2024-02-06][cppr] [P]). Akamai doesn't publicly document which TCP fields it scores today.
- **Observable artifacts:** none; it is passive.
- **Verdict:** Medium. It catches Linux-hosted impersonators that claim Windows or macOS.
- **How to simulate:** capture the SYN in the edge (TTL, window, MSS, window scale, option order; needs `NET_RAW` and
  pcap, or eBPF) and compare the inferred OS with the UA platform. Docker networking changes the TTL, so calibrate.

### 2.13 Realistic deny responses

- **What it is:** "Access Denied You don't have permission to access `<url>` on this server.
  Reference #18.85c5d617.1549635923.277a7a1" ([Microsoft Learn][mslearn] [S]). Akamai's Translate Error String tool
  decodes references such as `#9.6f64d440.1318965461.2f2b078`; the third segment reads as a Unix timestamp
  ([Akamai, 2026-09-17][tes] [P]). Denies typically carry `Server: AkamaiGHost` ([aethyn][aethyn] [V]). In the 2026
  measurement, 103 of 110 Akamai-blocked sites showed no vendor branding at all ([Gundelach et al.][bamberg] [S]).
- **Observable artifacts:** the page text, the reference number, the `Server` header and an
  `errors.edgesuite.net` link.
- **Verdict:** Low-Medium. It matters for your scrapers' block-detection logic.
- **How to simulate:** on deny, return a 403 page in this format with a reference that maps to the report in the
  dashboard.

### 2.14 Botnet clustering and the network effect

- **What it is:** a "Botnet ID" analytics dimension ([WSA dimensions][wsa] [P]) and the "catapult algorithm" that
  shares a newly detected bot across all customers within minutes ([brief][bmbrief] [P]).
- **Observable artifacts:** a fresh IP or session gets blocked immediately because its fingerprint was already flagged.
- **Verdict:** Low-Medium.
- **How to simulate:** cluster sessions across IPs by (JA4, H2 string, header-order hash, canvas hash). Once a cluster
  is flagged, new IPs inherit the flag.

### 2.15 Visitor Prioritization (waiting room)

- **What it is:** a cloudlet with an allowed-user cookie (the instance label changes its name) and a waiting-room
  cookie ([Akamai, 2026-06-23][vp] [P]). The cookie is commonly seen as `akavpau_<label>` [S, weak].
- **Observable artifacts:** a waiting-room page and the allowed-user cookie.
- **Verdict:** Low, though the lab's storefront is a "limited sneaker drop", the textbook case.
- **How to simulate:** admit a percentage of new sessions and park the rest on a waiting page with a TTL cookie.

### 2.16 HTTP/3 and QUIC fingerprints

- **What it is:** HTTP/3 SETTINGS and QUIC parameters can be fingerprinted (Chrome's H3 settings
  `1:65536;6:262144;7:100;51:1;GREASE`, pseudo-header order `masp`) ([lexiforest, 2025-04-10][lexi] [S]). I found no
  evidence that Akamai Bot Manager scores them.
- **Observable artifacts:** none known for Akamai.
- **Verdict:** Low for Akamai fidelity; the edge also has no QUIC listener.

## 3. Confidence & gaps

### 3.1 Confidence by finding

| Finding | Confidence | Basis |
|---|---|---|
| HTTP/2 string format and semantics (S, WU `00`, P, PS) | High | Akamai's own paper (old, but it defines the format) |
| Current Chrome and Firefox H2 values | High | Maintainer captures (2025), the lab's own capture, 2026 release notes |
| Lab defects: Safari fails TLS (85) and H2 (75) | High | Re-run locally against published Safari 18 values |
| Akamai fingerprints TLS at the edge; JA4 header; TLS client lists; TLS-fingerprint rate identifier | High | Akamai docs and blogs, 2019–2026 |
| Chrome changes: ML-KEM 4588 (131), ALPS 17613, `zstd` (123), `priority` (124, h2/h3), UA reduction, two-week cadence | High | Chromium/Chrome docs plus independent reports |
| Bot Score 0–100, segments, `isHuman`, `isSafeguardResponse`, `onBotSegmentAvailable` | High | Akamai brief and EdgeWorkers docs |
| Challenge types and fields; minimum-time crypto; interstitial with time penalty | High | Akamai API (2026) and brief (2023) |
| Rate-control fields, penalty box, reputation categories and 1–10 scale, client-list types | High | Akamai API and docs (2020–2026) |
| Telemetry types: standard, inline, native | High | Akamai WSA docs and brief |
| Content Protector capabilities, AVF, interactive behavioral challenge | High | Akamai press release (2024) and blog (2026) |
| AI category split; Web Bot Auth verification | High | Akamai blogs (2025, 2026) |
| Account Protector capabilities and header injection | High | Akamai brief (2024) and Terraform docs |
| Transparent detection covers out-of-order headers and version mismatches | High | Akamai detection-methods page (2026) |
| Deny-page text and reference format | High | Microsoft Learn and Akamai docs |
| Safari 18 TLS and H2 values | Medium | Two 2025 captures; Safari 26 has shipped since and may differ |
| ML-DSA signature schemes in Chrome 150+ | Medium | One issue plus client-library PRs; no Chromium doc found |
| Chrome JA4 strings per version | Medium | Vendor database plus one release-notes site |
| `_abck` and `bm_sz` shapes | Medium | Two public captures (2022, 2026) |
| Random sensor path, POST to the same path, 1–3 posts | Medium | Vendor docs, Akamai's "dynamic obfuscation" claim, a 2019 sighting |
| v3 prefix and script/`bm_sz` keying | Medium | A single reverse-engineering author (about 2024) |
| sec-cpt artifacts: 428, iframe, providers, `~3~` | Medium | Vendor docs, a 2020 sandbox capture, a 2026 PR |
| Behavioral-challenge markup classes | Medium | One 2026 PR, consistent with Akamai's 2026 blog |
| Pixel artifacts | Medium | 2019 captures, a 2026 PR, vendors |
| `Akamai-User-Risk` format | Medium | Integrator doc (2025), Auth0, Akamai brief (header injection) |
| `Akamai-Bot` header format | Medium | Header database, single example |
| `X-acf-sensor-data` | Medium | Integrator README, consistent with many repos |
| Inline header name `akamai-bm-telemetry` | Medium | Concept is primary; the name comes from vendors only |
| `Server: AkamaiGHost` on denies | Medium | Vendor-cited, widely observed |
| Shared-IP handling values | Medium | Search snippet of Akamai Terraform docs |
| SBSD artifacts and modes | Low | Vendors only |
| `~0~` semantics and the 3-post rule | Low | Vendors only |
| Purposes and lifetimes of `bm_so`, `bm_lso`, `bm_s`, `bm_ss`, `bm_sc`, `bm_sv`, `bm_mi` | Low | Site disclosures, inconsistent (at least one is clearly wrong) |
| `ak_bmsc` is HttpOnly; pixel affects `ak_bmsc` | Low | Vendors only |
| Akamai's current use of TCP/IP fingerprints | Low | 2017 paper plus vendor claims |
| Akamai-specific CDP and headless probes | Low | Vendor claims |
| Penalties for old but genuine browser versions | Low | No evidence found |
| HTTP/3 fingerprinting by Akamai | Low | No evidence found |
| Detection names "Cookie Integrity Failed", "Session Validation", "Browser Validation" | Low | Cookie-database wording; the API docs are login-gated |
| SBSD is part of Content Protector | Low | Speculation |
| `akavpau_` cookie prefix | Low | Search snippet only |

### 3.2 Could not verify; needs a captured session

1. `_abck` state transitions on a current site: whether `~0~` appears, after how many sensor POSTs, and what the tail
   fields look like now.
2. `Set-Cookie` attributes (HttpOnly, Secure, SameSite, Max-Age, Domain) for `_abck`, `bm_sz`, `ak_bmsc`, `bm_sv`,
   `bm_mi`, `bm_so`, `bm_s`, `bm_ss`, `bm_lso`, `sbsd_o` and `sec_cpt`.
3. The sensor payload's current version prefix, and whether a site uses standard or inline telemetry (look for
   `akamai-bm-telemetry` on XHR).
4. The SBSD script URL, body shape, cookies, and passive versus blocking behavior.
5. sec-cpt: 428 versus 200, the provider, `chlg_duration` values, the verify path.
6. The behavioral challenge's DOM and the events it records.
7. The pixel POST body, and which cookie changes afterwards.
8. Deny responses: `Server`, `Mime-Version`, the reference format. Tarpit and serve-alternate are hard to observe by
   design.
9. Whether a non-permuted extension order, a stale Chrome version or missing ML-DSA signature schemes get flagged in
   practice.
10. Safari 26's current TLS and H2 values.

How to collect these without leaving the project's boundaries: record a HAR in your everyday browser during an ordinary
manual visit to a site you use anyway (DevTools, Network, "Preserve log", then export the HAR), or better, put an Akamai
trial property in front of a site you own. Diff the capture against the lab's feed. Don't script captures against
third-party sites, and scrub cookies and tokens from HARs before committing them.

### 3.3 Conflicting or unreliable sources

- **Sensor endpoint.** [Edioff][edioff] and [crawlex][cxabck] say sensor data goes to `/_sec/cp_challenge/verify`.
  Other sources use that path as the sec-cpt verifier, and sec-cpt scripts live under `/_sec/cp_challenge/` (2020
  capture). I treated the claim as an error.
- **`bm_sz` HttpOnly.** [crawlex][cxpixel] says it is "typically marked HTTP-only" and also that client-side encoding
  consumes it. Both can't hold if the script reads it from `document.cookie`. Unverified.
- **Safari WINDOW_UPDATE.** One search summary claimed 10485760 for Safari 18; two direct captures show 10420225.
- **`bm_sv` purpose.** Ford's cookie guide calls it a bandwidth-test cookie, while cookie databases describe session
  validation. Site disclosures are unreliable for cookie purposes.
- **Clearcote.** Its Chrome release notes are a single source of unknown provenance; I used them only for JA4 and
  `sec-ch-ua` examples that Scrapfly's database corroborates.
- **Login-gated docs.** Akamai's Bot Manager API reference and SDK docs require a login, so detection-name lists and
  the SDK header docs could not be read directly.

[wp17]: https://blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf
[stunt]: https://www.akamai.com/blog/security/bots-tampering-with-tls-to-avoid-detection
[bmbrief]: https://www.akamai.com/site/en/documents/brief/2021/bot-manager-product-brief.pdf
[apbrief]: https://www.akamai.com/site/en/documents/brief/2021/akamai-account-protector-product-brief.pdf
[detm]: https://techdocs.akamai.com/cloud-security/docs/detection-methods
[adv]: https://techdocs.akamai.com/cloud-security/docs/handle-adversarial-bots
[chal]: https://techdocs.akamai.com/application-security/reference/post-challenge-action
[inject]: https://techdocs.akamai.com/terraform/docs/bmgr-rc-challenge-injection-rules
[ja4api]: https://techdocs.akamai.com/application-security/reference/get-ja4-fingerprint-settings
[rate]: https://techdocs.akamai.com/application-security/reference/get-rate-policy
[clists]: https://techdocs.akamai.com/powershell/docs/configure-client-lists
[crep]: https://techdocs.akamai.com/identity-cloud/docs/client-reputation-1
[creplookup]: https://www.akamai.com/us/en/clientrep-lookup
[pbox]: https://www.akamai.com/blog/security/penalty-box
[botscore]: https://techdocs.akamai.com/edgeworkers/docs/botscore-object
[onbot]: https://techdocs.akamai.com/edgeworkers/changelog/onbotsegmentavailable-event-handler
[wsa]: https://techdocs.akamai.com/security-ctr/docs/dimensions-new
[cppr]: https://www.akamai.com/newsroom/press-release/akamai-announces-content-protector-to-stop-scraping-attacks
[avf]: https://www.akamai.com/blog/security/avoid-evasive-scraping-stronger-content-protection
[natsdk]: https://techdocs.akamai.com/security-ctr/changelog/aug-11-2025-new-wsa-insight-available-for-native-app-traffic-protection-sdk
[agentic]: https://www.akamai.com/blog/security/bot-management-agentic-era
[aicat]: https://www.akamai.com/blog/security/introducing-more-granular-controls-ai-bot-traffic
[apr]: https://techdocs.akamai.com/terraform/docs/set-up-apr
[tep]: https://techdocs.akamai.com/terraform/docs/bmgr-rc-transactional-endpoint
[tfdet]: https://techdocs.akamai.com/terraform/docs/bmgr-ds-detection
[tes]: https://techdocs.akamai.com/edge-diagnostics/docs/translate-error-string
[vp]: https://techdocs.akamai.com/cloudlets/docs/config-visitor-prioritization-beh
[akuar]: https://www.akamai.com/blog/developers/user-agent-reduction
[twoweek]: https://developer.chrome.com/blog/chrome-two-week-release
[alps]: https://groups.google.com/a/chromium.org/g/blink-dev/c/yGdMW_gsGS4
[prio]: https://groups.google.com/a/chromium.org/g/blink-dev/c/U-XvxP0ZQJ0
[zstd]: https://www.mail-archive.com/blink-dev@chromium.org/msg09222.html
[uar]: https://www.chromium.org/updates/ua-reduction/
[rfc9421]: https://www.rfc-editor.org/rfc/rfc9421
[thn]: https://thehackernews.com/2024/09/google-chrome-switches-to-ml-kem-for.html
[mslearn]: https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/access-denied-visit-website-hosted-akamai-cdn
[auth0]: https://auth0.com/docs/secure/attack-protection/configure-akamai-supplemental-signals
[nextreason]: https://docs.nextreason.com/docs/threat-guard-akamai-edge
[udger]: https://udger.com/resources/http-request-headers-detail?header=Akamai-Bot
[cordova]: https://github.com/dawud-outsystems/AkamaiBPMCordovaPlugin
[bamberg]: https://arxiv.org/html/2606.14525v1
[lexi]: https://dev.to/lexiforest/http3-fingerprints-identifying-clients-in-the-quic-era-2k3d
[cc500]: https://github.com/lexiforest/curl_cffi/issues/500
[cc530]: https://github.com/lexiforest/curl_cffi/issues/530
[cc785]: https://github.com/lexiforest/curl_cffi/issues/785
[cc854]: https://github.com/lexiforest/curl_cffi/issues/854
[goiss]: https://github.com/golang/go/issues/81199
[ja4db]: https://scrapfly.io/web-scraping-tools/ja4-fingerprint/t13d1517h2_8daaf6152771_cb7bf5808d99
[ja4safari]: https://scrapfly.io/web-scraping-tools/ja4-fingerprint/t13d2014h2_a09f3c656075_14788d8d241b
[cc153]: https://www.clearcotelabs.com/chrome-releases/153
[cc154]: https://www.clearcotelabs.com/chrome-releases/154
[httpx]: https://github.com/encode/httpx/discussions/2287
[coraza]: https://github.com/corazawaf/coraza/issues/1620
[anyrun19]: https://any.run/report/d804e5085fc80bbce0da822cf5faaa74f85121f7c7235861310522e49242f5dd/1488e9aa-1491-43aa-ba50-34e27a097d18
[anyrun20]: https://any.run/report/236d74f98a662a145fe161cc13b1a2fdb059a1f598ff423da9b2551615bd037b/e3608b73-829b-4625-8146-e91cb57433be
[winney]: https://grantwinney.com/websites-requesting-access-to-motion-sensors/
[ps]: https://github.com/mikeknight85/PriceStalker/pull/226
[cpbmsv]: https://cookiepedia.co.uk/cookies/bm_sv
[hyper]: https://docs.hypersolutions.co/akamai-web/getting-started
[hyper428]: https://docs.hypersolutions.co/akamai-web/handling-428-status-code-sec-cpt
[hypersbsd]: https://docs.hypersolutions.co/akamai-web/sbsd-introduction
[hypersbsdflow]: https://docs.hypersolutions.co/akamai-web/sbsd-challenge-flow
[xhr]: https://apify.com/xhrdev/akamai-sbsd-unblocker
[cxabck]: https://blog.crawlex.net/blog/akamai-bot-manager-abck-cookie/
[cxpixel]: https://blog.crawlex.net/blog/akamai-bmsz-pixel-challenge/
[cxsensor]: https://blog.crawlex.net/blog/akamai-sensor-data-payload/
[v3]: https://github.com/glizzykingdreko/akamai-v3-sensor-data-helper
[capb]: https://capbreaker.gitbook.io/captchabreaker-api/akamai-web-stable/akamai-bm-telemetry
[xwg]: https://github.com/xiaoweigege/akamai2.0-sensor_data
[antibot]: https://docs.antibot.to/reference/akamai/pixel
[edioff]: https://github.com/Edioff/akamai-analysis
[aethyn]: https://www.aethyn.io/blog/what-is-akamai-reference-18-access-denied
