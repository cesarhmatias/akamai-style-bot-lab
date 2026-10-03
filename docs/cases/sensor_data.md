# `sensor_data`: browser telemetry posted by an obfuscated sensor

Category: js · Module: `api/app/modules/sensor_data.py` · Protected URL: `/protected/sensor_data`
· Default: on · Module tier: **MEDIUM**

## What it is

A `<script>` near the end of `<body>` collects device, interaction and integrity telemetry and POSTs it back as
`{"sensor_data": "<opaque string>"}`. The server decodes and validates it and refreshes the `_abck` cookie.

## How real Akamai uses it

(Report §1.2 case 5.) The script is served from a long, random, multi-segment same-origin path that changes over time
(for example `/yMOlMy/yS/3T/NVx6/...`); the client POSTs to that same path; one to three posts are typical ([V], with a
2019 sighting on retail sites, [S]). Akamai itself says "dynamic obfuscation of code and telemetry protects against
reverse engineering" ([P], brief 2023). Community write-ups describe a "v3" payload starting `3;0;1;0;<bm_sz-derived
hash>;...` whose encoding is keyed to the script build and the session's `bm_sz` ([V], a single author). Telemetry
categories: device fingerprint, interaction (mouse, keys, touch, scroll, focus, device motion), timing and integrity
probes. Akamai also separates standard (cookie) telemetry from inline telemetry ([P], see `inline_telemetry`).

## Confidence

| Sub-feature | Tier |
|---|---|
| Random same-origin script path, POST to the same path, 1-3 posts | MEDIUM (approximation; vendor docs plus Akamai's "dynamic obfuscation" claim) |
| v3-style prefix and script/`bm_sz` keying | MEDIUM (approximation; one reverse-engineering author) |
| Telemetry categories | HIGH (concept) |

No flag. The real encoding, keys and probe set are unknown ([KNOWN_GAPS](../KNOWN_GAPS.md) item 3).

## How the lab simulates it

- **Path**: `/<6>/<2>/<2>/<4>/<14>/<14>/<10>/<8>/<3>` characters, derived by an HMAC of (server secret, script build id,
  `bm_sz`); it rotates per session and per build and is injected by `page_snippets`. `handle_dynamic` serves the script
  (GET) and accepts the POST at the same path. The script is obfuscated per session (string-array rotation and hex
  identifiers) from the readable `static/sensor.src.js`.
- **Payload (lab-defined)**: `lab3;0;1;<post index>;<hash8>;<base64(xor(json, key))>` with `hash8` and the key both
  derived from (secret, build, `bm_sz`). A payload minted for another session or build fails.
- **Posts**: at most 3 per session (`sensor:n:{sid}`, a fourth is 429); the post index must equal the number already
  accepted, so a verbatim replay is rejected. Rejection reasons go to `sensor_rejected:{sid}`.
- **Structural validation** (`validate_sensor`): `navigator.webdriver === false`, `navigator.userAgent` equals the request
  UA, `hardwareConcurrency` 1-256, screen 200-16000 px, colour depth 8-48, pixel ratio 0.5-8, timezone and canvas
  present, at least 5 timing deltas with jitter, monotonic clocks and mouse timestamps.
- **State**: the decoded JSON is stored at `sensor:{sid}` (read by `behavioral`, `js_integrity`, `version_consistency`),
  the integrity block at `sensor:integrity:{sid}`. The first valid post validates the session for `abck_cookie` (or N
  posts with `abck_n_posts`), recording the fingerprint binding; a later post from another binding is rejected.
- **Score**: sensor stored => pass 0; rejected => fail 90 with the reason; nothing posted => fail 90 "no sensor_data
  posted (JS not executed)".
- Integrity probes are judged by `js_integrity`, not here. `cdp_probes` adds a flag-gated extra (LOW, see that case).

## How a scraper passes it

Run the page in a real browser. From pure HTTP one would parse the `<script src>` path from the HTML, GET it, extract the
per-session key and hash and POST a well-formed `lab3` payload (the harness's pure-HTTP client intentionally does not).
`window.__akSensorDone`, the `ak:sensor` event and `window.__akSensorFlush()` signal completion.

## Observed results

| Client | Cell | Verdict and reason |
|---|---|---|
| naive | fail | fail 90, "no sensor_data posted (JS not executed)" |
| curl_cffi | fail | fail 90, same reason |
| Playwright | pass | pass 0, "valid sensor_data received" |

## Limits and caveats

- Encoding, probes and thresholds are lab-defined; this models the shape of a keyed per-session sensor, not Akamai's
  payload.
- A client that reimplements the encoder passes; nothing is replayable between sessions or builds.
