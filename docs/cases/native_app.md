# `native_app`: native-app telemetry on the mobile API

Category: js · Module: `api/app/modules/native_app.py` · Protected URL: `/protected/native_app` (the matrix exercises
`GET /mobile/api/profile`) · Default: on · Module tier: **MEDIUM**

## What it is

Mobile apps cannot run the web sensor, so an SDK attaches telemetry to requests to protected API URLs. The module requires
a fresh, MAC-protected `X-acf-sensor-data` header with a device id, versions and a motion-sensor stream on
`/mobile/api/*`.

## How real Akamai uses it

The Bot Manager Premier SDK sends sensor data in `X-acf-sensor-data`, "ONLY on HTTP requests to URLs configured for
protection" ([S], OutSystems plugin README); Content Protector now has a Native App Traffic Protection SDK ([P], WSA
changelog 2025-08-11) and the API lists an `AKAMAI_MOBILE_CRYPTO` challenge type ([P]); report §2.8. Akamai's SDK
documentation is login-gated, so real layouts, device attestation and keys are not public.

## Confidence

| Sub-feature | Tier |
|---|---|
| Native telemetry as a separate telemetry type with its own thresholds | HIGH (WSA docs and brief) |
| Header name `X-acf-sensor-data` | MEDIUM (approximation: one integrator README, consistent with many repos) |
| Header layout, MAC and sensor stream | LAB-defined; reproduces no real SDK format or key |
| Native Bot Score bands 1-25 / 26-70 / 71-100 | LAB-chosen (the report only says native apps have their own row) |

No flag.

## How the lab simulates it

Lab header: `X-acf-sensor-data: lab1;<base64url(json)>;<hmac_sha256_hex(app_key, "lab1;" + base64url)>`, where the JSON is
`{"d": device id (16-64 hex), "av": app version x.y.z, "sv": SDK version x.y.z, "t": ts ms, "n": nonce, "p": request path,
"s": sensor stream}` and each stream sample is `[t_ms, ax, ay, az, gx, gy, gz]`. The key is `LAB_APP_KEY` or a documented
constant shared with the harness (`lab-native-app-key-v1`): it is not a secret, it models the integrity of the SDK-to-server
channel. Applies to the `mobile` endpoint class; the engine uses the `native` telemetry type.

| Check | Verdict | Score |
|---|---|---|
| header missing, malformed, bad device or version format | fail | 90 |
| older than 60 s (or more than 5 s in the future) | fail | 90 |
| MAC mismatch, or bound to another path | block | 100 |
| stream shorter than 8 samples, wrong width, non-increasing timestamps, any reading above 1000 in magnitude, or readings that never change (emulator tell) | fail | 80 |
| nonce replayed (`acf:nonce:{device}:{nonce}`, 180 s) | block | 100 |
| fresh and plausible | pass | 0 |

`build_acf_header()` mints a header for tests and the harness.

## How a scraper passes it

Be the app SDK, or hold the key and build the header per request. Anyone holding the documented sample key can mint it.

## Observed results

| Client | Cell | Verdict and reason |
|---|---|---|
| naive | fail | fail 90, "no x-acf-sensor-data header" |
| curl_cffi | pass | pass 0, "fresh native-app sensor" (it re-implements the documented header with the sample key and a synthetic motion stream, playing an app HTTP stack) |
| Playwright | fail | fail 90, "no x-acf-sensor-data header" (a browser has no native SDK) |
| Patchright | fail | fail 90, same (a browser has no native SDK) |

## Limits and caveats

- The curl_cffi pass is a statement about the lab's documented sample key, not about real SDKs.
- The `AKAMAI_MOBILE_CRYPTO` JSON crypto challenge is served by the `sec_cpt_challenge` providers, not here.
