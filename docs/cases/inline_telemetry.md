# `inline_telemetry`: request-bound telemetry on transactional calls

Category: js · Module: `api/app/modules/inline_telemetry.py` · Protected URL: `/protected/inline_telemetry` (the matrix
exercises it on `POST /api/checkout`) · Default: on · Module tier: **HIGH** (the header name is MEDIUM)

## What it is

Telemetry attached to the protected request itself, instead of (or next to) the cookie-based sensor. A fresh, signed blob
travels with every login or checkout call, so replaying a cookie from a solved session stops working.

## How real Akamai uses it

Akamai's analytics separate "Web client - standard telemetry" (first-party cookies) from "Web client - inline telemetry"
(requests "to which Bot Manager attaches user telemetry directly") and native apps (WSA dimensions, 2026-09-30, [P]);
Account Protector's protected operations take per-type thresholds for `standard`, `inline`, `nativeSdkIos` and
`nativeSdkAndroid` ([P], Terraform docs), and Bot Manager has a transactional-endpoint resource ([P], report §2.5).
Vendors observe the inline form as an `akamai-bm-telemetry` request header with `&&&`-separated segments including `e=`
and `sensor_data=` ([V]).

## Confidence

| Sub-feature | Tier |
|---|---|
| Concept (fresh telemetry bound to the protected request) and the three telemetry types | HIGH |
| Header name `akamai-bm-telemetry` and its `&&&`-separated layout | MEDIUM (approximation: names come from vendors only) |
| The segment contents, MAC and keys | LAB-defined; no real Akamai encoding is reproduced |

No flag.

## How the lab simulates it

Wire format (one line on the wire):

    akamai-bm-telemetry: a=lab1&&&t=<ts ms>&&&n=<nonce 16 hex>&&&h=<request hash>&&&e=<mac>&&&sensor_data=<payload>
    h = sha256( METHOD + " " + path + "\n" + sha256_hex(body) )          (empty body: sha256 of "")
    e = hmac_sha256( key, "a\nt\nn\nh\nsensor_data" ), hex
    key = HMAC(server secret, bm_sz), first 32 hex chars, delivered in the page markup (window.__akInline)
    sensor_data = base64url(JSON of keystroke / mouse / touch / scroll telemetry; key identities are never recorded)

A page script wraps `fetch` and `XMLHttpRequest` for `/api/login` and `/api/checkout` and attaches a fresh header to every
request (string bodies only). The markup also carries the server time, so a skewed client clock does not break the
staleness check. The module applies to `transactional` requests only.

| Check | Verdict | Score |
|---|---|---|
| header missing or malformed | fail | 95 |
| older than 30 s, or more than 5 s in the future | fail | 90 |
| MAC invalid (another session's or tampered) | block | 100 |
| request hash does not match method, path and body | block | 100 |
| nonce already seen (`inline:nonce:{sid}:{nonce}`, 120 s) | block | 100 |
| fresh and request-bound | pass | 0 |

Every result carries `details["telemetry_type"] = "inline"`, so the engine uses the inline Bot Score bands
(1-28 / 29-80 / 81-100). The decoded payload is kept at `inline:last:{sid}`, and `behavioral` judges it on this endpoint
(`source = inline`).

## How a scraper passes it

A browser gets the header from the page script for free. A pure-HTTP client must parse `window.__akInline` from the HTML,
build the payload itself (fabricating plausible interaction data, which `behavioral` then judges) and compute `h` and `e`
per request. The committed `clients/curl_cffi_client.py` does not.

## Observed results

| Client | Cell | Verdict and reason |
|---|---|---|
| naive | fail | fail 95, "no akamai-bm-telemetry header" |
| curl_cffi | fail | fail 95, same reason (no JS, so the page script never runs) |
| Playwright | pass | pass 0, "fresh request-bound telemetry" (login/checkout by in-page `fetch`) |
| Patchright | pass | pass 0, "fresh request-bound telemetry" (in-page `fetch` in the main world: Patchright evaluates in an isolated world by default, where the page's wrapper does not exist) |

The action column shows `deny/aggressive` even for Playwright: on transactional endpoints every applicable module runs,
and other signals (for example `js_integrity`) can still deny the request; the cell reflects this module's own signal.

## Limits and caveats

- Anyone who can read the markup can compute the MAC: the lab models replay and staleness resistance, not secrecy of the key.
- Akamai's real header layout, encoding and keys are not public ([KNOWN_GAPS](../KNOWN_GAPS.md) item 3).
- Bug fixed while building the matrix: the AJAX-injection wrapper turned each browser call into a `Request` whose body the
  inline wrapper did not hash (`hash_mismatch` for every browser login); `Request` bodies are hashed now.
