# Case 8: `sbsd_challenge` (dynamic per-issuance JS challenge)

Category: js. Module: `api/app/modules/sbsd_challenge.py`. Protected URL: `/protected/sbsd_challenge`.

## Mechanism
The server generates a different small program every time, computing a number from values that only a
JS/DOM environment provides, and expects that number back. Nothing is replayable across sessions or issuances.

## How real Akamai uses it
Public knowledge: newer Akamai deployments serve a dynamic script (people refer to `sbsd` / `sbsd_o`
artifacts and a `?v=<uuid>` parameter) that is regenerated frequently and must be executed. This lab is an
independent re-creation of the idea, with its own op set and endpoints.

## How THIS server detects it
- `GET /akam/sbsd_challenge/sbsd.js?v=<uuid>` (needs `bm_sz`) builds a spec from `generate_spec()`:
  random-named variables from sources `title_len`, `ua_len`, `dom_attr`, `dom_text_len`, `ua_char`,
  `str_char`, mixed with a seed through a random sequence of 32-bit ops
  (`add sub xor and or imul rotl xorshr`), then a final `rotl`. Stored at `sbsd:spec:{sid}` (TTL 300 s,
  one live issuance per session; a new request invalidates older `v`).
- The JS runs those steps using `document.title`, a created DOM element and `navigator.userAgent`, then
  POSTs `{t, v}` to `/verify`.
- `/verify` replays the ops in Python (`expected_answer`, using the request UA) and compares `t`.
  Errors (403): `no_challenge`, `stale_v`, `wrong_answer`. The spec is deleted on first use. Success sets
  `sbsd:{sid}="ok"` and an `sbsd_o` cookie.

Evaluation: solved -> pass 0, else fail 80 "SBSD challenge not solved for this session".

## How a client passes here
Load `/` so `sbsd.js` runs in a real JS engine and wait for `window.__akSbsdDone`
(Playwright, see `DONE_FLAGS`). Because `ua_len`/`ua_char` use the UA, the JS and HTTP user agents must match.

## Observed (real run)
- naive: fail 80, "SBSD challenge not solved for this session".
- curl_cffi: fail 80, same reason (no JS engine, so it cannot compute `t`).
- Playwright: pass 0, "SBSD challenge solved".

## Caveats
- By design the bypass for curl_cffi exists but is outside the client: fetch `sbsd.js`, interpret it with a
  JS engine (or port the ops), POST the answer. The module docstring states this limitation explicitly.
- It is not a headless detector: any JS engine with a DOM shim computes the same value.
