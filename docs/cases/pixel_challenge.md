# Case 7: `pixel_challenge` (pixel beacon)

Category: js. Module: `api/app/modules/pixel_challenge.py`. Protected URL: `/protected/pixel_challenge`.

## Mechanism
A tracking-pixel flow: the page learns a per-session id and token, requests a 1x1 GIF carrying them, then
posts a JSON beacon. The server requires both, in that order.

## How real Akamai uses it
Public knowledge: older Bot Manager deployments (the `bm_sz` era) used a pixel script
(`/akam/<version>/pixel_<id>`) whose requests carry a per-session token; the lab imitates that idea only
(own paths, own HMAC token). It is deliberately the cheap, replayable end of the spectrum.

## How THIS server detects it
Routes under `/akam/pixel_challenge/`:
1. `GET /config` -> `{pixel_id, token}`; both are HMAC-SHA256 of the `bm_sz` with a random per-process
   secret (`pixel_id` 12 hex chars, `token` 32).
2. `GET /pixel.gif?ap=<pixel_id>&t=<token>` always returns a GIF, but only a valid pair records
   `pixel:gif:{sid}`.
3. `POST /beacon` `{ap, t, ts}`: bad pair -> 403 `bad_token`; GIF not fetched first -> 403
   `gif_not_fetched`; otherwise sets `pixel:{sid}="ok"`.

Evaluation: `ok` -> pass 0; otherwise fail 70 "pixel beacon not received for this session".

## How a client passes here
Load `/` (for `bm_sz`), call `/config`, GET the GIF with the values, POST the beacon, all with the same
cookie jar. `clients/curl_cffi_client.py::solve_pixel` does it over plain HTTP; `pixel.js` does it in a browser.

## Observed (real run)
- naive: fail 70, "pixel beacon not received for this session".
- curl_cffi: pass 0, "pixel gif and beacon received".
- Playwright: pass 0, same reason.

## Caveats
- Token secrets are per process: restarting the api container invalidates in-flight sessions' tokens.
- Protects nothing against a client that reads `/config`; by design it demonstrates a weak control.
