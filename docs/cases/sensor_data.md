# Case 5: `sensor_data` (obfuscated JS telemetry)

Category: js. Module: `api/app/modules/sensor_data.py`; readable script `api/app/static/sensor.src.js`.
Protected URL: `/protected/sensor_data`.

## Mechanism
A script collects device and interaction telemetry in the browser and POSTs it back as an opaque string.
The server decodes it, checks plausibility, and records the result for the session.

## How real Akamai uses it
Public knowledge: Bot Manager injects a heavily obfuscated, frequently changing script that POSTs
`{"sensor_data": "<opaque string>"}` to a same-origin path; a good result upgrades `_abck` (see
`abck_cookie`). This lab mirrors the flow with its own script and format; no real Akamai code or format
is used.

## How THIS server detects it
1. `GET /akam/sensor_data/sensor.js` returns the script with a per-session XOR key baked in
   (`sensor_key` = first 32 hex chars of `sha256("sensor-key:" + bm_sz)`), string-array rotation and hex
   identifiers (`obfuscate()`), `Cache-Control: no-store`.
2. The script counts keydown/scroll/wheel/touch/click, records up to 300 `[x, y, t]` mouse points,
   navigator/screen/timezone/canvas hash, and timing deltas. It sends 2 s after the first mouse move, at
   300 points, or after 4 s idle without mouse movement.
3. `POST /akam/sensor_data/sensor` with `{"sensor_data": base64(xor(json, key))}`. `validate_sensor()`
   rejects (400, reason stored at `sensor_rejected:{sid}`): `navigator.webdriver` not `false`; JS UA differing
   from the request UA; implausible hardwareConcurrency (1-256), screen (200-16000 px), colorDepth, pixelRatio
   (0.5-8); missing timezone/canvas; fewer than 5 timing deltas or no jitter; non-monotonic clocks or mouse
   timestamps. Success stores `sensor:{sid}`, marks `_abck` validated and sets the `~0~` cookie.
4. Evaluation: stored sensor -> pass 0; rejected -> fail 90 with the reason; nothing -> fail 90
   "no sensor_data posted (JS not executed)".

## How a client passes here
Execute the script in a real JS environment with a patched `navigator.webdriver`
(`clients/playwright_client.py` injects `Object.defineProperty(Navigator.prototype, 'webdriver', {get: () => false})`),
generate some mouse movement, wait for `window.__akSensorDone`, then request the protected URL.

## Observed (real run)
- naive / curl_cffi: fail 90, "no sensor_data posted (JS not executed)".
- Playwright: pass 0, "valid sensor_data received".

## Caveats
- The XOR key derives from the session cookie the client already holds, so this is obfuscation, not
  secrecy: a client that reverse-engineers the format could post a forged payload from Python
  (`encode_payload()` in the module is exactly that encoder). Realism of the content is then judged by
  `behavioral`.
- The `webdriver` check only catches an unmasked automation flag; it is not a general headless detector.
