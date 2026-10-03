# Internal build contract (shared by all components)

Source of truth for interfaces: `api/app/contract.py`. This file pins topology,
routes, slugs and cross-module state so components can be built independently.

## Topology
- `edge` (Go, `edge/`): TLS (self-signed, generated at startup) on `:8443`, ALPN h2 + http/1.1.
  Computes JA3/JA4/H2 fingerprint + raw header order, injects `x-ja3`, `x-ja3-hash`, `x-ja4`,
  `x-h2-fingerprint`, `x-header-order`, `x-client-ip`, `x-http-proto`, strips any client-supplied
  `x-*` of those names, proxies to `api:8000` (plain HTTP/1.1). `/edge -healthcheck` exits 0 if the
  listener answers. Host port 8443.
- `api` (FastAPI, `api/`): port 8000, internal only (reachable from dashboard via nginx).
- `dashboard` (static + nginx, `dashboard/`): host port 3000; nginx proxies `/api/*` and
  `/healthz` to `http://api:8000`. Browser "real browser" tests open `https://localhost:8443/...`.
- `redis`: session/score state. API falls back to in-memory store if `REDIS_URL` unset.

## Case slugs (module `slug`, file `api/app/modules/<slug>.py`, doc `docs/cases/<slug>.md`)
| # | slug | category |
|---|------|----------|
| 1 | tls_fingerprint | passive |
| 2 | h2_fingerprint | passive |
| 3 | header_order | passive |
| 4 | abck_cookie | cookie |
| 5 | sensor_data | js |
| 6 | proof_of_work | js |
| 7 | pixel_challenge | js |
| 8 | sbsd_challenge | js |
| 9 | behavioral | behavioral |
| 10 | ip_reputation | network |

Modules are auto-discovered: the engine imports every submodule of `app.modules` and
registers each concrete `DetectionModule` subclass. No central registry file to edit.

## HTTP routes (API, as seen through the edge)
- `GET /protected/<slug>` — evaluates ONLY that module (if enabled; if disabled -> always 200).
  200 JSON `{"ok": true, "case": slug, "report": ScoreReport}` when passed, 403 JSON
  `{"ok": false, "case": slug, "report": ScoreReport}` when blocked.
  A case is "passed" iff its signal verdict is `pass` or `skip` (score < BLOCK_THRESHOLD).
- `GET /protected/all` — evaluates all enabled modules; blocked iff total score >= 50 or any BLOCK.
- `GET /` (through edge) — "landing page" HTML that loads `/akam/sensor_data/sensor.js` etc.
  (owned by core; JS-module agents provide their scripts, core landing page includes them all).
- Module-specific routes mounted at `/akam/<slug>/...` via `DetectionModule.router()`.
- Control plane (dashboard): `GET /api/modules`, `PUT /api/modules/{slug}` body `{"enabled": bool}`,
  `GET /api/requests?limit=N` (recent ScoreReports), `GET /api/feed` (SSE, event `report`,
  data = ScoreReport JSON), `POST /api/reset` (clear state + feed), `GET /healthz`.
  Control-plane and `/akam/*` requests are NOT scored and NOT in the feed; `/protected/*` and `/` are.
- Clients may send `X-Lab-Client: <name>` (naive|curl_cffi|playwright|browser) -> `ScoreReport.client_label`.

## Session & shared state (store keys)
- `bm_sz` cookie: session id, issued by core middleware on any scored response lacking it
  (value: 32 hex chars + `~` + 8 hex). `ctx.session_id` = full cookie value.
- `ak_bmsc` cookie: issued alongside bm_sz by core (opaque, random).
- `_abck` cookie: issued by core alongside bm_sz with value `<hex>~-1~<b64>~-1~-1` (unvalidated).
  Validated form contains `~0~` (mirrors real Akamai). Server-side truth lives in store key
  `abck:{session_id}` = `"validated"` | absent. Helpers in `app/session.py`:
  `async mark_abck_validated(store, session_id)`, `async is_abck_validated(store, session_id)`,
  `abck_cookie_value(validated: bool) -> str`.
- Sensor POST (`/akam/sensor_data/sensor`) stores latest sensor JSON at `sensor:{session_id}`
  (behavioral module reads it for its scoring).
- Pixel: `pixel:{session_id}` = "ok". PoW: `pow:{session_id}` = "ok". SBSD: `sbsd:{session_id}` = "ok".
- Rate/reputation: `rate:{ip}:{window}` counters, `rep:{ip}`.

## Expected matrix (target behaviour)
| case | naive | curl_cffi | playwright |
|---|---|---|---|
| tls_fingerprint | fail | pass | pass |
| h2_fingerprint | fail | pass | pass |
| header_order | fail | pass | pass |
| abck_cookie | fail | fail | pass |
| sensor_data | fail | fail | pass |
| proof_of_work | fail | pass | pass |
| pixel_challenge | fail | pass | pass |
| sbsd_challenge | fail | fail | pass |
| behavioral | fail | fail | pass |
| ip_reputation | pass | pass | pass |

Rationale: naive does no work; curl_cffi has a real Chrome TLS/H2 stack and can solve
pure-HTTP challenges (PoW in Python, pixel token) but cannot execute JS (sensor, SBSD's
per-session obfuscated code, behavioral). Playwright executes everything.
Headless "HeadlessChrome" UA must NOT be penalised by tls/h2/header modules (they check the
transport, not UA brand) — Playwright client may override UA to normal Chrome anyway.

## Conventions
Python 3.12, fully typed, ruff (config in root pyproject.toml), pytest under `api/tests/`
(`test_<slug>.py` per module). Conventional Commits; commit only your own files
(`git add <your paths>`; if `.git/index.lock` exists, wait a second and retry).

## Client scripts
A module that needs JS in the browser declares an OPTIONAL class attribute
`client_scripts: ClassVar[list[str]] = []` — paths relative to `/akam/<slug>/` (e.g.
`["sensor.js"]` -> `/akam/<slug>/sensor.js`). The core landing page `/` and the HTML 403
interstitial include one `<script src>` per entry, for every registered module.
