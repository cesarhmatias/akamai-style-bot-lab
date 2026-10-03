# Architecture

```
client -> edge (Go, :8443, TLS + h2 fingerprinting) -> api (FastAPI :8000, engine + 10 modules) <-> redis
browser dashboard (nginx :3000) -> /api/* -> api
```

| service | source | port | role |
|---|---|---|---|
| `edge` | `edge/` | host 8443 | terminates TLS (self-signed, generated at startup), computes JA3/JA4/H2 fingerprint and raw header order, strips client-supplied copies of the `x-*` fingerprint headers, injects its own, proxies to the api over plain HTTP/1.1 |
| `api` | `api/app/` | internal 8000 | scoring engine, detection modules, challenge endpoints, control plane |
| `dashboard` | `dashboard/` | host 3000 | static single-page UI (feed, gauge, inspector, comparison) and nginx proxy of `/api/*` and `/healthz` to the api |
| `redis` | image | internal | session and score state (the api falls back to an in-memory store if `REDIS_URL` is unset) |

## Request lifecycle
1. The client connects to `https://localhost:8443`. The edge reads the ClientHello (JA3, JA4, GREASE flag,
   extension order), and for h2 the SETTINGS / WINDOW_UPDATE / PRIORITY frames and first HEADERS block.
2. The edge forwards the request to the api with `x-ja3`, `x-ja3-hash`, `x-ja4`, `x-ja3-grease`,
   `x-tls-exts`, `x-h2-fingerprint`, `x-header-order`, `x-http-proto`, `x-client-ip` (see `edge/README.md`).
3. `build_context()` (`api/app/engine.py`) builds a `RequestContext`: headers (edge headers removed), wire
   header order, cookies, UA, fingerprints, `session_id` = value of the `bm_sz` cookie.
4. Routes (`api/app/main.py`):
   - `GET /protected/<slug>` evaluates only that module (if enabled; a disabled module means no signals, so 200).
   - `GET /protected/all` and `GET /` evaluate every enabled module. `/` serves the landing page that loads
     every module's `client_scripts`.
   - `/akam/<slug>/...` are module routers (challenge scripts and endpoints). Not scored, not in the feed.
   - Control plane, not scored: `GET /api/modules`, `PUT /api/modules/{slug}` `{"enabled": bool}`,
     `GET /api/requests?limit=N`, `GET /api/feed` (SSE, event `report`), `POST /api/reset`, `GET /healthz`.
5. Modules run concurrently (`asyncio.gather`). An exception in a module becomes a `warn` signal with score 10.
6. The engine aggregates, records a `ScoreReport` in a 500-entry ring buffer (`RING_SIZE`), and publishes it
   to SSE subscribers.
7. Response: 200 JSON `{"ok": true, "case", "report"}` when passed, 403 when blocked. If blocked and
   the request `Accept` contains `text/html`, the body is an HTML interstitial (which loads the challenge
   scripts) instead of JSON. Core then issues `bm_sz`, `ak_bmsc` and `_abck` if missing.

## Scoring
Each module returns a `Signal(module, verdict, score 0-100, reason, details)`.
Verdicts: `pass`, `warn`, `fail`, `block`, `skip`.

    score   = min(100, round(max(scores) + 0.25 * sum(other scores)))
    blocked = score >= BLOCK_THRESHOLD (50)  or  any signal has verdict == block

The strongest signal dominates; the others add a quarter of their weight. For a single-case URL the score is
that module's own score. Per-case clients treat "passed" as HTTP 200.

## State keys (store)
| key | written by | meaning |
|---|---|---|
| `abck:{sid}` | sensor POST | `"validated"` when the sensor was accepted |
| `sensor:{sid}` / `sensor_rejected:{sid}` | sensor POST | latest accepted sensor JSON (read by `behavioral`) / last rejection reason |
| `pow:ch:{cid}` | `/proof_of_work/challenge` | pending challenge, TTL 65 s |
| `pow:{sid}` / `pow:simple:{sid}` | `/proof_of_work/verify` | `"ok"` when the hard / simple variant was solved |
| `pixel:gif:{sid}` / `pixel:{sid}` | pixel routes | GIF fetched / beacon accepted |
| `sbsd:spec:{sid}` / `sbsd:{sid}` | SBSD routes | live challenge spec (TTL 300 s) / `"ok"` when solved |
| `rate:{ip}:{window}` / `rep:{ip}` | `ip_reputation` | per-10 s counters / decaying strikes |
| `toggle:{slug}` | `PUT /api/modules/{slug}` | `"1"` / `"0"`; preserved by `POST /api/reset` |

Most session keys have a 3600 s TTL. `POST /api/reset` clears the store and the feed but keeps toggles.

## Module auto-discovery
`registry.discover_modules()` imports every submodule of `app.modules` and instantiates each concrete
`DetectionModule` subclass defined in it. A module may declare `client_scripts` (paths relative to
`/akam/<slug>/`) and a `router()`; the landing page and interstitial include one `<script>` per entry.

## Tunables
Constants live in the modules (for example `BLOCK_THRESHOLD` in `contract.py`, `DEFAULT_DIFFICULTY` in
`proof_of_work.py`, penalty weights in `behavioral.py`). `ip_reputation` also reads the env vars
`LAB_RATE_FAIL`, `LAB_RATE_BLOCK` and `LAB_BAD_CIDRS`; `docker-compose.yml` does not set them, so add them
under the `api` service `environment:` to use them.
