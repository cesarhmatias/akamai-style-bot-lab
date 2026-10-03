# Architecture

```
client -> edge (Go, :8443, TLS + h2 fingerprinting) -> api (FastAPI :8000, engine + 23 modules + response policy) <-> redis
browser dashboard (nginx :3000) -> /api/* -> api
```

| service | source | port | role |
|---|---|---|---|
| `edge` | `edge/` | host 8443 | terminates TLS (self-signed, generated at startup), computes JA3/JA4/H2 fingerprint and raw header order, strips client-supplied copies of the `x-*` fingerprint headers, injects its own, proxies to the api over plain HTTP/1.1 |
| `api` | `api/app/` | internal 8000 | scoring engine, detection modules, response policy and enforcement, challenge endpoints, control plane |
| `dashboard` | `dashboard/` | host 3000 | static single-page UI (cases, feed, inspector, comparison, policy, flags) and nginx proxy of `/api/*` and `/healthz` to the api |
| `redis` | image | internal | session, score, policy and flag state (the api falls back to an in-memory store if `REDIS_URL` is unset) |

The scope of the simulation, and what is deliberately missing, is in [KNOWN_GAPS.md](KNOWN_GAPS.md); the research it is calibrated
from is [research/akamai-audit-2026-10.md](research/akamai-audit-2026-10.md).

## Request lifecycle

1. The client connects to `https://localhost:8443`. The edge reads the ClientHello (JA3, JA4, GREASE flag, extension order,
   groups, signature algorithms, ALPS codepoint) and, for h2, the SETTINGS / WINDOW_UPDATE / PRIORITY frames and the first
   HEADERS block.
2. The edge forwards the request to the api with `x-ja3`, `x-ja3-hash`, `x-ja4`, `x-ja3-grease`, `x-tls-exts`, `x-tls-groups`,
   `x-tls-sigalgs`, `x-tls-alpn`, `x-tls-alps`, `x-tls-conn`, `x-h2-fingerprint`, `x-h2-headers-priority`, `x-header-order`,
   `x-http-proto`, `x-client-ip` (see `edge/README.md`). Client-supplied copies are stripped first.
3. `context_for()` (`api/app/main.py`) mints the `bm_sz` session id if the request has none (so modules and page snippets always
   see `ctx.session_id`), reads the body of POST/PUT/PATCH (kept up to 64 KiB, with its sha256), resolves the feature flags and
   builds a `RequestContext` through `build_context()` (`api/app/engine.py`): headers (edge headers removed), wire header order,
   cookies, UA, fingerprints, query, endpoint class.
4. Routes (`api/app/main.py`):
   - Scored: `GET /` (page), `GET /protected/<slug>` and `GET /protected/all` (protected), `POST /api/login` and
     `POST /api/checkout` (transactional), `GET|POST /mobile/api/*` (mobile). `/protected/<slug>` evaluates only that module
     (if it is disabled there are no signals, so the resource is served).
   - Module routes: `/akam/<slug>/...` (`router()`), absolute vendor-style paths such as `/_sec/cp_challenge/...` and
     `/.well-known/http-message-signatures-directory` (`root_router()`), the shared challenge verify paths
     `POST /_sec/verify?provider=<p>` and `POST /_sec/cp_challenge/verify` (each challenge provider redeems its own tokens
     through `verify_challenge()`), and a catch-all **mounted last** that offers every other
     unrouted GET/POST path to each module's `handle_dynamic()` (per-session random sensor, pixel and SBSD paths) and otherwise
     answers 404 (and bumps the `SCANTL` reputation counter). Not scored, not in the feed.
   - Control plane (not scored): `GET /api/modules`, `PUT /api/modules/{slug}`, `GET|PUT|DELETE /api/policy`,
     `GET /api/requests?limit=N&reference=&canary=`, `GET /api/requests/{id}`, `GET /api/reference/{ref}`,
     `GET /api/canary/{token}`, `GET /api/flags`, `PUT /api/flags/{name}`, `GET /api/feed` (SSE, event `report`),
     `POST /api/reset`, `GET /healthz`.
5. **Pre-request gate** (`gate()`, page and protected routes only): each enabled module's `pre_request()` may short-circuit before
   any scoring, for example the waiting room (`visitor_prioritization`). A short-circuited
   HTML response still receives the sensor and pixel snippets and the lab's cookies.
6. **Scoring** (`Engine.evaluate`): the selected modules run concurrently (`asyncio.gather`), either the one named by
   `/protected/<slug>` or every enabled module whose `applies_to` contains the request's endpoint class. An exception in a module
   becomes a `warn` signal with score 10 and `details.error`.
7. **Aggregation**: `score = min(100, round(max(scores) + 0.25 * sum(other scores)))`.
8. **Segment**: the score is bucketed per telemetry type (`standard`, `inline` from `inline_telemetry`, `native` for the mobile
   class) into `human` (0), `cautious`, `strict` or `aggressive` using the bands of the response policy.
9. **Action**: the policy maps (endpoint class, segment) to an action. A `block` verdict forces `deny`. A `challenge` is downgraded
   to `monitor` when a challenge provider reports the session already solved one; after K unsolved challenges it becomes
   `safeguard`. A `deny` gets an Akamai-style `Reference #18.<hex>.<ts>.<hex>`; a `serve_alternate` gets a canary
   (`canary:{token}`, 24 h). `blocked` is true for `deny`, `tarpit` and `challenge`.
10. The `ScoreReport` (v2: `segment`, `action`, `telemetry_type`, `canary`, `reference`, `layers`, `origin_headers`, `is_human`,
    `is_safeguard`, `challenge_provider`) is stored in a 500-entry ring buffer (`RING_SIZE`) and published to SSE subscribers;
    then every enabled module's `after_score()` runs (profile learning, step-up arming).
11. **Enforcement** (`enforce()`): the action becomes a response: the real resource, a delayed or chunked one, an empty 403 after a
    tarpit hold, the `serve_alternate` body, the challenge (428 JSON to API callers, an interstitial page to navigations,
    issued by the module that serves the provider), or the deny page (HTML) / 403 JSON. Every scored response gets
    `X-Lab-Report-Id`.
12. **Cookies** (`finalize_cookies`): `bm_sz`, `ak_bmsc` and `_abck` are issued when missing (and `_abck` is refreshed from the
    store's validated state), plus flag-gated extras (`bm_sv`, `bm_mi`) and cookies queued by gates. Shapes and attributes
    come from `api/app/session.py`.

See [cases/bot_score.md](cases/bot_score.md) for the bands, the per-endpoint policy and every action.

## State keys (store)

Per-session keys use `{sid}` = the `bm_sz` value; `SESSION_TTL` is 4 h (the `bm_sz` lifetime). `POST /api/reset` clears the
store but preserves `toggle:*`, `flag:*` and `policy:doc`.

| key | written by | meaning (TTL) |
|---|---|---|
| `toggle:{slug}` / `flag:{name}` / `policy:doc` | control plane | module on/off, feature flag `1`/`0`, the policy document (persistent) |
| `abck:{sid}` / `abck:bind:{sid}` | `sensor_data` | `validated`, and the JA4-family/UA/network binding at that moment (4 h) |
| `sensor:{sid}` / `sensor:n:{sid}` / `sensor:integrity:{sid}` / `sensor_rejected:{sid}` | `sensor_data` | latest accepted sensor JSON, count of valid posts (max 3), integrity block of every decodable post, last rejection reason |
| `sec_cpt:ch:{token}` / `sec_cpt:{sid}` | `sec_cpt_challenge` | pending challenge (timeout + 5 s), solved record with the `sec_cpt` cookie (3600 s) |
| `bm_verify:ch:{token}` / `bm_verify:{sid}` | `bm_verify_interstitial` | pending interstitial (timeout + 5 s), solved interstitial (3600 s) |
| `chlg:fail:{sid}` / `safeguard:{sid}` | policy | sliding window of issued challenges; session let through under monitoring |
| `ichal:{token}` / `ichal:ok:{sid}` | `interactive_challenge` | pending tile challenge (180 s), solved marker (`norechallenge_seconds`, 3000 s) |
| `avf:need:{sid}` / `avf:data:{sid}` | `avf_stepup` | step-up requested (900 s), step-up data and score (3600 s) |
| `pixel:{sid}` / `pixel:bmsc:{sid}` | `pixel_challenge` | beacon accepted; hash of the re-issued `ak_bmsc` (flag) |
| `sbsd:spec:{sid}` / `sbsd:{sid}` | `sbsd_challenge` | live lab-device spec (300 s) / solved (3600 s) |
| `sbsd:path:{sid}`, `sbsd:vspec:{sid}`, `sbsd:tok:{sid}`, `sbsd:o:{sid}` | `sbsd_challenge` (vendor flow) | random path, live spec, blocking token, issued `sbsd_o` |
| `inline:nonce:{sid}:{nonce}` / `inline:last:{sid}` | `inline_telemetry` | replay guard (120 s), last decoded payload |
| `acf:nonce:{device}:{nonce}` | `native_app` | replay guard (180 s) |
| `sv:nav:{sid}` / `sv:xhr:{sid}` / `sv:lastnav:{sid}` | `session_validation` | navigation and XHR counters, last navigation |
| `tlsorder:{ip}:{ja4}` | `tls_fingerprint` | extension order and distinct connections that presented it (3600 s) |
| `rate:{cid}:s:{sec}` / `rate:{cid}:b:{bucket}` / `penalty:{cid}` | `ip_reputation` | per-second and 10 s buckets, penalty box |
| `repcat:{CAT}:{ip}` | `ip_reputation`, catch-all 404 | reputation counters (600 s) |
| `cluster:ips:{key}` / `cluster:hits:{key}:{min}` / `cluster:bad:{key}` | `botnet_cluster` | cluster membership, rate, flagged marker |
| `ap:profile:{hash}` | `account_protector` | per-username login profile (30 days) |
| `botsig:nonce:{keyid}:{nonce}` | `known_bots` | Web Bot Auth replay guard (600 s) |
| `vp:allowed:{sid}` / `vp:parked:{sid}` | `visitor_prioritization` | admitted (3600 s) / parked in the waiting room |
| `canary:{token}` | engine | report id that received the serve_alternate canary (24 h) |

Cookies the lab issues: `bm_sz` (4 h), `ak_bmsc` (2 h), `_abck` (1 year), `sec_cpt` (solved `sec_cpt` challenge), `sec_bc` (tile game),
`sbsd_o` and the vendor-flow cookies, `lab_vp_waiting` / `lab_vp_allowed`, and the flag-gated `bm_sv` / `bm_mi`.

## Module auto-discovery

`registry.discover_modules()` imports every submodule of `app.modules` and instantiates each concrete `DetectionModule` subclass
defined in it. A module declares its tier (`confidence`), `applies_to`, `flags`, optionally `client_scripts`, `page_snippets()`,
`router()`, `root_router()`, `handle_dynamic()`, the challenge-provider hooks, `pre_request()` and `after_score()`. The hooks
and their order are described in [CONTRACT.md](../CONTRACT.md) and [GUIDE.md](../GUIDE.md#6-add-a-new-case).

## Environment variables

`docker-compose.yml` sets only `REDIS_URL` (api) and `UPSTREAM` / `LISTEN` (edge); everything else has a default. Add variables
under the `api` service `environment:` to use them. An unset or invalid numeric value falls back to the default.

| variable | default | meaning |
|---|---|---|
| `REDIS_URL` | unset (in-memory store) | Redis connection for the api |
| `LAB_SECRET` | random per process | master secret for the sensor, pixel and inline-telemetry keys; set it to keep them valid across api restarts |
| `LAB_FLAG_<NAME>` | the flag's default | override a flag (`1`/`true`/`yes`/`on`) when no store value exists |
| `LAB_DELAY_SECONDS` / `LAB_SLOW_SECONDS` / `LAB_TARPIT_SECONDS` | 1.5 / 3.0 / 5.0 | initial `delay`, `slow` and `tarpit` durations in the policy |
| `LAB_CHLG_DURATION` / `LAB_CHALLENGE_INTERVAL` | 2.0 / 600 | initial `chlg_duration` (max 120 s) and `challenge_interval` (1-7200 s) |
| `LAB_RATE_BURST_WINDOW` / `LAB_RATE_BURST_THRESHOLD` / `LAB_RATE_AVG_THRESHOLD` | 5 / 20 / 2 | burst window (1-5 s), burst and 2-minute average hits per second |
| `LAB_RATE_IDENTIFIER` | `ip` | `ip`, `ip-useragent` or `tls-fingerprint` |
| `LAB_PENALTY_BOX_SECONDS` | 600 | penalty box duration (clamped to 24 h; below 600 s is a lab convenience) |
| `LAB_BAD_CIDRS` | unset | comma-separated customer IP list: WARN 40 |
| `LAB_ABCK_REQUIRED_POSTS` | 3 | sensor posts needed in `abck_n_posts` mode |
| `LAB_APP_KEY` | documented constant | HMAC key of the native-app header |
| `LAB_BOT_KEY_SEED` / `LAB_KNOWN_BOT_RANGES` | random / unset | Web Bot Auth key seed (hex); extra source ranges (`name=cidr,cidr;...`) |
| `LAB_CLUSTER_MIN_IPS` / `LAB_CLUSTER_WINDOW_MIN` / `LAB_CLUSTER_BAD_RATE` | 3 / 10 / 60 | `botnet_cluster` thresholds |
| `LAB_VP_ADMIT_PERCENT` / `LAB_VP_WAIT_SECONDS` / `LAB_VP_LABEL` | 50 / 30 / `lab` | waiting-room admission percent, wait, cookie label |
| edge: `LISTEN` / `UPSTREAM` / `CERT_FILE` / `KEY_FILE` | `:8443` / `http://api:8000` / mounted cert paths | see `edge/README.md` |
| clients: `LAB_URL` / `CONTROL_URL` | `https://localhost:8443` / `http://localhost:3000` | where `clients.*` send traffic and read reports |

**Removed:** `LAB_RATE_FAIL` and `LAB_RATE_BLOCK` (the v1 fixed 10 s windows that counted only scored requests) no longer exist;
`ip_reputation` uses the burst and average controls above. Other constants (`BLOCK_THRESHOLD` in `contract.py`,
`DEFAULT_DIFFICULTY` in `sec_cpt_challenge.py`, penalty weights in `behavioral.py`) live in the modules; the segment bands, actions and
action parameters live in the policy document (`GET/PUT/DELETE /api/policy`).
