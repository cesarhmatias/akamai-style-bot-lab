# Internal build contract (shared by all components)

Source of truth for interfaces: `api/app/contract.py`. This file pins topology, routes, slugs, hooks and cross-module state so
components can be built independently. It is kept in sync with the code; the request lifecycle is described in more prose in
`docs/architecture.md`, the scope in `docs/KNOWN_GAPS.md`.

## Topology
- `edge` (Go, `edge/`): TLS (self-signed, generated at startup) on `:8443`, ALPN h2 + http/1.1.
  Computes JA3/JA4/H2 fingerprint + raw header order, injects `x-ja3`, `x-ja3-hash`, `x-ja4`, `x-ja3-grease`, `x-tls-exts`,
  `x-tls-groups`, `x-tls-sigalgs`, `x-tls-alpn`, `x-tls-alps`, `x-tls-conn`, `x-h2-fingerprint`, `x-h2-headers-priority`,
  `x-header-order`, `x-http-proto`, `x-client-ip`, strips any client-supplied copy of those names, proxies to `api:8000` (plain
  HTTP/1.1). `/edge -healthcheck` exits 0 if the listener answers. Host port 8443. Full list: `edge/README.md`.
- `api` (FastAPI, `api/`): port 8000, internal only (reachable from the dashboard via nginx).
- `dashboard` (static + nginx, `dashboard/`): host port 3000; nginx proxies `/api/*` and `/healthz` to `http://api:8000`.
  "Real browser" tests open `https://localhost:8443/...`.
- `redis`: session, score, policy and flag state. The API falls back to an in-memory store if `REDIS_URL` is unset.

## Case slugs (module `slug`, file `api/app/modules/<slug>.py`, doc `docs/cases/<slug>.md`)
Modules are auto-discovered: the registry imports every submodule of `app.modules` and instantiates each concrete
`DetectionModule` subclass. There is no central registry file to edit. `GET /api/modules` lists them with tier, `applies_to`,
flags and challenge providers; the README table lists every module with its tier and default.

| slug | category | tier | default | applies_to |
|---|---|---|---|---|
| tls_fingerprint | passive | high | on | page, protected |
| h2_fingerprint | passive | high | on | page, protected |
| header_order | passive | high | on | page, protected |
| version_consistency | passive | high | on | page, protected, transactional |
| known_bots | passive | medium | on | all four classes |
| tcp_fingerprint | passive | low | off (stub) | page, protected |
| ip_reputation | network | high | on | page, protected |
| botnet_cluster | network | low | off | page, protected |
| visitor_prioritization | network | low | off (gate) | none (gate only) |
| abck_cookie | cookie | medium | on | page, protected |
| sensor_data | js | medium | on | page, protected |
| js_integrity | js | high | on | page, protected, transactional |
| proof_of_work | js | medium | on | page, protected |
| pixel_challenge | js | medium | on | page, protected |
| sbsd_challenge | js | low | on (lab device) | page, protected |
| avf_stepup | js | medium | on | page, protected, transactional |
| inline_telemetry | js | high | on | transactional |
| native_app | js | medium | on | mobile |
| behavioral | behavioral | high | on | page, protected, transactional |
| session_validation | behavioral | medium | on | page, protected, transactional |
| interactive_challenge | behavioral | medium | on | none (explicit `/protected/<slug>` only) |
| account_protector | behavioral | medium | on | transactional |

## HTTP routes (API, as seen through the edge)
- `GET /protected/<slug>` evaluates ONLY that module (if enabled; if disabled there are no signals and the resource is served).
  `GET /protected/all` evaluates every enabled module whose `applies_to` contains `protected`.
- `GET /` (through the edge): the landing page, an HTML storefront that loads every enabled module's `client_scripts` and
  `page_snippets` (per-session sensor path, pixel value and script, inline-telemetry config, step-up script when armed, ...).
- `POST /api/login` and `POST /api/checkout` (JSON bodies; transactional) and `GET|POST /mobile/api/*` (mobile) are scored too.
- What a scored request answers is decided by the response policy, **not** by "score >= 50": the Bot Score selects a segment and
  the segment an action (`monitor`, `allow`, `deny`, `delay`, `slow`, `tarpit`, `serve_alternate`, `challenge`, `safeguard`).
  `deny` is 403 (an HTML `Access Denied` page with a `Reference #18...` for navigations, JSON for API callers); `challenge` is
  428 JSON or an interstitial page; `serve_alternate` is a 200 with wrong data and a canary. `ScoreReport.blocked` is true exactly
  for `deny`, `tarpit` and `challenge` (`contract.BLOCKING_ACTIONS`). `GET /protected/<slug>` bodies are
  `{"ok": bool, "case": slug, "report": ScoreReport}`. See `docs/cases/bot_score.md`.
- Every scored response carries the lab-only `X-Lab-Report-Id`; `GET /api/requests/{id}` returns the report. The harness judges a
  case from the case's own signal in that report, never from the HTTP status.
- Module routes: `/akam/<slug>/...` via `DetectionModule.router()`; site-root routes via `root_router()` (for example
  `/_sec/cp_challenge/...`, `/.well-known/http-message-signatures-directory`); any other unrouted GET/POST path goes through the
  catch-all (registered last) to each module's `handle_dynamic()`.
- Shared verify paths, owned by `main.py`: `POST /_sec/verify?provider=<p>` and `POST /_sec/cp_challenge/verify`, body a JSON
  object with `token` or `bm-verify` (400 `bad_request` otherwise, 400 `no_session` without `bm_sz`). The token goes to
  `verify_challenge` of each module that serves `<p>` (every challenge provider when `provider` is absent) until one claims it;
  a token nobody issued is 403 `unknown_or_replayed`.
- Control plane (dashboard and harness): `GET /api/modules`, `PUT /api/modules/{slug}` `{"enabled": bool}`,
  `GET|PUT|DELETE /api/policy` (PUT deep-merges a partial `{bands, actions, params}`; 422 on invalid), `GET /api/requests`
  (`limit`, `reference`, `canary`), `GET /api/requests/{id}`, `GET /api/reference/{ref}`, `GET /api/canary/{token}`,
  `GET /api/flags`, `PUT /api/flags/{name}` `{"value": bool}`, `GET /api/feed` (SSE, event `report`, data = ScoreReport JSON),
  `POST /api/reset` (clears the store and the feed; keeps toggles, flags and the policy), `GET /healthz`.
  Control-plane and `/akam/*` requests are NOT scored and NOT in the feed.
- Clients may send `X-Lab-Client: <name>` (naive|curl_cffi|playwright|browser|anything) -> `ScoreReport.client_label`.

## Session & shared state (store keys)
The full key table (writer, meaning, TTL) is in `docs/architecture.md`. The cross-module ones:
- `bm_sz` cookie: the session id, minted by `main.session_id_for` before evaluation when absent
  (`HEX32~YAAQ<base64>~<int>~<int>`, about 4 h). `ctx.session_id` = the full cookie value.
- `ak_bmsc` (opaque blob) and `_abck` (`HEX32~<flag>~YAAQ<base64>~-1~-1~-1`) are issued with it by `main.finalize_cookies`.
  The server-side truth for `_abck` is store key `abck:{sid}` = `"validated"`; the cookie's flag field is not trusted (only the LOW
  flag `abck_tilde0_mode` flips it to `~0~`). Helpers in `app/session.py`: `mark_abck_validated`, `is_abck_validated`,
  `abck_cookie_value`, `cookie_attrs`, `extra_cookies`, `fingerprint_binding`.
- `sensor:{sid}` (latest accepted sensor JSON, read by `behavioral`, `js_integrity`, `version_consistency`), `sensor:n:{sid}`,
  `sensor:integrity:{sid}`; `pixel:{sid}`, `pow:{sid}`, `sbsd:{sid}` solved markers; `inline:last:{sid}`.
- Policy: `policy:doc`; flags: `flag:{name}`; toggles: `toggle:{slug}`.
- Rate and reputation: `rate:{cid}:s:{sec}`, `rate:{cid}:b:{bucket}`, `penalty:{cid}`, `repcat:{CAT}:{ip}`.

## Expected matrix (target behaviour)
The v1 table that lived here is gone: the matrix has 19+ cases judged per cell as `pass` / `warn` / `fail` from the case's signal.
The source of truth is `clients/expected_matrix.json`; the rendered result, the reason behind each cell and how a failing client
would pass are in `RESULTS.md` (regenerate with `python -m clients.run_matrix`; CI fails on drift).

## Conventions
Python 3.12, fully typed, ruff (config in root `pyproject.toml`), mypy, pytest under `api/tests/` (`test_<slug>.py` per module,
coverage `fail_under = 90`). Conventional Commits; commit only your own files (`git add <your paths>`; commit with
`git commit -m ... -- <paths>`; if `.git/index.lock` exists, wait a second and retry).

## Client scripts
A module that needs JS in the browser declares an OPTIONAL class attribute `client_scripts: ClassVar[list[str]] = []`: paths
relative to `/akam/<slug>/` (for example `["pow.js"]` -> `/akam/proof_of_work/pow.js`). The landing page and the lab's HTML
interstitials include one `<script src>` per entry for every enabled module. Prefer `page_snippets()` for per-session markup.

## v2 — audit remediation (2026-10)

Spec: `docs/research/akamai-audit-2026-10.md`. Types in `api/app/contract.py`.

### Confidence gating (governs how every change ships)
| Tier | Source in report §3.1 | How it ships |
|---|---|---|
| `high` | High | Real lab behaviour, on by default |
| `medium` | Medium | Implemented; docs label it an approximation and cite the tier |
| `low` | Low (vendor-only) | Behind a `FlagSpec` (default **off**); docs say "unverified, vendor-sourced" |
| `lab` | — | Lab-only teaching device with no known Akamai analogue; say so |

Never copy proprietary Akamai script code, keys or real encodings. Artifact *shapes* (cookie names, path formats, field layout)
are fine; encodings are lab-defined. The flags and their tiers are listed in the README and returned by `GET /api/flags`.

### Hooks available to modules
- `confidence: ClassVar[Confidence]` — tier of the module as a whole.
- `flags: ClassVar[list[FlagSpec]]` — declared flags; read with `ctx.flag("name")`. Resolution: store `flag:{name}` -> env
  `LAB_FLAG_<NAME>` -> default. `GET/PUT /api/flags[/{name}]`.
- `applies_to: ClassVar[frozenset[EndpointClass]]` — default `{page, protected}`. Classes: `page` (`GET /`), `protected`
  (`/protected/*`), `transactional` (`POST /api/login`, `POST /api/checkout`), `mobile` (`/mobile/api/*`). `/protected/<slug>`
  always runs that module.
- `async page_snippets(ctx) -> list[str]` — HTML injected before `</body>` of every lab HTML page (enabled modules only).
- `async handle_dynamic(request, ctx) -> Response | None` — claim an unrouted same-origin GET/POST path (catch-all route,
  registered last in `main.py`; called in module slug order, first non-None wins).
- `root_router() -> APIRouter | None` — routes mounted at the site root, before the catch-all.
- `challenge_providers: ClassVar[frozenset[str]]`, `async issue_challenge(request, ctx, provider, *, html) -> Response | None`,
  `async challenge_satisfied(ctx, provider=None) -> bool` — challenge actions: the policy's `challenge_provider` picks the enabled
  module that lists it; `html` is true for navigations (interstitial) and false for API callers (428 JSON); a satisfied
  challenge downgrades `challenge` to `monitor`. A module that does not serve a provider must return False for it.
- `async verify_challenge(request, token, body, provider) -> Response | None` (v2.2) — redeem a token posted to the shared
  verify paths. Return a `Response` when this module issued the token, `None` when it did not.
- `async after_score(ctx, report) -> None` — called on every enabled module after the engine decided segment and action;
  learn from the outcome or arm follow-up work. Must not raise.
- `async pre_request(request, ctx) -> Response | None` — access gate run before scoring on page and protected requests; return a
  `Response` to short-circuit.
- `ctx.session_id` is always set (`bm_sz` minted before evaluation); `ctx.body`, `ctx.body_sha256`, `ctx.query`,
  `ctx.endpoint_class`, `ctx.flags`.
- Every scored response has `X-Lab-Report-Id`; `GET /api/requests/{id}` returns the report.

### Request order (what runs when)
`context_for` (mint `bm_sz`, read body, resolve flags) -> `pre_request` gates -> modules (`evaluate`, concurrently) -> aggregate ->
segment (per telemetry type) -> action (policy; forced deny on `block`; challenge downgrade or safeguard; reference or canary) ->
`ScoreReport` recorded and published -> `after_score` hooks -> enforcement (`X-Lab-Report-Id`, cookies).

### ScoreReport v2 fields
`endpoint_class`, `telemetry_type` (standard|inline|native), `segment`, `action` (`Action` enum), `canary`, `reference`, `layers`
(cross-layer version agreement), `origin_headers` (Akamai-Bot / Akamai-User-Risk style verdict headers, recorded and never
forwarded), `is_human` (score 0), `is_safeguard`, `challenge_provider`. Conventional keys of `Signal.details` the engine reads:
`telemetry_type`, `layers`, `bot_name`, `bot_category`, `user_risk`.

### Environment variables
Listed with defaults in `docs/architecture.md`. `LAB_RATE_FAIL` and `LAB_RATE_BLOCK` (v1 fixed-window rate controls) were
removed; `ip_reputation` reads `LAB_RATE_BURST_WINDOW`, `LAB_RATE_BURST_THRESHOLD`, `LAB_RATE_AVG_THRESHOLD`,
`LAB_RATE_IDENTIFIER` and `LAB_PENALTY_BOX_SECONDS`.

### File ownership during the remediation fan-out (HISTORICAL)
This table records how the 2026-10 remediation work was split between parallel agents. It is **historical**: the fan-out is
finished, the table no longer constrains anyone, and ownership today is the normal repository workflow.

| Owner | Files |
|---|---|
| passive agent | `edge/**`, modules `tls_fingerprint`, `h2_fingerprint`, `header_order`, `ip_reputation`, new passive modules (`version_consistency`, `known_bots`, `botnet_cluster`, `tcp_fingerprint`) |
| client-side agent | `api/app/session.py`, `api/app/static/**`, modules `abck_cookie`, `sensor_data`, `pixel_challenge`, `behavioral`, new `js_integrity`, `inline_telemetry`, `session_validation`, `native_app` |
| response agent | `api/app/contract.py`, `engine.py`, `main.py`, `registry.py`, `store.py`, modules `proof_of_work`, `sbsd_challenge`, new `account_protector`, `visitor_prioritization`, `avf_stepup`, `interactive_challenge`; Bot Score segments, actions, deny pages, origin headers |

Tests: `api/tests/test_<slug>.py` per module; shared fixtures live in `conftest.py`, so add helpers in your own test files.
