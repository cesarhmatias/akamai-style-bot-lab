# Bot Score, segments and response actions

Not a detection module: this is the engine and response layer that turns every module's signal into one score, a segment
and an action. Code: `api/app/engine.py` (aggregation and decision), `api/app/policy.py` (bands, actions, parameters),
`api/app/responses.py` and `api/app/main.py` (enforcement). Default: always on. Tier: **HIGH** for the concept; the numbers
are called out below.

## What it is

Every enabled module contributes a signal. The engine combines them into **one 0-100 Bot Score**, buckets the score into a
**response segment** (cautious, strict, aggressive; `human` when the score is 0) using bands that depend on the telemetry
type, and maps (endpoint class, segment) to an **action**. A 403 is only one possible outcome: a response can be delayed,
slowed, held, silently degraded or challenged.

## How real Akamai uses it

(Report §2.1, [P].) The Bot Manager brief's UI example sets, for standard telemetry, Cautious 1-20 (Monitor), Strict 21-60
(Crypto Challenge) and Aggressive 61-100 (Deny); for inline telemetry 1-28, 29-80 and 81-100; and a separate row for native
mobile apps. EdgeWorkers exposes `isHuman()` ("haven't triggered any detections, resulting in a bot score of zero") and
`isSafeguardResponse()` ("set aside by Bot Manager for special handling to prevent a human user from getting endlessly
trapped by bot detections") in the `onBotSegmentAvailable` handler (since 2025-12-05). Actions include monitor, allow, deny,
delay, slow, tarpit, serve alternate content, challenge and conditional actions. Often nothing obvious shows on the wire:
responses get slower, content is subtly different, or a challenge appears. Akamai does not publish how it combines
detections.

## Confidence

| Piece | Tier |
|---|---|
| One 0-100 score, segments, non-block actions, `isHuman`, `isSafeguardResponse` (concept) | HIGH |
| `standard` and `inline` band numbers | HIGH as the report's UI example values, not necessarily Akamai's defaults |
| `native` bands 1-25 / 26-70 / 71-100 | LAB-chosen (the report only says native apps have their own row) |
| Segment-to-action mapping, delay/slow/tarpit durations, safeguard thresholds, aggregation formula | LAB defaults (editable) |
| Deny-page text and reference format | HIGH |
| `Server: AkamaiGHost` on denies | MEDIUM, flag `akamai_ghost_server_header` (default **on**; in a 2026 measurement 103 of 110 blocked Akamai sites showed no branding) |
| Origin verdict headers (`Akamai-Bot`, `Akamai-User-Risk`, JA4 header) | MEDIUM; the unclassified and human forms of `Akamai-Bot` are lab-defined |

There is no EdgeWorkers runtime; `isHuman` and `isSafeguardResponse` are reported as `ScoreReport.is_human` and
`is_safeguard`.

## How the lab simulates it

**Aggregation** (`engine.aggregate`): `score = min(100, round(max(scores) + 0.25 * sum(other scores)))`. The strongest signal
dominates; the rest add a quarter of their weight. On `/protected/<slug>` only that module runs, so the score is its own.
Score 0 means no detection fired (`is_human`).

**Telemetry type**: a signal's `details["telemetry_type"]` (`inline_telemetry` says `inline`, `native_app` says `native`), else
`native` for the mobile class, else `standard`.

**Bands** (inclusive; `GET /api/policy`, editable with `PUT /api/policy`):

| Telemetry type | cautious | strict | aggressive |
|---|---|---|---|
| standard | 1-20 | 21-60 | 61-100 |
| inline | 1-28 | 29-80 | 81-100 |
| native (LAB) | 1-25 | 26-70 | 71-100 |

**Per-endpoint policy** (lab defaults):

| Endpoint class | human | cautious | strict | aggressive |
|---|---|---|---|---|
| page (`GET /`) | allow | monitor | monitor | monitor |
| protected (`/protected/*`) | allow | monitor | challenge | deny |
| transactional (`POST /api/login`, `/api/checkout`) | allow | delay | serve_alternate | deny |
| mobile (`/mobile/api/*`) | allow | monitor | challenge | deny |

The landing page is always served so challenge scripts can load. A `block` verdict from any module forces `deny` on any
class. `ScoreReport.blocked` is true exactly when the action is `deny`, `tarpit` or `challenge`
(`contract.BLOCKING_ACTIONS`); delay, slow, serve_alternate, safeguard, monitor and allow answer with a normal 2xx.

**Actions** (parameters in the policy document, `POST /api/reset` keeps them):

| Action | What the lab does |
|---|---|
| `monitor` / `allow` | serve the real resource |
| `delay` | sleep `delay_seconds` (default 1.5, `LAB_DELAY_SECONDS`), then serve |
| `slow` | stream the body in `slow_chunks` (6) chunks over `slow_seconds` (default 3, `LAB_SLOW_SECONDS`) |
| `tarpit` | hold the connection `tarpit_seconds` (default 5, `LAB_TARPIT_SECONDS`), then an empty 403 |
| `serve_alternate` | HTTP 200 with subtly wrong data and a canary (below) |
| `challenge` | the policy's `challenge_provider` (`crypto` by default; the choices are `crypto`, `behavioral`, `adaptive`, `interactive` and `interstitial`): 428 JSON for XHR/API callers, an interstitial page for navigations; with no provider able to issue it, a 428 `no_challenge_provider` |
| `deny` | the deny page (below) |
| `safeguard` | let the session through under monitoring |

**Challenge handling**: if a module serving the requested provider reports the session already solved its challenge (valid
cookie and store state), the engine downgrades `challenge` to `monitor` instead of looping. The check is per provider: a
solved crypto challenge does not waive the tile game, and a solved interstitial satisfies only `interstitial`. Otherwise `decide_challenge` records the
challenge in a sliding window (`chlg:fail:{sid}`); after `safeguard_failures` (3) challenges inside
`safeguard_window_seconds` (600) with no solve, the next one becomes `safeguard` (`is_safeguard = true`, no provider, a pass
under monitoring for the same window, `safeguard:{sid}`), so a human is never trapped forever. A solve clears the counters.

**Deny page** (`responses.deny_html`): a 403 HTML page `Access Denied` / `You don't have permission to access "<url>" on this
server.` / `Reference #18.<8 hex>.<unix ts>.<7 hex>`, with an `errors.edgesuite.net/<reference>` line (text only; the lab
never contacts it) and HTML-entity encoding like Akamai's error pages. With the flag on it sends `Server: AkamaiGHost`. For
non-HTML callers a deny is a 403 JSON `{"ok": false, "case", "reference", "report"}`. The reference maps to the report:
`GET /api/reference/18.xxxxxxxx.<ts>.xxxxxxx` (a leading `Reference #` or `#` is accepted) or
`GET /api/requests?reference=...`; the dashboard links it.

**serve_alternate** (`responses.alt_*`): a 200 whose data is plausible but wrong. The product price is the real one times
`1.06 + (a % 15) / 100` and the stock is 1 or 2 (never the real 3); a checkout total is multiplied by `1.05 + (a % 10) / 100`
and its `order_id` gets a suffix; a login returns the canary as its `token`. A hidden `cnry-<12 hex>` canary is planted (a
hidden `<span data-ref>` in HTML, a `ref` field in JSON). The canary is recorded in `ScoreReport.canary` and `canary:{token}`
(24 h); `GET /api/canary/{token}` or `GET /api/requests?canary=...` reveals which request got it. Nothing in the body says the
client was classified.

**Origin verdict headers** (`ScoreReport.origin_headers`; the lab has no real origin behind the API, so they are recorded and
shown in the inspector's "Origin headers" tab, never forwarded): `Akamai-Bot` (`Akamai-Categorized Bot (<name>):<action>:<category>`
when `known_bots` classified the client, otherwise a lab-defined human or unclassified form), `Akamai-User-Risk` (from
`account_protector`) and `ja4-fingerprint` (the JA4, an example header name from Akamai's JA4 settings API).

**Where to read it**: every scored response carries `X-Lab-Report-Id`; `GET /api/requests/{id}` returns the `ScoreReport` with
`score`, `segment`, `action`, `blocked`, `telemetry_type`, `challenge_provider`, `is_human`, `is_safeguard`, `reference`,
`canary`, `layers`, `origin_headers` and every signal.

## How a scraper passes it

There is nothing to "pass" in aggregate: keep every detection below the `cautious` band (a score of 0 is `human`). To
notice silent degradation, compare the data against a reference and check for the canary: an HTTP 200 does not mean the real
resource was served. Challenges are answered per provider (see `sec_cpt_challenge`, `bm_verify_interstitial` and
`interactive_challenge`).

## Observed results

The harness judges each case from its signal, not from the action, but `RESULTS.md` records the action and segment the lab
chose for each request, for example: `tls_fingerprint` naive deny/aggressive (75), curl_cffi allow/human (0); `sec_cpt_challenge`
naive challenge/strict (45); `avf_stepup` naive challenge/strict (30) and curl_cffi monitor/strict (30, downgraded because it
held a valid `sec_cpt`); `inline_telemetry` Playwright deny/aggressive although its own signal passed, because other modules
fired on the same transactional request. Patchright's checkout and login are serve_alternate/strict (score 70 and 78): every
stealth check passes, but the landing page it reloads before them saw no pointer movement, so `behavioral` fails 70 and the
lab serves the canary with a 200. With a pointer path on every page view they were allow/human.

## Limits and caveats

- The aggregation formula, band numbers for `native`, durations and the segment-to-action mapping are lab defaults, not Akamai's.
- Tarpit and serve-alternate are hard to observe by design ([KNOWN_GAPS](../KNOWN_GAPS.md) item 8).
- `deny`, `tarpit` and `challenge` count as blocked; a scraper that only checks `status == 200` will misjudge `serve_alternate`.
