# Guide

Everything here runs on your own machine against your own server. Prerequisites: Docker with Compose v2, Python 3.12 (on
Debian/Ubuntu: `sudo apt install python3.12-venv`). Go is only needed to run the edge tests outside Docker. What the lab is
and is not (an educational simulation, not a replica of Akamai) is in the [README](README.md) and
[docs/KNOWN_GAPS.md](docs/KNOWN_GAPS.md).

## 1. Run the lab

```bash
docker compose up --build            # add -d to detach; first build takes a minute or two
# or, wait until all healthchecks pass:
docker compose up -d --build --wait --wait-timeout 300
```

Four containers start: `redis`, `api`, `edge` (host port 8443) and `dashboard` (host port 3000).
The edge generates a **self-signed certificate** at startup, so HTTPS clients on `https://localhost:8443` must
skip verification (`verify=False`, `curl -k`, Playwright `ignore_https_errors=True`) or you click through the
browser warning once. Stop with `docker compose down`.

Environment variables you may want to set under the `api` service in `docker-compose.yml` are listed in
[docs/architecture.md](docs/architecture.md#environment-variables).

## 2. Open the dashboard

http://localhost:3000 is a single page with:

- **Cases**: every module with its confidence tier and an on/off toggle (`PUT /api/modules/{slug}`).
- **Live feed** (SSE): every scored request with its score, segment and action, filterable by action. Select one to open
  the **request inspector**: headers, the fingerprint (JA3/JA4, HTTP/2 string, header order), cookies, the **origin
  headers** tab (`Akamai-Bot`, `Akamai-User-Risk`, `ja4-fingerprint`; recorded, never forwarded), the raw JSON, and every
  signal with its confidence. A deny shows its **Reference** and a serve-alternate shows its **canary**, each linked to
  its lookup endpoint.
- **Cross-layer agreement**: from `version_consistency`, whether TLS, headers and JavaScript describe the same Chrome
  release (AGREE or DISAGREE, with the per-layer values and the disagreements).
- **Browser vs scraper**: a per-case comparison of what each client label got.
- **Response policy**: the Bot Score bands per telemetry type, the segment-to-action mapping per endpoint class, and the
  parameters (delay, slow, tarpit, safeguard, challenge provider, `chlg_duration`, `challenge_interval`). It edits
  `GET/PUT/DELETE /api/policy`.
- **Feature flags**: every flag with its tier, default and current value (`GET /api/flags`, `PUT /api/flags/{name}`).

"Reset lab" clears sessions, reputation, profiles and the feed and keeps toggles, flags and the policy. You can also browse
the protected storefront at `https://localhost:8443/`.

## 3. Run the clients and the matrix

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev,clients]'                       # playwright and curl_cffi are pinned
.venv/bin/python -m playwright install --with-deps chromium     # Playwright client only
```

Run a single client (results go to a scratch folder so the committed `RESULTS.md` is not overwritten):

```bash
.venv/bin/python -m clients.run_matrix --clients naive     --no-diff --output /tmp/lab-out
.venv/bin/python -m clients.run_matrix --clients curl_cffi --no-diff --output /tmp/lab-out
.venv/bin/python -m clients.run_matrix --clients playwright --no-diff --output /tmp/lab-out
```

Run the whole matrix (all three clients, every case) and diff it against `clients/expected_matrix.json` (exit code 1 on
drift). With no `--output` it rewrites `RESULTS.md` and `results.json` in the current directory:

```bash
.venv/bin/python -m clients.run_matrix
.venv/bin/python -m clients.run_matrix --cases tls_fingerprint,sensor_data --output /tmp/lab-out
```

How the harness judges a cell: every scored response carries an `X-Lab-Report-Id` header; the runner fetches
`GET /api/requests/{id}` and reads **the case's own signal** in that report. It does **not** use the HTTP status, because
the lab answers `monitor`, `delay` and `serve_alternate` with 200 and a challenge with 428 or an HTML page. A cell is
**tri-state**:

| Cell | Meaning |
|---|---|
| ✅ `pass` | the case's verdict is `pass` or `skip` |
| ⚠️ `warn` | the verdict is `warn` |
| ❌ `fail` | the verdict is `fail` or `block`, or no report or signal was found |

`clients/expected_matrix.json` stores the expected class per cell; drift is any cell that differs. The runner pins the
module toggles it assumes, resets state between clients (they share one Docker bridge IP), and restores toggles, flags and
the challenge provider afterwards. It reads `CONTROL_URL` (default `http://localhost:3000`) and `LAB_URL` (default
`https://localhost:8443`). After an intended change, `--write-expected` (full runs only) rewrites the fixture from the run.
`RESULTS.md` also lists the reason behind every cell and how a failing client would pass.

## 4. Point your own scraper at the lab

- Base URL: `https://localhost:8443` (self-signed, disable verification).
- Optional label: send `X-Lab-Client: my-scraper`; it appears as `client_label` in reports and the dashboard.
- Keep a cookie jar. The lab issues `bm_sz` (session id), `ak_bmsc` and `_abck` on the first scored response.
- Targets: `GET /` (the landing page, which loads every module's scripts), `GET /protected/<case>` (evaluates one case),
  `GET /protected/all`, `POST /api/login` and `POST /api/checkout` (JSON bodies; transactional), `GET|POST /mobile/api/*`
  (mobile).
- Send `Accept: application/json` to get JSON; with `text/html` in `Accept` a deny is an HTML page and a challenge is an
  interstitial page.

### Reading the verdict when the response is 200, 428 or HTML

The HTTP status does not tell you whether you were detected. Use the report id, which is on **every** scored response:

```python
import requests as plain
from curl_cffi import requests

LAB, CONTROL = "https://localhost:8443", "http://localhost:3000"
s = requests.Session(impersonate="chrome131", verify=False)
s.headers["X-Lab-Client"] = "my-scraper"

s.get(f"{LAB}/", headers={"Accept": "text/html"})                       # navigate first: builds a page chain
r = s.get(f"{LAB}/protected/all", headers={"Accept": "application/json"})
rep = plain.get(f"{CONTROL}/api/requests/{r.headers['x-lab-report-id']}").json()
print(r.status_code, rep["score"], rep["segment"], rep["action"], rep["blocked"])
for sig in rep["signals"]:
    print(f"{sig['module']:22} {sig['verdict']:5} {sig['score']:3} {sig['reason']}")
```

Against a fresh lab this prints status 403, score 100, segment `aggressive`, action `deny`, passes `tls_fingerprint`,
`h2_fingerprint`, `header_order`, `version_consistency`, `session_validation` and `ip_reputation` and fails the JS-backed
cases, which is the curl_cffi column of `RESULTS.md`. `GET /api/requests?limit=5` lists the newest reports; the dashboard
feed streams the same `ScoreReport` JSON. Fields to read: `score`, `segment`, `action`, `blocked` (true for deny, tarpit
and challenge), `telemetry_type`, `challenge_provider`, `is_human`, `is_safeguard`, `reference`, `canary`, `layers`,
`origin_headers` and the per-module `signals`.

What each outcome looks like to your scraper:

| Action | What you receive |
|---|---|
| `monitor`, `allow` | the real resource, HTTP 200 |
| `delay`, `slow` | the real resource, late (a pause before the response, or a body streamed in chunks) |
| `tarpit` | an empty 403 after a hold |
| `serve_alternate` | HTTP 200 with plausible but **wrong** data and a hidden canary; nothing says you were classified |
| `challenge` | `428` JSON `{provider, token, ...}` for API callers, or an HTML interstitial (HTTP 200) for navigations |
| `deny` | `403` JSON with a `reference` for API callers, or an `Access Denied` HTML page for navigations |
| `safeguard` | the real resource: after 3 unsolved challenges in 600 s the session is let through under monitoring |

**Deny reference lookup.** The deny page ends with `Reference #18.<hex>.<unix ts>.<hex>` (HTML-entity encoded in the
source; use `html.unescape`). Map it to the full report (the reference below is an example; use the one from your own deny page):

```bash
curl -s 'localhost:3000/api/reference/18.55ae3fb2.1790997725.e4ef040'      # also accepts "Reference #18...."
curl -s 'localhost:3000/api/requests?reference=18.55ae3fb2.1790997725.e4ef040'
```

**Canary lookup.** A `serve_alternate` response carries a `cnry-<12 hex>` token (a hidden `<span data-ref>` in HTML, a `ref`
field in JSON). To see the behaviour, route the aggressive segment of protected resources to it, then request a failing case:

```bash
curl -s -X PUT localhost:3000/api/policy -H 'content-type: application/json' \
     -d '{"actions": {"protected": {"aggressive": "serve_alternate"}}}'
curl -s localhost:3000/api/canary/cnry-6b6f1d7f9406            # which request got that canary
curl -s 'localhost:3000/api/requests?canary=cnry-6b6f1d7f9406'
curl -s -X DELETE localhost:3000/api/policy                    # back to the defaults
```

To pass the rest of the cases follow each one's process in [docs/cases](docs/cases).

## 5. Read the scores

Every module returns a signal: `verdict` (`pass`, `warn`, `fail`, `block`, `skip`), `score` 0 (human) to 100 (bot), a
human-readable `reason` and a `details` dict.

    score = min(100, round(max(scores) + 0.25 * sum(other scores)))

The score selects a **segment** and the segment an **action**, both from the response policy
([docs/cases/bot_score.md](docs/cases/bot_score.md)):

| Telemetry type | cautious | strict | aggressive |
|---|---|---|---|
| standard | 1-20 | 21-60 | 61-100 |
| inline (login, checkout) | 1-28 | 29-80 | 81-100 |
| native (`/mobile/api/*`, lab-chosen) | 1-25 | 26-70 | 71-100 |

Score 0 is `human`. Default actions: protected `monitor` / `challenge` / `deny` (cautious / strict / aggressive);
transactional `delay` / `serve_alternate` / `deny`; mobile like protected; the landing page always `monitor`. A module
returning `block` forces `deny` whatever the score. `blocked` in a report is true only for `deny`, `tarpit` and `challenge`.

| verdict | meaning |
|---|---|
| `pass` | consistent with a real browser |
| `warn` | suspicious; adds score; module-specific (usually score 20-49) |
| `fail` | strongly bot-like |
| `block` | hard deny regardless of the total (forged `_abck`, request burst, replayed telemetry) |
| `skip` | not applicable (contributes 0) |

On `/protected/<case>` only that module runs, so the score is its own. Note that a lone WARN of 30 on a protected resource
already lands in the `strict` segment, which challenges. Where reasons and details come from: each module in
`api/app/modules/<slug>.py` builds them in `evaluate()`; fingerprint fields are in `report.fingerprint`, filled from the edge
headers. `docs/cases/<slug>.md` lists every threshold. A module error shows up as a `warn` with score 10 and
`details.error = true`.

## 6. Add a new case

1. Create `api/app/modules/<slug>.py` with a `DetectionModule` subclass (`api/app/contract.py`). It is auto-discovered; there
   is no registry to edit.

   ```python
   from typing import ClassVar

   from fastapi import APIRouter
   from app.contract import (
       Confidence, DetectionModule, EndpointClass, FlagSpec, RequestContext, Signal, Verdict,
   )

   class MyCase(DetectionModule):
       slug: ClassVar[str] = "my_case"
       title: ClassVar[str] = "My case"
       description: ClassVar[str] = "Requires the demo header."
       category: ClassVar[str] = "passive"          # passive | cookie | js | behavioral | network
       confidence: ClassVar[Confidence] = Confidence.MEDIUM
       applies_to: ClassVar[frozenset[EndpointClass]] = frozenset(
           {EndpointClass.PAGE, EndpointClass.PROTECTED}
       )
       flags: ClassVar[list[FlagSpec]] = [
           FlagSpec(name="my_case_strict", description="Fail instead of warn.",
                    confidence=Confidence.LOW),        # LOW flags default to off
       ]

       async def evaluate(self, ctx: RequestContext) -> Signal:
           if ctx.header("x-demo") == "1":
               return self.signal(Verdict.PASS, 0, "demo header present")
           if ctx.flag("my_case_strict"):
               return self.signal(Verdict.FAIL, 80, "demo header missing")
           return self.signal(Verdict.WARN, 30, "demo header missing (lenient)")

       def router(self) -> APIRouter:               # optional: mounted at /akam/my_case/
           r = APIRouter()

           @r.get("/ping")
           async def ping() -> dict[str, bool]:
               return {"ok": True}

           return r
   ```

   Use `ctx.store` for per-session or per-IP state (`get`, `set`, `incr`, `delete`) keyed by `ctx.session_id` (always set:
   the lab mints `bm_sz` before evaluation) or `ctx.client_ip`.

   **Hooks** (all optional except `evaluate`; defaults do nothing):

   | Hook or attribute | Use it to |
   |---|---|
   | `confidence` | declare the tier: `HIGH` (on, stated as fact), `MEDIUM` (on, document as an approximation), `LOW` (gate behind a flag, off), `LAB` (a lab-only device) |
   | `applies_to` | the endpoint classes `page`, `protected`, `transactional`, `mobile` where the module runs in "all enabled modules" (default page and protected). `/protected/<slug>` always runs it; an empty set means explicit only |
   | `flags` | `FlagSpec`s resolved as store key `flag:{name}`, then env `LAB_FLAG_<NAME>`, then the default; read with `ctx.flag(name)` |
   | `default_enabled` | `False` to ship the module off |
   | `client_scripts` | static script paths relative to `/akam/<slug>/`, injected into HTML pages |
   | `page_snippets(ctx)` | raw HTML injected before `</body>` of every lab page (per-session script paths, embedded values) |
   | `handle_dynamic(request, ctx)` | claim an unrouted same-origin GET or POST path (random script paths); return a `Response` or `None` |
   | `router()` / `root_router()` | routes under `/akam/<slug>/` / at the site root (for absolute vendor-style paths such as `/_sec/cp_challenge/...`) |
   | `challenge_providers`, `issue_challenge(request, ctx, provider, html=)`, `challenge_satisfied(ctx, provider)` | serve a challenge when the policy's `challenge_provider` names yours (428 JSON for XHR, a page for navigations); report that the session already solved it so the engine downgrades `challenge` to `monitor` instead of looping |
   | `verify_challenge(request, token, body, provider)` | redeem a token your module issued when it is posted to the shared `POST /_sec/verify?provider=<p>` route; return `None` for a token that is not yours |
   | `pre_request(request, ctx)` | an access gate that runs before scoring on page and protected requests (a waiting room); return a `Response` to short-circuit |
   | `after_score(ctx, report)` | learn from the final segment and action (profiles) or arm follow-up work (step-up collection); must not raise |

   Signals may add `details["telemetry_type"]` (`inline` or `native`) to select Bot Score bands, `details["layers"]` for the
   cross-layer panel, `details["bot_name"]` and `details["user_risk"]` for the origin headers. If a module serves a challenge
   provider, remember the policy validator only accepts the names in `CHALLENGE_PROVIDERS` (`api/app/policy.py`) as
   `challenge_provider` values.
2. Add `api/tests/test_<slug>.py` using the `make_ctx` / `memory_store` / `client` fixtures from `api/tests/conftest.py`
   (see `api/tests/test_abck_cookie.py` for a stateful module, `api/tests/test_tcp_fingerprint.py` for a minimal one).
   Coverage must stay at or above 90% (`fail_under`).
3. Add `docs/cases/<slug>.md` with the sections the other case docs use: What it is, How real Akamai uses it (cite the audit
   section and the source tier), Confidence (with flags), How the lab simulates it (exact checks, scores, thresholds, store
   keys), How a scraper passes it, Observed results, Limits and caveats. Every number must match the code. Tier rules:
   `HIGH` as lab behaviour, `MEDIUM` labelled an approximation, `LOW` labelled "unverified, vendor-sourced" and flag-gated.
4. Make the clients know about it: add a `Case` (name, module, endpoint class, summary) to the table in `clients/common.py`
   (the runner fails when `/api/modules` has a module that is neither a case nor listed in `EXCLUDED`), and add a row to
   `clients/expected_matrix.json` (`{"naive": "...", "curl_cffi": "...", "playwright": "..."}` with `pass`/`warn`/`fail`,
   judged from the case's signal in the report). If a client needs a new solver, extend it in `clients/`;
   `python -m clients.run_matrix --write-expected` rewrites the fixture from a full run.
5. Verify, then regenerate the results table:

   ```bash
   .venv/bin/ruff check . && .venv/bin/mypy && .venv/bin/pytest --cov
   docker compose up -d --build --wait
   .venv/bin/python -m clients.run_matrix     # rewrites RESULTS.md; fails on drift
   ```

   Also add the case to the tables in `README.md` and `CONTRACT.md`. CI runs the same checks.
