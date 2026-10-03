# Guide

Everything here runs on your own machine. Prerequisites: Docker with Compose v2, Python 3.12 (on
Debian/Ubuntu: `sudo apt install python3.12-venv`). Go is only needed to run the edge tests outside Docker.

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

## 2. Open the dashboard

http://localhost:3000 shows the live feed of scored requests (SSE), the score gauge, a request inspector
(fingerprints, headers, cookies, per-module signals) and a client comparison panel. Each module has an
on/off toggle. You can also browse the protected storefront at `https://localhost:8443/`.

## 3. Run the example clients

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev,clients]'
.venv/bin/python -m playwright install --with-deps chromium   # Playwright client only
```

Run a single client (results go to a scratch folder so the committed `RESULTS.md` is not overwritten):

```bash
.venv/bin/python -m clients.run_matrix --clients naive     --no-diff --output /tmp/lab-out
.venv/bin/python -m clients.run_matrix --clients curl_cffi --no-diff --output /tmp/lab-out
.venv/bin/python -m clients.run_matrix --clients playwright --no-diff --output /tmp/lab-out
```

Run the whole matrix (all three clients, every default-enabled case) and diff it against `clients/expected_matrix.json`
(exit code 1 on drift). With no `--output` it rewrites `RESULTS.md` and `results.json` in the current directory:

```bash
.venv/bin/python -m clients.run_matrix
.venv/bin/python -m clients.run_matrix --cases tls_fingerprint,sensor_data --output /tmp/lab-out
```

The runner enables all modules, resets state between clients, and reads the verdicts through the control plane
(`CONTROL_URL`, default `http://localhost:3000`; `LAB_URL`, default `https://localhost:8443`).
The Playwright client takes about 5 seconds.

## 4. Point your own scraper at the lab

- Base URL: `https://localhost:8443` (self-signed, disable verification).
- Optional label: send `X-Lab-Client: my-scraper`; it appears as `client_label` in reports and the dashboard.
- Keep a cookie jar. The lab issues `bm_sz` (session id), `ak_bmsc` and `_abck` on the first scored response.
- Targets: `GET /protected/<case>` evaluates one case; `GET /protected/all` evaluates all enabled modules.
  Send `Accept: application/json` (non-browser default is fine) to get the JSON report on a block; with a
  `text/html` Accept a block returns an HTML interstitial and you must read the verdict from the feed.
- Read the verdict from any of: the response (200 `{"ok": true, "report": ...}` or 403
  `{"ok": false, "report": ...}`), the dashboard feed, or `curl -s 'localhost:3000/api/requests?limit=5'`
  (newest first, same `ScoreReport` JSON).

Minimal example (verified against the running lab, prints one line per signal):

```python
from curl_cffi import requests

s = requests.Session(impersonate="chrome131", verify=False)
s.headers["X-Lab-Client"] = "my-scraper"
r = s.get("https://localhost:8443/protected/all", headers={"Accept": "application/json"})
rep = r.json()["report"]
print(r.status_code, rep["score"], rep["blocked"])
for sig in rep["signals"]:
    print(sig["module"], sig["verdict"], sig["score"], sig["reason"])
```

Against a fresh lab this prints status 403, score 100 and passes `tls_fingerprint`, `h2_fingerprint`,
`header_order` and `ip_reputation` while failing the JS-backed cases, which is exactly the curl_cffi column of
`RESULTS.md`. To pass the rest you must follow each case's process (see [docs/cases](docs/cases)).

## 5. Read the scores

Every module returns a signal: `verdict` (`pass`, `warn`, `fail`, `block`, `skip`), `score` 0 (human) to
100 (bot), a human-readable `reason` and a `details` dict.

    score   = min(100, round(max(scores) + 0.25 * sum(other scores)))
    blocked = score >= BLOCK_THRESHOLD (50)  or  any signal is "block"

| verdict | meaning |
|---|---|
| `pass` | consistent with a real browser |
| `warn` | suspicious; adds score; module-specific (usually score 20-49) |
| `fail` | strongly bot-like |
| `block` | hard block regardless of the total (forged `_abck`, request burst) |
| `skip` | not applicable (contributes 0) |

On `/protected/<case>` only that module runs, so the case passes iff its score is below 50 and its verdict
is not `block`. On `/protected/all` the aggregation above applies.

Where reasons and details come from: each module in `api/app/modules/<slug>.py` builds its `reason` and
`details` in `evaluate()`; fingerprint fields (`ja3`, `ja4`, `h2`, `header_order`, `proto`) are in
`report.fingerprint`, filled from the edge headers. `docs/cases/<slug>.md` lists every threshold for a case.
Module errors show up as a `warn` with score 10 and `details.error = true`.

## 6. Add a new case

1. Create `api/app/modules/<slug>.py` with a `DetectionModule` subclass. It is auto-discovered, there is no
   registry to edit.

   ```python
   from typing import ClassVar
   from app.contract import DetectionModule, RequestContext, Signal, Verdict

   class MyCase(DetectionModule):
       slug: ClassVar[str] = "my_case"
       title: ClassVar[str] = "My case"
       description: ClassVar[str] = "What it checks."
       category: ClassVar[str] = "passive"   # passive | cookie | js | behavioral | network
       client_scripts: ClassVar[list[str]] = []   # e.g. ["my.js"] -> /akam/my_case/my.js

       async def evaluate(self, ctx: RequestContext) -> Signal:
           if ctx.header("x-demo") == "1":
               return self.signal(Verdict.PASS, 0, "demo header present")
           return self.signal(Verdict.FAIL, 80, "demo header missing")

       # optional: def router(self) -> APIRouter  (mounted at /akam/my_case/)
   ```

   Use `ctx.store` for per-session/per-IP state (`get`, `set`, `incr`, `delete`) keyed by `ctx.session_id`
   or `ctx.client_ip`. Browser-side scripts are listed in `client_scripts` and served by your router; the
   landing page and 403 interstitial include them automatically.
2. Add `api/tests/test_<slug>.py` using the `make_ctx` / `memory_store` / `client` fixtures from
   `api/tests/conftest.py` (see `api/tests/test_abck_cookie.py`).
3. Add `docs/cases/<slug>.md` describing mechanism, thresholds, how a client passes, observed results.
4. Make the clients know about it: add a `Case` (slug, module, endpoint class) to the table in
   `clients/common.py` (the runner fails when `/api/modules` has a module without a case), and add a row to
   `clients/expected_matrix.json` (`{"naive": "...", "curl_cffi": "...", "playwright": "..."}` with
   `pass`/`warn`/`fail`, judged from the case's signal in the report). If a client needs a new solver, extend
   it in `clients/`; `python -m clients.run_matrix --write-expected` rewrites the fixture from a full run.
5. Verify, then regenerate the results table:

   ```bash
   .venv/bin/ruff check . && .venv/bin/mypy && .venv/bin/pytest --cov
   docker compose up -d --build --wait
   .venv/bin/python -m clients.run_matrix     # rewrites RESULTS.md; fails on drift
   ```

   Also add the case to the tables in `README.md`/`CONTRACT.md`. CI runs the same checks.
