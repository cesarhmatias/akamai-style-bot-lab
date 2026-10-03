# `proof_of_work`: `sec_cpt`-style challenge providers

Category: js · Module: `api/app/modules/proof_of_work.py` · Protected URL: `/protected/proof_of_work` · Default: on
· Module tier: **MEDIUM** (artifacts are approximations; the cookieless `bm-verify` interstitial is MEDIUM; the free-form `simple` variant and the hardened interstitial are LAB devices)

## What it is

A client that cannot execute JavaScript, store cookies and spend time is stopped by a challenge it must solve before it may
continue. The challenge is bound to the session (`bm_sz`), single use, and has a **minimum wall-clock duration**: a correct
answer that arrives before `chlg_duration` seconds have passed is rejected. Three providers exist (`crypto`, `behavioral`,
`adaptive`), selected by `challenge_provider` in the response policy.

## How real Akamai uses it

- Akamai's challenge-action API lists the challenge types `GOOGLE_RECAPTCHA`, `AKAMAI_WEB_CRYPTO` and
  `AKAMAI_MOBILE_CRYPTO`, with `challengeIntervalInSeconds` (1-7200), `cryptoChallengeDurationInSeconds` (up to 120),
  `allowFullCpuUtilization` and custom branding ([P], 2026-06-02, report §1.2 case 6). The Bot Manager brief describes
  "minimum-time-to-solve cryptographic puzzles" and a separate interstitial that enforces a time penalty on clients without
  cookies or JavaScript ([P], 10/2023).
- Observed artifacts ([S]/[V]): scripts under `/_sec/cp_challenge/` (`sec-cpt-2.8.js` on a retail site, 2020); a 428
  Precondition Required JSON body for API calls, or an HTML page with an iframe `sec-cpt-if` carrying `provider`, a base64
  `challenge` JSON (`token`, `nonce`, `difficulty`, `timestamp`, `timeout`, `chlg_duration`, plus `count` for adaptive) and
  `data-duration`; verification at `/_sec/verify?provider=crypto|adaptive` or `/_sec/cp_challenge/verify`; a solved
  challenge leaves a `sec_cpt` cookie containing `~3~`. Providers: `crypto` (proof of work plus mandatory wait),
  `behavioral` (sensor posts) and `adaptive` (both).
- The puzzle algorithm, field values and cookie value are lab-defined; none of this is Akamai's encoding.

## Confidence

| Sub-feature | Tier |
|---|---|
| Challenge types, `chlg_duration` minimum wait, `challengeInterval`, interstitial with time penalty (concept) | HIGH (Akamai API 2026 and brief 2023) |
| 428 JSON, `sec-cpt-if` iframe, `/_sec/` verify paths, providers, `~3~` cookie | MEDIUM (approximation: vendor docs, a 2020 sandbox capture, a 2026 PR) |
| Free-form `a op b op c` arithmetic (`variant=simple`) | LAB: a teaching device kept for the harness |
| Cookieless `bm-verify` interstitial (arithmetic `pow`, `/_sec/verify?provider=interstitial`, cookies on success) | MEDIUM (approximation; see the interstitial section) |
| JSON `location` in the interstitial verify response | LOW, flag `pow_interstitial_location` (off): unverified; same-origin only |
| Meta-refresh path for clients without JavaScript (one navigation per single-use token, after 5 s) | MEDIUM (markup and the one-shot refetch are observed; that the wait is enforced server-side is an inference from the brief's "time penalty") |
| Randomized interstitial shape | LAB, flag `pow_interstitial_hardened` (off) |
| Cookieless gate on first visits, cleared by server-side proof only | MEDIUM, flag `pow_cookieless_gate` (off, because it changes every client's first visit) |

Flags: `pow_cookieless_gate`, `pow_interstitial_location` and `pow_interstitial_hardened`, all default off. Whether verify
returns 428 vs 200 and the `chlg_duration` values on real sites are unverified ([KNOWN_GAPS](../KNOWN_GAPS.md) item 5).

## How the lab simulates it

Settings live in the policy document (`GET/PUT /api/policy`): `chlg_duration` (default 2 s via `LAB_CHLG_DURATION`, maximum
120), `challenge_interval` (default 600 s via `LAB_CHALLENGE_INTERVAL`, range 1-7200), `challenge_timeout` (60 s to submit)
and `adaptive_count` (3). The puzzle difficulty is the constant 4.

- **`crypto`**: find `counter` with `sha256(nonce + str(counter))` starting with `difficulty` hex zeros, then wait until
  `chlg_duration` seconds after issue.
- **`adaptive`**: `count` solutions (sub-nonce `nonce.i`, difficulty lowered by one to 3) **and** at least one sensor post
  **and** the wait.
- **`behavioral`**: nothing to compute; requires a sensor post (`sensor:n:{sid}` or `sensor:{sid}`) and the wait. The
  interstitial page loads the other modules' scripts so the sensor can run.
- **Delivery**: with `Accept: application/json` (XHR/API) the challenge answers **428** JSON
  `{provider, token, nonce, difficulty, timestamp, timeout, chlg_duration, ...}`; for navigations it answers an HTML page with
  `<iframe id="sec-cpt-if" provider challenge="<base64 JSON>" data-duration src="/_sec/cp_challenge/message.htm?provider=...">`
  and the lab-written solver `/_sec/cp_challenge/sec-cpt-1.0.js`, which reloads after a solve.
- **Verify**: `POST /_sec/verify?provider=<p>` or `POST /_sec/cp_challenge/verify` (mounted by `root_router`), plus the legacy lab
  routes `GET /akam/proof_of_work/challenge?variant=hard|simple&provider=...`, `POST /akam/proof_of_work/verify` and
  `GET /akam/proof_of_work/pow.js` (same enforcement). Body `{"token", "answer"|"answers"}`. The challenge (`pow:ch:{token}`) is
  consumed even on failure. Errors (403): `unknown_or_replayed`, `wrong_session`, `wrong_provider`, `expired`, `bad_answer`,
  `wrong_answer`, `too_early` (with `retry_after`), `no_sensor`.
- **Success**: sets the `sec_cpt` cookie `<32 hex>~3~<unix ts>` and the store record `pow:{sid}` (3600 s), and clears the
  safeguard failure counter.
- **Scoring** (`evaluate`):

  | State | Verdict | Score |
  |---|---|---|
  | solved, `sec_cpt` matches the stored cookie and is inside the interval | pass | 0 |
  | `sec_cpt` forged or not the one issued | fail | 80 |
  | solved but the cookie was not presented | fail | 45 |
  | interval elapsed (`rechallenge`) | fail | 45 |
  | only the cookieless interstitial or the free-form `simple` variant solved | warn | 20 |
  | nothing solved | fail | 45 |

  45 lands in the `strict` segment for standard telemetry, so a protected request is challenged (428 or iframe) rather than
  denied.
- **Proactive solver** (LAB convenience): `pow.js`, included on the landing page, runs the `crypto` flow in the background so a
  real browser already holds a valid `sec_cpt` when it reaches a protected resource. Akamai does not do this; it keeps the
  harness's browser case meaningful.
- **`simple` (LAB)**: `GET /akam/proof_of_work/challenge?variant=simple` returns an expression `a op b op c` (numbers 2-99,
  `+ - *`, normal precedence, evaluated server-side without `eval`). Solving it alone only WARNs 20 (`pow:simple:{sid}`).

## How a scraper passes it

Read the challenge (the 428 JSON, or the iframe attributes), solve, **wait `chlg_duration` seconds** after the issue time,
`POST /_sec/verify?provider=<p>` with `{"token", "answer"|"answers"}`, and keep the `sec_cpt` cookie. A pure-HTTP client can
do all of this after sleeping, which is the intended lesson: the wait costs time, not identity. Re-solve after
`challenge_interval` seconds.

## Observed results

| Client | Cell | Verdict and reason |
|---|---|---|
| naive | fail | fail 45, "no proof of work solved for this session" (challenge/strict) |
| curl_cffi | pass | pass 0, "proof of work solved, sec_cpt cookie valid" (hard proof of work over HTTP with the minimum wait, then verify) |
| Playwright | pass | pass 0, same reason (the landing page's proactive solver) |

The interstitial rows (`pow_interstitial`, `pow_interstitial_hardened`) are covered in the section below.

## Limits and caveats

- Difficulty and wait are lab constants and settings; the legacy `/akam/proof_of_work/` routes exist for the harness clients.
- The proactive solver and the `simple` variant are lab devices with no Akamai counterpart.
- See `interactive_challenge` for the tile game that shares the engine's "already solved" downgrade.

## Cookieless `bm-verify` interstitial

### What it models

The Bot Manager brief describes an interstitial challenge that "requires clients to prove they support storing cookies and
executing JavaScript" ([P], 10/2023). The corrected audit (report §1.2 case 6, correction of 2026-10-02) found two independent
2026 sources that describe the same artifact, so the lab's arithmetic page is **not** a lab-only invention and must not be
deleted on that basis ([S]: the bershka-scraper README, measured 2026-09-19 to 09-22; sugarplum issue #172 and PR #177,
2026-09-27):

- a cookieless client gets HTTP 200 (about 2.1-2.4 KB) with a `bm-verify` token and one line of arithmetic, for example
  `var i = 1789910678; var j = i + Number("3886" + "11036");`;
- the page's script POSTs `{"bm-verify": token, "pow": i + 388611036}` to `/_sec/verify?provider=interstitial` and reloads;
- the page itself sets no Akamai cookie (only the site's own session cookies); the verify response sets `_abck`, `bm_sz` and
  `ak_bmsc`, and the cleared session kept getting the real page (five further requests);
- the page also carries `<meta http-equiv="refresh" content="5; URL='<url>&bm-verify=AAQ…'">`: refetching the URL with that
  single-use token returned the real page, with no JavaScript and no cookies, and a second interstitial was final.

Tier **MEDIUM** (concept [P]; artifacts from two independent secondary sources, plus an unpublished observation from the
lab owner's own HAR-derived client that matches the same shape). Akamai's real page wording and the cookie-issuing step are
approximated. A JSON `location` in the verify reply is **LOW**: only that unpublished client tolerates one; the published
sources show a reload or a `<meta http-equiv="refresh">` carrying a single-use token ([KNOWN_GAPS](../KNOWN_GAPS.md), section 4).

### How the lab simulates it

- **Page**: `interstitial` provider (or the gate below) answers an HTML page, HTTP 200, titled "Checking your browser", whose
  inline script computes the arithmetic and POSTs the result. For XHR the provider answers a 428 JSON carrying the same
  `bm-verify`, `expression` and `hardened` fields. The page is lab-written markup, not Akamai's.
- **The arithmetic is data**: the basic form is `var i = <issue time>; var j = i + Number("<4 digits>" + "<5 digits>");`,
  the observed shape. The observed `i`, 1789910678, is 2026-09-20 13:24 UTC, inside the capture window, so the lab reads it
  as the issuing Unix time (an inference). The observed answer, 2,178,521,714, is above 2³¹−1, and with a current clock the
  lab's answer often is too, which overflows a 32-bit signed integer. The server stores the spec (`i` and the digit
  parts) with the challenge and computes the expected `pow = i + int(parts)` from it, never from the page text and never
  with `eval`.
- **Token**: `bm-verify` is the challenge token, `AAQ` (the observed prefix) plus random lab data: single use (consumed even
  on failure), bound to `bm_sz`, valid for
  `challenge_timeout` (60 s). Failures are the other variants' reasons: `unknown_or_replayed`, `wrong_session`, `expired`,
  `wrong_provider`, `bad_answer`, `wrong_answer`. There is no minimum wait for this variant (the `chlg_duration` wait applies
  to the hard proof of work only).
- **Verify routes**: `POST /_sec/verify?provider=interstitial` (the vendor-style absolute path, mounted by `root_router`, the
  same path the public sources show and the one `crypto` and `adaptive` already use) and the lab alias
  `POST /akam/proof_of_work/interstitial/verify`. The alias exists because every module's own routes live under
  `/akam/<slug>/` (as do the legacy `challenge`, `verify` and `pow.js` routes and the on-demand page below), so lab and
  harness clients get a namespaced path with identical enforcement (both call the same `_verify`). Body
  `{"bm-verify": token, "pow": int}`.
- **On success**: `pow:interstitial:{sid}` is stored (3600 s) and the lab issues or refreshes `bm_sz`, `ak_bmsc` and `_abck`
  through its own cookie issuance (`main.finalize_cookies`). It does **not** set `sec_cpt` and does **not** mark `_abck`
  validated (that still needs the sensor flow). Approximation: the lab already hands those three cookies out with the page,
  because it binds the token to `bm_sz`; in the capture they arrive only with the verify response. Cookie presence
  therefore proves nothing in the lab, and the gate below checks server-side state.
- **On-demand page**: `GET /akam/proof_of_work/interstitial?return_to=<path>` serves the page without waiting for a policy
  decision (used by the harness). The legacy `GET /akam/proof_of_work/challenge?variant=interstitial` returns the same
  challenge as JSON.
- **After the verify**: the page reloads, as observed. The on-demand route's page goes to its `return_to` (default `/`)
  instead, because reloading that route would only issue a fresh interstitial.
- **`location` (flag `pow_interstitial_location`, LOW, default off)**: with the flag on, the verify reply carries the path of the
  request that was challenged, and only when `safe_location` accepts it: a plain absolute path, nothing with a scheme or
  netloc, no `//host`, no backslash, no control characters. Anything else is dropped, so a crafted `return_to` cannot turn the
  page into an open redirect, and the page script applies the same check before `location.replace(...)`. No published
  source shows this field, so it is off by default and clients must not depend on it.
- **Gate** (flag `pow_cookieless_gate`, MEDIUM, default **off**): a `pre_request` hook that serves this page to a GET navigation
  (`Accept` contains `text/html`) until the session has server-side proof: a solved interstitial (`pow:interstitial:{sid}`),
  a valid `sec_cpt`, or an `_abck` the sensor flow validated. A reload with the cookies the page handed out is not enough;
  before 2026-10-03 it was, which let any client with a cookie jar skip the page. The flag is off because it changes every
  client's first visit.
- **No-JavaScript path**: the page's meta refresh re-requests the URL with `bm-verify=<token>` after 5 seconds. A gated
  navigation carrying an unused interstitial token at least 5 seconds old passes once; an earlier one is served the page
  again and keeps the token. The token is then consumed and nothing is cleared, so the next navigation gets a new
  interstitial. A request that sends a `bm_sz` must send the session the token was issued for; one without cookies is
  accepted, like the observed refetch. That Akamai enforces the wait server-side is an inference from the brief ("Bot
  Manager enforces a time penalty").
- **Hardened variant** (flag `pow_interstitial_hardened`, **LAB**, default off): randomizes the arithmetic shape per issuance
  (identifier names, two to four concatenated string parts, operand order, whitespace, quote style, `Number(...)` /
  `parseInt(..., 10)` / unary plus, a decimal or hex `i`, `var` or `let`, an optional decoy declaration), so a fixed regex such
  as `var\s+j\s*=\s*i\s*\+\s*Number\("(\d+)"\s*\+\s*"(\d+)"\)` stops matching and only a client that interprets the
  script answers correctly. It is a lab device, not an Akamai feature, and a determined solver can still interpret the script.
- **Scoring and why solving it only WARNs**: a fixed regex solves the basic page without running any JavaScript, so a solved
  interstitial is weak evidence: **WARN 20** ("only the basic arithmetic interstitial was solved (a regex can do that)"),
  never PASS. 20 is the top of the cautious band for every telemetry type, so the default policy monitors the session and
  serves the protected page, as the bershka capture shows for a cleared session. (It was WARN 30 until 2026-10-03, which put a
  cleared session in the strict band and challenged it again, unlike the captures.) Precedence is hard proof of work
  (pass 0), then interstitial or `simple` (warn 20), then nothing (fail 45). Other modules still score the session: on a
  page that runs every module, a regex-only client is usually stopped by the sensor and telemetry checks instead.
- **Provider scoping**: the engine now asks `challenge_satisfied(ctx, provider)`. This module vouches only for providers it
  serves, and a solved interstitial satisfies only the `interstitial` provider (a valid `sec_cpt` satisfies any provider this
  module serves). A crypto `sec_cpt` no longer waives another module's challenge, for example the tile game. `interstitial` is
  an accepted `challenge_provider` value in the policy.

### How a scraper passes it

Parse the token and the two statements from the page, compute `i + int(A + B)`, `POST {"bm-verify", "pow"}` to
`/_sec/verify?provider=interstitial` with the same cookie jar, request the page again (or follow a same-origin `location` if
the LOW flag adds one), and keep the cookies. Regexes are enough for the basic page and give WARN 20 at best; the hardened
page needs a JavaScript engine or a robust JS parser. Only the hard proof of work reaches PASS. Without JavaScript, follow
the meta refresh after 5 seconds: one page, nothing cleared.

### Observed results

From `RESULTS.md`. The runner turns `pow_cookieless_gate` on for both rows and `pow_interstitial_hardened` on
for the second, in a fresh session per client, and judges the `proof_of_work` signal after the attempt.

| Row | naive | curl_cffi (regexes only) | Playwright |
|---|---|---|---|
| `pow_interstitial` | fail 45, "no proof of work solved for this session" (not attempted; its `Accept: */*` requests are not gated) | **warn 20**, monitor/cautious, "only the basic arithmetic interstitial was solved (a regex can do that)"; verify accepted, reloaded | **warn 20**, monitor/cautious, same reason; the page's own script ran and verify was accepted |
| `pow_interstitial_hardened` | fail 45 (not attempted) | **not scored**: the regexes did not match the hardened script, so it stopped, and the gate served the interstitial again | **warn 20**, same reason as the basic row (a browser interprets the script) |

Cells in the matrix: `pow_interstitial` naive ❌, curl_cffi ⚠️, Playwright ⚠️; `pow_interstitial_hardened` naive ❌, curl_cffi ❌,
Playwright ⚠️.

### Limits

`location` is unconfirmed (LOW, flag off). The page wording and the cookie timing are approximations (the lab issues the
cookies with the page, the capture with the verify response), and the server-side wait on the refresh path is an inference.
The hardened variant defeats regexes, not a JS engine.
