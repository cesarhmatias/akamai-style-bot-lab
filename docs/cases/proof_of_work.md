# `proof_of_work`: `sec_cpt`-style challenge providers

Category: js · Module: `api/app/modules/proof_of_work.py` · Protected URL: `/protected/proof_of_work` · Default: on
· Module tier: **MEDIUM** (artifacts are approximations; the free-form `simple` variant is a LAB device)

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

No flags in the committed behaviour. Whether verify returns 428 vs 200 and the `chlg_duration` values on real sites are
unverified ([KNOWN_GAPS](../KNOWN_GAPS.md) item 5).

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
  | only the free-form `simple` variant solved | warn | 30 |
  | nothing solved | fail | 45 |

  45 lands in the `strict` segment for standard telemetry, so a protected request is challenged (428 or iframe) rather than
  denied.
- **Proactive solver** (LAB convenience): `pow.js`, included on the landing page, runs the `crypto` flow in the background so a
  real browser already holds a valid `sec_cpt` when it reaches a protected resource. Akamai does not do this; it keeps the
  harness's browser case meaningful.
- **`simple` (LAB)**: `GET /akam/proof_of_work/challenge?variant=simple` returns an expression `a op b op c` (numbers 2-99,
  `+ - *`, normal precedence, evaluated server-side without `eval`). Solving it alone only WARNs 30 (`pow:simple:{sid}`).

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

## Limits and caveats

- Difficulty and wait are lab constants and settings; the legacy `/akam/proof_of_work/` routes exist for the harness clients.
- The proactive solver and the `simple` variant are lab devices with no Akamai counterpart.
- See `interactive_challenge` for the tile game that shares the engine's "already solved" downgrade.
