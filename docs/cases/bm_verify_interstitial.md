# `bm_verify_interstitial`: the cookieless `bm-verify` interstitial

Category: js · Module: `api/app/modules/bm_verify_interstitial.py` · Protected URL: `/protected/bm_verify_interstitial` ·
Default: on, with the cookieless gate behind a flag (off) · Module tier: **MEDIUM** (the hardened variant is a LAB device)

## What it is

A navigation from a session with no server-side proof that it stores cookies and runs JavaScript gets an HTML page instead of
the resource. The page's inline script does one line of arithmetic and POSTs the result with a single-use `bm-verify` token;
a client without JavaScript can follow the page's meta refresh after a time penalty instead. Once the session has proof, it
gets the real page.

### Why this is not a proof of work

A proof of work has a cost that a difficulty tunes, an answer that is much cheaper to check than to find, and a fresh
challenge. The interstitial has only the fresh challenge (a single-use token):

- the "work" is one addition, `i + Number("3886" + "11036")`, with no difficulty to raise;
- checking the answer costs the server exactly what finding it costs the client;
- a fixed regular expression answers it without running the script, which is why the lab never lets it PASS.

What it does check is capability: that the client keeps a cookie jar, makes the round trip and (unless it parses the page)
executes JavaScript. Akamai's brief describes it in those terms. The JSON field that carries the answer is named `pow` on the
wire, which is Akamai's name and the reason the lab keeps it; the concept is not a proof of work. The proof of work in Akamai's
design is the crypto challenge: [`sec_cpt_challenge`](sec_cpt_challenge.md).

## How real Akamai uses it

The Bot Manager brief describes, apart from its "minimum-time-to-solve cryptographic puzzles", an interstitial challenge that
"requires clients to prove they support storing cookies and executing JavaScript. If not, Bot Manager enforces a time
penalty" ([P], 10/2023). The corrected audit (report §1.2 case 6, correction of 2026-10-02) found two independent 2026 sources
that describe the same artifact, so the lab's arithmetic page is **not** a lab-only invention ([S]: the bershka-scraper
README, measured 2026-09-19 to 09-22; sugarplum issue #172 and PR #177, 2026-09-27):

- a cookieless client gets HTTP 200 (about 2.1-2.4 KB) with a `bm-verify` token and one line of arithmetic, for example
  `var i = 1789910678; var j = i + Number("3886" + "11036");`;
- the page's script POSTs `{"bm-verify": token, "pow": i + 388611036}` to `/_sec/verify?provider=interstitial` and reloads;
- the page itself sets no Akamai cookie (only the site's own session cookies); the verify response sets `_abck`, `bm_sz` and
  `ak_bmsc`, and the cleared session kept getting the real page (five further requests);
- the page also carries `<meta http-equiv="refresh" content="5; URL='<url>&bm-verify=AAQ…'">`: refetching the URL with that
  single-use token returned the real page, with no JavaScript and no cookies, and a second interstitial was final.

## Confidence

| Sub-feature | Tier |
|---|---|
| Interstitial with a time penalty for clients without cookies or JavaScript (concept) | HIGH (Akamai brief 2023) |
| The `bm-verify` page (arithmetic `pow`, `/_sec/verify?provider=interstitial`, cookies on success) | MEDIUM (approximation: concept [P], artifacts from two independent secondary sources, plus an unpublished observation from the lab owner's own HAR-derived client that matches the same shape) |
| Meta-refresh path for clients without JavaScript (one navigation per single-use token, after 5 s) | MEDIUM (markup and the one-shot refetch are observed; that the wait is enforced server-side is an inference from the brief's "time penalty") |
| Cookieless gate on first visits, cleared by server-side proof only | MEDIUM, flag `interstitial_cookieless_gate` (off, because it changes every client's first visit) |
| JSON `location` in the verify response | LOW, flag `interstitial_location` (off): unverified; same-origin only |
| Randomized arithmetic shape | LAB, flag `interstitial_hardened` (off) |

Akamai's real page wording and the cookie-issuing step are approximated ([KNOWN_GAPS](../KNOWN_GAPS.md), section 4).

## How the lab simulates it

- **Page**: the `interstitial` challenge provider (or the gate below) answers an HTML page, HTTP 200, titled "Checking your
  browser", whose inline script computes the arithmetic and POSTs the result. For XHR the provider answers a 428 JSON carrying
  the same `bm-verify`, `expression` and `hardened` fields. The page is lab-written markup, not Akamai's.
- **The arithmetic is data**: the basic form is `var i = <issue time>; var j = i + Number("<4 digits>" + "<5 digits>");`,
  the observed shape. The observed `i`, 1789910678, is 2026-09-20 13:24 UTC, inside the capture window, so the lab reads it
  as the issuing Unix time (an inference). The observed answer, 2,178,521,714, is above 2³¹−1, and with a current clock the
  lab's answer often is too, which overflows a 32-bit signed integer. The server stores the spec (`i` and the digit parts)
  with the challenge and computes the expected answer from it, never from the page text and never with `eval`.
- **Token**: `bm-verify` is the challenge token, `AAQ` (the observed prefix) plus random lab data: single use (consumed even on
  failure), bound to `bm_sz`, valid for `challenge_timeout` (60 s), stored as `bm_verify:ch:{token}`. Failures (403):
  `unknown_or_replayed`, `wrong_session`, `expired`, `bad_answer`, `wrong_answer`. There is no minimum wait on this page.
- **Verify**: `POST /_sec/verify?provider=interstitial`, the vendor-style path the public sources show. It is the engine's
  shared verify route, the same one the `sec_cpt` providers use; it hands the token to this module's `verify_challenge`.
  Body `{"bm-verify": token, "pow": int}`.
- **On success**: `bm_verify:{sid}` is stored (3600 s) and the lab issues or refreshes `bm_sz`, `ak_bmsc` and `_abck` through
  its own cookie issuance (`main.finalize_cookies`). It does **not** set `sec_cpt` and does **not** mark `_abck` validated
  (that still needs the sensor flow). Approximation: the lab already hands those three cookies out with the page, because it
  binds the token to `bm_sz`; in the capture they arrive only with the verify response. Cookie presence therefore proves
  nothing in the lab, and the gate below checks server-side state.
- **On-demand page**: `GET /akam/bm_verify_interstitial/page?return_to=<path>` serves the page without waiting for a policy
  decision (used by the harness). After the verify, the gate's page reloads, as observed; the on-demand page goes to its
  `return_to` (default `/`) instead, because reloading that route would only issue a fresh interstitial.
- **`location` (flag `interstitial_location`, LOW, default off)**: with the flag on, the verify reply carries the path of the
  request that was challenged, and only when `safe_location` accepts it: a plain absolute path, nothing with a scheme or
  netloc, no `//host`, no backslash, no control characters. Anything else is dropped, so a crafted `return_to` cannot turn the
  page into an open redirect, and the page script applies the same check before `location.replace(...)`. No published source
  shows this field, so it is off by default and clients must not depend on it.
- **Gate** (flag `interstitial_cookieless_gate`, MEDIUM, default **off**): a `pre_request` hook that serves this page to a GET
  navigation (`Accept` contains `text/html`) until the session has server-side proof: a solved interstitial
  (`bm_verify:{sid}`), a valid `sec_cpt` (from [`sec_cpt_challenge`](sec_cpt_challenge.md)), or an `_abck` the sensor flow
  validated. A reload with the cookies the page handed out is not enough. The flag is off because it changes every client's
  first visit.
- **No-JavaScript path**: the page's meta refresh re-requests the URL with `bm-verify=<token>` after 5 seconds. A gated
  navigation carrying an unused interstitial token at least 5 seconds old passes once; an earlier one is served the page
  again and keeps the token. The token is then consumed and nothing is cleared, so the next navigation gets a new
  interstitial. A request that sends a `bm_sz` must send the session the token was issued for; one without cookies is
  accepted, like the observed refetch. That Akamai enforces the wait server-side is an inference from the brief ("Bot
  Manager enforces a time penalty").
- **Hardened variant** (flag `interstitial_hardened`, **LAB**, default off): randomizes the arithmetic shape per issuance
  (identifier names, two to four concatenated string parts, operand order, whitespace, quote style, `Number(...)` /
  `parseInt(..., 10)` / unary plus, a decimal or hex `i`, `var` or `let`, an optional decoy declaration), so a fixed regex such
  as `var\s+j\s*=\s*i\s*\+\s*Number\("(\d+)"\s*\+\s*"(\d+)"\)` stops matching and only a client that interprets the
  script answers correctly. It is a lab device, not an Akamai feature, and a determined solver can still interpret the script.
- **Scoring** (`evaluate`), by the best proof the session holds:

  | State | Verdict | Score |
  |---|---|---|
  | a valid `sec_cpt` or a validated `_abck` | pass | 0 |
  | only the interstitial solved | warn | 20 |
  | no proof, and the interstitial is in use (gate on, or `challenge_provider` is `interstitial`) | fail | 45 |
  | no proof, interstitial not in use | skip | 0 |

  A solved interstitial is weak evidence (a regex can do it), so it WARNs and never PASSes. 20 is the top of the cautious band
  for every telemetry type, so the default policy monitors the session and serves the protected page, as the bershka capture
  shows for a cleared session. The module's `applies_to` is empty: it is evaluated on `/protected/bm_verify_interstitial` only,
  never on the all-module pages, where `sec_cpt_challenge` already scores a session that solved nothing and a second "nothing
  solved" signal would only count the same fact twice.
- **Provider scoping**: `challenge_satisfied` vouches only for the `interstitial` provider, using the same proof as the gate.
  A solved interstitial never waives a crypto or tile challenge; a valid `sec_cpt` or a validated `_abck` waives this one.

## How a scraper passes it

Parse the token and the two statements from the page, compute `i + int(A + B)`, `POST {"bm-verify", "pow"}` to
`/_sec/verify?provider=interstitial` with the same cookie jar, request the page again (or follow a same-origin `location` if
the LOW flag adds one), and keep the cookies. Regexes are enough for the basic page and give WARN 20 at best; the hardened
page needs a JavaScript engine or a robust JS parser. A valid `sec_cpt` or a validated `_abck` is what reaches PASS. Without
JavaScript, follow the meta refresh after 5 seconds: one page, nothing cleared.

## Observed results

From `RESULTS.md`. The runner turns `interstitial_cookieless_gate` on for both rows and `interstitial_hardened` on for the
second, in a fresh session per client, and judges the `bm_verify_interstitial` signal after the attempt.

| Row | naive | curl_cffi (regexes only) | Playwright |
|---|---|---|---|
| `bm_verify_interstitial` | fail 45, "no proof of cookie and JavaScript support yet" (not attempted; its `Accept: */*` requests are not gated) | **warn 20**, monitor/cautious, "only the basic arithmetic interstitial was solved (a regex can do that)"; verify accepted, reloaded | **warn 20**, monitor/cautious, same reason; the page's own script ran and verify was accepted |
| `bm_verify_interstitial_hardened` | fail 45 (not attempted) | **not scored**: the regexes did not match the hardened script, so it stopped, and the gate served the interstitial again | **warn 20**, same reason as the basic row (a browser interprets the script) |

Cells in the matrix: `bm_verify_interstitial` naive ❌, curl_cffi ⚠️, Playwright ⚠️; `bm_verify_interstitial_hardened` naive ❌,
curl_cffi ❌, Playwright ⚠️.

## Limits and caveats

`location` is unconfirmed (LOW, flag off). The page wording and the cookie timing are approximations (the lab issues the
cookies with the page, the capture with the verify response), and the server-side wait on the refresh path is an inference.
The hardened variant defeats regexes, not a JS engine.
