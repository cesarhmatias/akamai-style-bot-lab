## How the clients are configured

All three are representative default configurations, not tuned to pass.

* **naive**: plain `requests`, cookie jar, one landing visit, no script, no challenge solver, none of
  the telemetry the lab asks for.
* **curl_cffi**: `impersonate="chrome131"` stays pinned on purpose (the audit notes the profile is
  about 23 Chrome majors old). It solves the pure-HTTP challenges with the current protocols
  (the crypto `sec_cpt` challenge: sha256 with the minimum wait; pixel beacon parsed from the page
  HTML) but runs no JavaScript, so it sends no sensor, no inline telemetry and cannot play the tile
  game. For the interstitial rows a cookie-less navigation to `/protected/bm_verify_interstitial` gets
  the page from the gate, and it solves the BASIC interstitial with regexes only (`var i = N;`,
  `var j = i + Number("A" + "B");` and the `"bm-verify"` token): it POSTs `{"bm-verify", "pow"}` to
  `/_sec/verify?provider=interstitial` and reloads the resource, as the page does. It follows a
  same-origin `location` only when the reply carries one (LOW flag `interstitial_location`, off); on
  a page the regexes do not match it stops with a clear reason.
  `native_app` is the one cell where it plays a different role: an app HTTP stack. It
  re-implements the lab's documented `X-acf-sensor-data` header with the documented sample app key
  and a synthetic motion stream.
* **playwright**: headless Chromium (Playwright's bundled headless shell) with the two most copied
  recipes left on: a User-Agent override to `Chrome/131` and
  `Object.defineProperty(Navigator.prototype, 'webdriver', ...)`, plus a seeded Bezier mouse path.
  Protected resources are navigated to, login/checkout/mobile calls use an in-page `fetch` (so the page's
  inline-telemetry wrapper attaches its header) and the tile game is played with a curved, jittered
  pointer path. For the interstitial rows it just loads the page and lets the page's own script run.

## Reading the cells

* The cell is the case's own signal. A request can be denied or challenged for a different module's
  score without moving another module's cell (for example `account_protector` is ✅ for naive although
  its login was denied).
* `/protected/<case>` evaluates only that module, so the action and segment shown are the case's own.
  Login, checkout and mobile requests run every module that applies to the endpoint class.
* `known_bots` is ✅ (skip) for everyone: no client claims a crawler User-Agent. It is a row so the
  harness fails when the module disappears, not because the clients are tested on it.
* `account_protector` needs account history to say anything. A single clean login is ✅ for everyone;
  its risk factors (new device, impossible travel, disposable domain) are covered by unit tests.
* `avf_stepup` depends on session history by design. It is armed by an earlier request that landed in
  the strict segment; the case order in the matrix is fixed so the result is deterministic. A client that
  cannot run the step-up script keeps the WARN; Playwright was never pushed into the strict segment in
  this run, so the module stays skip (✅).
* `interactive_challenge` for Playwright runs in a fresh browser session. The engine downgrades a
  `challenge` action to monitor only when the module serving the requested provider reports the
  session solved: a valid `sec_cpt` waives crypto/interstitial challenges, never the tile game, and a
  solved tile game never waives a crypto challenge. The fresh session is kept so this row does not
  depend on what the landing page solved first.
* `native_app` for curl_cffi is a statement about the lab's documented sample key, not about real SDKs:
  anyone holding the key can mint the header. Real SDK keys and attestation are not public.
* `bm_verify_interstitial` and `bm_verify_interstitial_hardened` judge the `bm_verify_interstitial`
  signal AFTER an interstitial attempt, in a fresh session for every client (the signal follows the
  best proof the session holds: a valid `sec_cpt` or a validated `_abck` is PASS, so Playwright's
  landing-page solver would hide the interstitial). The runner turns `interstitial_cookieless_gate` on
  for both rows and `interstitial_hardened` on for the second one, and restores both afterwards. Both
  browser-like clients get the page from the gate on a cookie-less navigation to
  `/protected/bm_verify_interstitial`, solve it and reload that URL; the `client` column records
  whether the verify call was accepted.
  A solved interstitial is WARN 20 by design: weak evidence (a fixed regex can solve it), but inside
  the cautious band, so the protected page is served under monitoring, as the bershka capture shows
  for a cleared session. An unsolved one is FAIL 45 while the interstitial is in use (strict:
  challenge). The interstitial is a cookie and JavaScript check, not a proof of work: the "work" is one
  addition, which is why a regex can do it. The gate checks server-side state,
  not cookies, so a client that could not solve it stays behind it: curl_cffi's hardened cell is ❌
  because its last request was answered with the interstitial again and never scored. A client
  without JavaScript could follow the page's 5-second meta refresh instead, which lets one navigation
  through without clearing the session. naive does neither: its requests send `Accept: */*`, which
  the gate does not intercept, so they are scored as an unsolved session.
* `ip_reputation` stays ✅ for every client because the lab resets state between clients and each
  client sends well under the rate controls.

## Why the non-passing cells fail, and how a client would pass them

### naive

| cell | why | how a client passes |
|---|---|---|
| tls_fingerprint, h2_fingerprint, header_order | OpenSSL hello, HTTP/1.1, `python-requests` headers | an impersonation library or a real browser |
| session_validation | an API-style call without browser fetch metadata and a page-to-XHR chain | load a page first and send `Sec-Fetch-*` plus a same-origin `Referer` |
| abck_cookie, sensor_data, js_integrity, behavioral | no JavaScript, so no sensor and no interaction | run the page in a browser |
| sec_cpt_challenge | no solve | `GET /akam/sec_cpt_challenge/challenge?provider=crypto`, sha256, wait `chlg_duration`, `POST /_sec/verify?provider=crypto` |
| pixel_challenge | no beacon | parse `bazadebezolkohpepadr` and `/akam/13/<hex>` from the HTML, POST `p=<ts>.<digest>` |
| sbsd_challenge | script never executed | run the script |
| interactive_challenge | game not played | play it in a browser with real pointer input |
| avf_stepup | step-up data requested but not sent | run the step-up script |
| inline_telemetry | no `akamai-bm-telemetry` header | a browser gets it for free; HTTP needs the page's key and MAC |
| native_app | no `X-acf-sensor-data` header | the app SDK |
| bm_verify_interstitial, bm_verify_interstitial_hardened | the interstitial is never attempted | solve it: regexes are enough for the basic page; WARN 20 (served under monitoring) is the ceiling, only a valid `sec_cpt` or a validated `_abck` reaches PASS |

### curl_cffi

| cell | why | how a client passes |
|---|---|---|
| abck_cookie, sensor_data, js_integrity, behavioral | no JavaScript, so no sensor | run the page in a browser (or port the sensor) |
| sbsd_challenge | op chain needs a JS engine | execute the script |
| interactive_challenge | needs trusted pointer events | a browser |
| avf_stepup (warn) | step-up data requested but not sent | a browser |
| inline_telemetry | the page script that attaches the header never runs | parse `window.__akInline` from the HTML and compute the request-bound MAC |
| bm_verify_interstitial (warn) | the regexes solve the basic page and the verify call is accepted, but a regex-solvable challenge is weak evidence: WARN 20, served under monitoring | hold a valid `sec_cpt` in the same session (its `sec_cpt_challenge` cell is ✅) |
| bm_verify_interstitial_hardened | the randomized arithmetic shape (names, quotes, `Number`/`parseInt`/unary plus, hex or decimal `i`, `var`/`let`, operand order) no longer matches the fixed regexes, so the client stops without solving and the gate keeps serving it the interstitial | interpret the script (a JS engine or a robust JS parser instead of regexes) |

curl_cffi still passes `tls_fingerprint` and `version_consistency` because the pinned `chrome131` profile
is internally consistent (UA 131, TLS of that era, matching hints). The audit's warning applies when its
UA is raised above what the TLS hello can support, or when real Chrome moves on: nothing in the matrix
punishes an old but consistent profile.

### playwright

| cell | why | how a client passes |
|---|---|---|
| tls_fingerprint (warn) | the bundled headless shell's JA4 is a real Chromium fingerprint (Scrapfly lists it as Brave 153 on Linux) but not Google Chrome's: 16 extensions, without the `trust_anchors` extension Chrome 152+ sends (WARN 10) | launch the full browser (`channel="chromium"`, new headless) |
| header_order, version_consistency | the UA says Chrome 131 while `sec-ch-ua`, `navigator.userAgentData` and the TLS hello (ALPS 17613, ML-DSA, the GREASE signature algorithm of Chrome 152+) say Chrome 153; `HeadlessChrome` is in the brands | do not override the UA to an old major; if one is needed, override it with the browser's own major and matching client hints through CDP `Emulation.setUserAgentOverride` + `userAgentMetadata` |
| js_integrity | the `webdriver` getter is a script function (not native code), `HeadlessChrome` shows in the UA or hints, `window.chrome` is absent in the headless shell | launch with `--disable-blink-features=AutomationControlled` instead of a JS override, use the full browser, and hide the headless brand with the same CDP override |
| native_app | a browser has no native SDK to produce the header | n/a for a web client |
| bm_verify_interstitial, bm_verify_interstitial_hardened (warn) | the page's script solves both variants and the verify call is accepted (the hardened shape only breaks regexes, not an engine), but a solved interstitial tops out at WARN 20 | hold a valid `sec_cpt` or a validated `_abck`: the landing page earns both in the main session, but these rows start from a fresh session on purpose |

These fixes were checked in a scratch run (not applied to the default client): `channel="chromium"`, the
`--disable-blink-features=AutomationControlled` flag, no `defineProperty` override, and a CDP user-agent
override carrying the browser's real major and matching `userAgentMetadata` turned `tls_fingerprint`,
`header_order`, `version_consistency`, `js_integrity`, `abck_cookie` and `behavioral` to pass. Removing only the UA
override is not enough: the UA then reads `HeadlessChrome/153`, which `header_order` and `js_integrity`
flag on their own.

## Before vs after this remediation

The previous `RESULTS.md` (commit `9c6bc16`) had ten cases judged from the HTTP status (✅ = allowed).
Against the remediated lab the same ten cases give the same cells for naive and curl_cffi, and two moved
for Playwright:

| cell | before | after | why |
|---|---|---|---|
| header_order x playwright | ✅ (score 5) | ❌ (100) | the new Chrome-version checks: `HeadlessChrome` in the `sec-ch-ua` brands and UA 131 against hints saying 153 |
| tls_fingerprint x playwright | ✅ | ⚠️ (10) | the known-Chrome JA4 check: the bundled hello's JA4 is a Chromium build's, not Google Chrome's |

New rows (not in the old matrix):

| case | naive | curl_cffi | playwright | what it shows |
|---|---|---|---|---|
| version_consistency | ✅ (skip: not Chromium) | ✅ | ❌ | the UA override on a newer Chromium contradicts TLS, hints and JS in four places |
| js_integrity | ❌ | ❌ | ❌ | Playwright's `defineProperty` override is caught (non-native getter) together with the headless markers |
| known_bots | ✅ | ✅ | ✅ | skip for non-crawler UAs |
| session_validation | ❌ | ✅ | ✅ | an API-style client without a page chain |
| interactive_challenge | ❌ | ❌ | ✅ | only a client with trusted pointer input plays the game |
| avf_stepup | ⚠️ | ⚠️ | ✅ | clients that cannot run the step-up script keep the WARN |
| inline_telemetry | ❌ | ❌ | ✅ | transactional calls need a request-bound header |
| account_protector | ✅ | ✅ | ✅ | a first clean login has no history to contradict |
| native_app | ❌ | ✅ | ❌ | curl_cffi stands in for an app stack with the documented key |
| bm_verify_interstitial | ❌ | ⚠️ | ⚠️ | a regex solves the basic cookieless interstitial: accepted, but only WARN 20 |
| bm_verify_interstitial_hardened | ❌ | ❌ | ⚠️ | the randomized shape defeats the fixed regexes; a client that runs the script still solves it |

Other differences:

* Cells are judged from the signal in the report, not the HTTP status. With the response policy,
  `monitor`, `delay` and `serve_alternate` answer 200 and a challenge answers 428 or HTML, so the old
  "allowed = 200" reading no longer says anything about the detection.
* The curl_cffi crypto-challenge and pixel cells are ✅ as before but through the new protocols: the
  crypto challenge needs the minimum wait and the pixel is parsed from the page HTML (there is no
  `/config` hand-out any more).
* Safari is not a matrix client: the Safari TLS/H2 fix is covered by the regression tests in
  `api/tests`, not by this table.
* Running the matrix against the remediated stack exposed three bugs that were fixed on the way:
  a `Server` header sent twice on the deny page (uvicorn added its own), `inline_telemetry` returning
  `hash_mismatch` (BLOCK) to every browser login/checkout because the AJAX-injection wrapper turned each
  call into a `Request` whose body the inline wrapper did not hash, and a JA4 whose third part changed on
  every Chrome connection because the GREASE signature algorithm (which Chrome 152+ sends first) was not
  stripped.
* A later pass (2026-10-03) compared the interstitial with the published captures and changed three
  things without moving any cell: the gate checks server-side state (before, a reload with the cookies
  the page handed out got through without solving); a solved interstitial is WARN 20 in the cautious
  band (it was WARN 30, which kept a cleared session in the challenge band, unlike the captures); and the
  verify reply carries no `location` unless the LOW flag is on (the captures reload). The same pass
  added the page's meta-refresh path and the Chrome 152 TLS markers.
* A second pass on 2026-10-03 split `proof_of_work` into `sec_cpt_challenge` (the `sec_cpt` providers:
  only `crypto`, and the hashing half of `adaptive`, is a proof of work) and `bm_verify_interstitial`
  (the cookieless interstitial: a cookie and JavaScript check whose only "work" is one addition). The
  rows were renamed (`proof_of_work` to `sec_cpt_challenge`, `pow_interstitial*` to
  `bm_verify_interstitial*`), the flags too (`pow_*` to `interstitial_*`), and no cell moved.
