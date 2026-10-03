# `abck_cookie`: the `_abck` cookie, validated server-side

Category: cookie · Module: `api/app/modules/abck_cookie.py` · Protected URL: `/protected/abck_cookie`
· Default: on · Module tier: **MEDIUM** (modes `abck_tilde0_mode` and `abck_n_posts` are LOW, flag-gated, off)

## What it is

`_abck` is the cookie Akamai's sensor flow upgrades once it accepts a client's telemetry. The lab issues it with `bm_sz`
and `ak_bmsc` on the first scored response and treats a cookie as good only when the server's own record says the
session was validated, and the same client presents it.

## How real Akamai uses it

Public captures show `_abck=HEX32~<flag>~YAAQ<base64>~-1~-1~-1` (a 32-hex id, a state flag, a `YAAQ`-prefixed blob, three
`-1` fields in 2022) next to `bm_sz=HEX32~YAAQ<base64>~<int>~<int>` (report §1.2 case 4, [S]: httpx #2287 (2022) and
Coraza #1620 (2026)). The cookie is refreshed by `Set-Cookie` on sensor POST responses and lives about a year ([V]).
Akamai frames cookie and JavaScript checks as active detection that "employs an interaction to confirm the request is
coming from a web browser" ([P]). Vendor docs say the cookie is valid once it contains `~0~` and that sites which never
show it expect exactly three sensor posts; a 2026 write-up calls `~0~` "a convention, not a guarantee" ([V]).

## Confidence

| Sub-feature | Tier | Flag (default) |
|---|---|---|
| Cookie shape `HEX32~flag~YAAQ...~-1~-1~-1`; server-side validation as truth | MEDIUM (approximation, two public captures) | none (default mode) |
| Binding validated state to fingerprint continuity (JA4 family, UA, /24) | MEDIUM (approximation: Akamai's binding rules are not public) | none |
| `~0~` in the cookie after validation; forged `~0~` is a BLOCK | LOW: unverified, vendor-sourced | `abck_tilde0_mode` (off) |
| Validity needs N valid sensor posts, `~0~` never appears | LOW: unverified, vendor-sourced | `abck_n_posts` (off) |
| Cookie attributes (HttpOnly, Secure, Max-Age) | not confirmed ([KNOWN_GAPS](../KNOWN_GAPS.md) item 2) | none |

## How the lab simulates it

The module has no JavaScript. `sensor_data` validates posts and calls `mark_abck_validated`, storing `abck:{sid}` =
`validated` and `abck:bind:{sid}` (the binding at validation time), both with a 4 h TTL.

- **default mode**: only the store key decides. The cookie's flag is not trusted (a forged `~0~` is just not
  validated) and stays `-1`.
- **`abck_tilde0_mode`**: the cookie flips to `~0~` on validation; a `~0~` cookie the server never validated is
  BLOCK 100 ("forged").
- **`abck_n_posts`**: validity needs `LAB_ABCK_REQUIRED_POSTS` valid sensor posts (default 3, `sensor:n:{sid}`) and `~0~`
  never appears.

| Situation | Verdict | Score |
|---|---|---|
| no `_abck` | fail | 95 |
| `~0~` claimed but never validated (tilde0 mode) | block | 100 |
| malformed value | fail | 85 |
| not validated server-side | fail | 85 |
| validated, but UA or JA4 family changed | block | 100 |
| validated, only the /24 (IPv6 /48) changed | fail | 70 |
| validated, same binding | pass | 0 |

Cookie shapes come from `api/app/session.py`: `bm_sz` is `HEX32~YAAQ<b64>~int~int` (4 h); `_abck` keeps its 32-hex id
across refreshes and changes the blob. Everything after `YAAQ` is random lab data, not an Akamai encoding.

## How a scraper passes it

Run the sensor flow in the same browser (same TLS stack, UA and network prefix) and keep the cookies it is handed.
Replaying a validated cookie from another client is detected.

## Observed results

| Client | Cell | Verdict and reason |
|---|---|---|
| naive | fail | fail 85, "_abck not validated" |
| curl_cffi | fail | fail 85, "_abck not validated" (no JavaScript, so no sensor) |
| Playwright | pass | pass 0, "_abck validated" |

## Limits and caveats

- Thresholds and binding components are the lab's own. A UA or JA4-family change is a BLOCK; a prefix-only change is a
  FAIL because NAT and mobile roaming move clients legitimately.
- `_abck` state transitions on a current site are unverified ([KNOWN_GAPS](../KNOWN_GAPS.md) item 1).
