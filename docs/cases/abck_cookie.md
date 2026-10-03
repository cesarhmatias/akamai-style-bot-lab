# Case 4: `abck_cookie` (the `_abck` cookie lifecycle)

Category: cookie. Module: `api/app/modules/abck_cookie.py`. Protected URL: `/protected/abck_cookie`.

## Mechanism
The server issues a session cookie that starts "unvalidated" and is upgraded only after the client proves it
ran the sensor script. Later requests are judged by the cookie.

## How real Akamai uses it
Public knowledge: Akamai Bot Manager sets `_abck`, `bm_sz` and `ak_bmsc` on first contact. `_abck` carries
`~-1~` while unvalidated; after a successful `sensor_data` POST the response returns a new `_abck`
containing `~0~`. Scrapers have long been observed gating on that marker. The exact internal format is not
public; the lab imitates only the visible shape `<hex>~-1~<blob>~-1~-1`.

## How THIS server detects it
- Core middleware (`finalize_cookies` in `api/app/main.py`) issues `bm_sz` (session id, `32 hex~8 hex`),
  `ak_bmsc` and an unvalidated `_abck` on any scored response that lacks them.
- A successful sensor POST stores `abck:{session_id}="validated"` (via `mark_abck_validated`) and sets an
  `_abck` with `~0~`.
- The module checks the cookie against the server-side truth:

| situation | verdict | score |
|---|---|---|
| no `_abck` | fail | 95 |
| cookie contains `~0~` but store says not validated (forged) | **block** | 100 |
| cookie without `~0~` | fail | 85 |
| `~0~` and validated | pass | 0 |

## How a client passes here
Keep the cookie jar, load `/`, let the sensor run and succeed (see `sensor_data`), then request the
protected URL with the same cookies. Editing the cookie to contain `~0~` is detected and hard-blocked.

## Observed (real run)
- naive: fail 85, "_abck not validated" (has cookie, never ran JS).
- curl_cffi: fail 85, "_abck not validated" (cookie persisted but no JS).
- Playwright: pass 0, "_abck validated".

## Caveats
- This module has no JS of its own: its outcome is a function of the `sensor_data` case.
- Disabling `sensor_data` in the dashboard does not change the sensor endpoint, only whether it is scored.
- The cookie is not cryptographically signed; the truth lives in the store (Redis/in-memory), keyed by `bm_sz`.
