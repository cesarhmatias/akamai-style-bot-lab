# Case 6: `proof_of_work` (`sec_cpt`-style interstitial)

Category: js. Module: `api/app/modules/proof_of_work.py`. Protected URL: `/protected/proof_of_work`.

## Mechanism
The client must spend CPU on a server-issued puzzle bound to its session, which makes mass automation
costly and filters clients that cannot compute.

## How real Akamai uses it
Public knowledge: Akamai's challenge actions ("crypto challenge" / `sec_cpt` cookie) serve an interstitial
whose script computes a proof of work and, on success, the server sets a `sec_cpt` cookie. The lab imitates
that shape (own algorithm, own cookie value `<32 hex>~3~<unix ts>`); it is not Akamai's scheme.

## How THIS server detects it
Two variants, both under `/akam/proof_of_work/`:
- `GET /challenge?variant=simple` returns an arithmetic expression (`a op b op c`, `+ - *`).
- `GET /challenge?variant=hard` returns `nonce`, `difficulty` (default 4) and the rule: find a `counter`
  with `sha256(nonce + str(counter))` hex starting with `difficulty` zeros.
- `POST /verify` `{"challenge_id", "answer"}`. Challenges are single use (deleted even on failure),
  bound to `bm_sz`, expire after 60 s. Errors: `unknown_or_replayed`, `wrong_session`, `expired`,
  `bad_answer`, `wrong_answer` (403). Success sets store key `pow:{sid}` (hard) or `pow:simple:{sid}`
  and a `sec_cpt` cookie.

| state | verdict | score |
|---|---|---|
| hard solved | pass | 0 |
| only simple solved | warn | 30 |
| nothing solved | fail | 80 |

`pow.js` (browser) solves both variants with WebCrypto in batches of 256 and sets `window.__akPowDone`.

## How a client passes here
Hold the `bm_sz` cookie (load `/` first), fetch the hard challenge, brute-force the counter, POST it.
`clients/curl_cffi_client.py::solve_pow` does this in pure Python (difficulty 4 is about 65k hashes on average).

## Observed (real run)
- naive: fail 80, "no proof of work solved for this session".
- curl_cffi: pass 0, "hard proof of work solved" (pure HTTP, no JS).
- Playwright: pass 0, "hard proof of work solved" (via `pow.js`).

## Caveats
- It costs time, not identity: any language can solve it, and difficulty is a fixed constant here
  (`DEFAULT_DIFFICULTY = 4`).
- The `sec_cpt` cookie is issued but not itself checked; the server-side `pow:{sid}` key is the truth.
