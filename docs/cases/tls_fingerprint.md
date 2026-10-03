# Case 1: `tls_fingerprint` (JA3 / JA4)

Category: passive. Module: `api/app/modules/tls_fingerprint.py`. Protected URL: `/protected/tls_fingerprint`.

## Mechanism
Before any HTTP byte is sent, a TLS client sends a ClientHello: TLS version, cipher suites, extensions and
their order, supported groups, ALPN. Each TLS library (BoringSSL in Chrome, OpenSSL in Python and curl, Go's
`crypto/tls`, NSS in Firefox) produces a recognisable hello. Two public fingerprint formats summarise it:

- **JA3**: MD5 of `version,ciphers,extensions,groups,point-formats` (GREASE removed).
- **JA4** (FoxIO): `t13d1516h2_<hash of ciphers>_<hash of sorted extensions + sigalgs>`. Sorting the extensions
  makes it stable against Chrome's per-connection extension permutation, which makes JA3 useless for Chrome.

## How real Akamai uses it
Akamai Bot Manager is public about fingerprinting the TLS handshake at the CDN edge and comparing it with
what the request claims to be (the User-Agent). A `requests`/OpenSSL hello with a Chrome UA is a mismatch
that no header tweak can fix. (This lab does not know Akamai's actual tables or thresholds.)

## How THIS server detects it
The Go edge (`edge/`) parses the raw ClientHello and injects `x-ja3`, `x-ja3-hash`, `x-ja4`, `x-ja3-grease`
and `x-tls-exts` (anti-spoofing: client-sent copies are stripped). The module does not match exact hashes.
`classify_tls()` scores Chrome-ness from structural marks: GREASE, ALPS (ext 17513/17613),
`compress_certificate` (27), ECH grease (65037), cipher prefix `4865,4866,4867`. Chrome needs >= 3 marks.
Firefox is recognised by ext 34/28 plus prefix `4865,4867,4866`; OpenSSL by prefix `4866,4867,4865` or
a `h1`/`00` JA4 ALPN; Go by the Chrome cipher prefix without ALPS.

| situation | verdict | score |
|---|---|---|
| Chrome-like hello and Chrome UA (or `sec-ch-ua` present) | pass | 0 |
| Chrome hello, UA claims another family | fail | 85 |
| Firefox hello and Firefox UA, no `sec-ch-ua` | pass | 0 |
| openssl/go hello with browser UA | fail | 85 |
| openssl/go hello, non-browser UA | fail | 75 |
| unrecognised hello | warn | 40 |
| no TLS fingerprint at all (bypassed the edge) | warn | 40 |

## How a client passes here
Use a real TLS stack of a browser: Playwright/Chromium, or `curl_cffi` with `impersonate="chrome131"`
(`clients/curl_cffi_client.py`). Setting headers never changes this signal.

## Observed (real run)
| client | JA4 | verdict | reason |
|---|---|---|---|
| naive (`requests` 2.34.2, OpenSSL) | `t13d3112h1_e8f1e7e78f70_b26ce05bbdd6` | fail 75 | Non-browser TLS stack (openssl) |
| curl_cffi chrome131 | `t13d1516h2_8daaf6152771_02713d6af862` | pass 0 | Chrome-like TLS matches Chrome UA |
| Playwright Chromium | `t13d1516h2_8daaf6152771_cca3cc876f32` | pass 0 | Chrome-like TLS matches Chrome UA |

Note the `h1` in the naive JA4: `requests` does not offer `h2` in ALPN. (`t13d3112h2_e8f1e7e78f70_...` is
what `curl` produces; the same cipher/extension hash, different ALPN.) The last JA4 segment differs between
curl_cffi and Playwright even though both are Chrome-like, so exact-hash matching would be brittle.

## Caveats
- Heuristics, not an allow-list: a custom client could replay a Chrome-shaped hello and pass.
- Impersonation profiles age: the profile must track a real browser release.
- The edge sees only the first connection hello; resumption and multiple hosts are out of scope.
