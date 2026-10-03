# Case 2: `h2_fingerprint` (HTTP/2 connection fingerprint)

Category: passive. Module: `api/app/modules/h2_fingerprint.py`. Protected URL: `/protected/h2_fingerprint`.

## Mechanism
HTTP/2 stacks differ in connection-level choices that no header exposes: the SETTINGS frame (ids, values,
order), the initial connection WINDOW_UPDATE, PRIORITY frames and the pseudo-header order
(`:method :authority :scheme :path`). Chrome sends `:method, :authority, :scheme, :path` (`m,a,s,p`);
Firefox sends `m,p,a,s`.

## How real Akamai uses it
Akamai published the technique ("Passive Fingerprinting of HTTP/2 Clients", Black Hat EU 2017) and the
fingerprint string format `SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO_ORDER`, which this lab reuses.
Browsers must speak h2 over TLS, so an h1 client with a browser UA is already suspicious.

## How THIS server detects it
The edge sniffs the preface, SETTINGS, WINDOW_UPDATE, PRIORITY and first HEADERS frames and injects
`x-h2-fingerprint` (empty for HTTP/1.1). Chrome's value is
`1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`. The module parses it and compares per component with
the profile of the browser the UA claims (chrome, firefox, safari; unknown UAs are compared to Chrome):

| component | points when different |
|---|---|
| SETTINGS ids / order | 30 |
| SETTINGS values | 25 |
| WINDOW_UPDATE | 20 |
| pseudo-header order | 25 |

Score = sum (cap 100), `>= 50` fail, otherwise warn, `0` pass. Special cases: HTTP/1.1 with browser UA is
fail 80, HTTP/1.1 with any other UA is fail 70, malformed fingerprint is fail 80. `details.breakdown` shows
the per-component points.

## How a client passes here
Speak h2 with a browser-identical SETTINGS/WINDOW_UPDATE/pseudo-order: Playwright, or `curl_cffi`
impersonation. A plain `requests` client cannot (no h2 at all).

## Observed (real run)
| client | proto | fingerprint | verdict |
|---|---|---|---|
| naive | http/1.1 | (empty) | fail 70, "HTTP/1.1 client, not a browser stack" |
| curl_cffi | h2 | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | pass 0, "H2 matches chrome profile" |
| Playwright | h2 | same | pass 0, "H2 matches chrome profile" |

## Caveats
- The profiles are single, hard-coded values (the Chrome one observed here); real deployments track many
  versions and platforms.
- Any h2 library that copies the four values passes; this checks a mimic, not authenticity.
- Fingerprints are per connection; the edge reads them once per connection.
