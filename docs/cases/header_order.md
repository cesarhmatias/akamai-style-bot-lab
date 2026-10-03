# Case 3: `header_order` (header set, order and casing)

Category: passive. Module: `api/app/modules/header_order.py`. Protected URL: `/protected/header_order`.

## Mechanism
Browsers send a stack-specific, stable set of headers in a stable order (Chrome: `sec-ch-ua*`,
`upgrade-insecure-requests`, `user-agent`, `accept`, `sec-fetch-*`, `accept-encoding`, `accept-language`,
`priority`). HTTP libraries use dict order and omit browser-only headers. HTTP/2 requires lower-case names.

## How real Akamai uses it
Header presence/order consistency with the claimed browser is a commonly cited bot-manager signal, together
with the fact that servers behind a normalising framework cannot see it. No Akamai-specific thresholds are
public; this lab's numbers are its own.

## How THIS server detects it
The edge records the names in wire order (original casing, no pseudo-headers) in `x-header-order`.
The module compares the observed known headers with two Chrome baselines (`navigation`, `fetch`) using a
longest-common-subsequence ratio and takes the better one. Ignored: `host`, `content-length`,
`content-type`, `x-lab-client`, `connection`.

Score = `round((1 - similarity) * 60)` plus: 25 missing any of `sec-fetch-site/mode/dest`; 15 missing
`accept-language`; 10 Chrome UA without `sec-ch-ua`; 50 uppercase names on h2; 30 python-requests
telltales (python UA, or two of: `Accept: */*` without sec-fetch-mode, `gzip, deflate` without `br`,
a `Connection` header). Capped at 100. `< 20` pass, `20-49` warn, `>= 50` fail. No order data: warn 40.

## How a client passes here
Send the browser's exact header set in its order. `curl_cffi` impersonation does it for the headers it owns;
`clients/curl_cffi_client.py` adds `Accept`, `Accept-Language`, `Sec-Fetch-*` and `Upgrade-Insecure-Requests`.
Playwright does it natively.

## Observed (real run)
| client | verdict | details |
|---|---|---|
| naive | fail 85 | missing sec-fetch-* headers; missing accept-language; python-requests telltales: python UA, Accept: */*, accept-encoding without br, Connection header. Wire order: `Host,User-Agent,Accept-Encoding,Accept,Connection,X-Lab-Client,Cookie` |
| curl_cffi | pass 0 | similarity 1.0 against `navigation` |
| Playwright | pass 5 | similarity 0.92 against `navigation` (the lab's `X-Lab-Client` header is ignored; `accept-language` sits before `accept` in Chromium's order) |

## Caveats
- The baselines are Chrome-only and static; Firefox/Safari users would score lower.
- On h2 the edge reuses the first stream's order for later streams on the same connection.
- Order can be mimicked by anyone who controls the raw request writer.
