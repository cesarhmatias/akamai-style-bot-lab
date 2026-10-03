# edge: fingerprinting TLS reverse proxy

Go reverse proxy that terminates TLS (ALPN `h2` + `http/1.1`), computes
transport-level fingerprints and forwards requests to `$UPSTREAM` over plain
HTTP/1.1 with the fingerprints injected as `x-*` headers. Local lab use only.

## Why an edge is required

TLS and HTTP/2 framing terminate before the ASGI app. FastAPI/uvicorn only sees
a decoded request: it never sees the ClientHello (cipher/extension order,
GREASE), the HTTP/2 SETTINGS / WINDOW_UPDATE / PRIORITY frames, or HPACK
header order. Python HTTP servers also normalise header casing and order. Real
bot managers sit at the CDN edge for this reason; this proxy plays that role.

## Configuration

| env | default | meaning |
|---|---|---|
| `LISTEN` | `:8443` | TLS listen address |
| `UPSTREAM` | `http://api:8000` | upstream base URL |
| `CERT_FILE` / `KEY_FILE` | `/certs/tls.crt`, `/certs/tls.key` | optional mounted cert; otherwise an in-memory self-signed localhost cert is generated at startup |

`/edge -healthcheck` completes a TLS handshake against the local listener and
exits 0/1. Responses are streamed and flushed immediately (SSE works).

## Injected headers

Any client-supplied header with these names is stripped first (anti-spoofing).

| header | example |
|---|---|
| `x-ja3` | `771,4865-4866-...,0-23-65281-...,29-23-24,0` (GREASE removed) |
| `x-ja3-hash` | `0149f47eabf9a20d0893e2a44e5a6323` (md5 of `x-ja3`) |
| `x-ja4` | `t13d3112h2_e8f1e7e78f70_b26ce05bbdd6` (FoxIO JA4) |
| `x-ja3-grease` | `1` if any GREASE value was in the ClientHello, else `0` (Chrome: 1, curl/Python: 0) |
| `x-tls-exts` | `grease,0,23,65281,10,11,...` raw extension ids in wire order, GREASE as `grease` |
| `x-h2-fingerprint` | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` (h2 only) |
| `x-h2-fingerprint-labeled` | `S[1:65536;2:0;4:6291456;6:262144]\|WU[15663105]\|P[0]\|PS[m,a,s,p]` (h2 only) |
| `x-header-order` | h1: `Host,User-Agent,Accept`; h2: `user-agent,accept` (names in wire order, no pseudo-headers) |
| `x-http-proto` | `h2` or `http/1.1` |
| `x-client-ip` | `172.20.0.1` (TCP peer address) |

H2 fingerprint format: `SETTINGS id:value in order | first WINDOW_UPDATE on
stream 0 | PRIORITY frames as stream:exclusive:dep:weight (or 0) | pseudo-header
order (m=:method a=:authority s=:scheme p=:path)`. For HTTP/1.1 the two h2
headers are omitted (empty).

## Notes and limits

- The ClientHello is captured by wrapping the raw `net.Conn` before `crypto/tls`
  reads it, then parsed independently.
- For h2 the edge reads the preface, SETTINGS, WINDOW_UPDATE, PRIORITY and the
  first HEADERS block (HPACK-decoded) and replays those bytes to
  `golang.org/x/net/http2`. The fingerprint is per connection. Header order
  for h2 comes from the first stream's HEADERS and is reused for later streams
  on the same connection (x/net/http2 does not expose per-stream raw order).
- For HTTP/1.1 the raw header block is sniffed per request (a read starting with
  a request line begins a new request), preserving original casing.

## Build and test

    docker build edge/            # runs go vet + go test in the build stage
    docker run --rm -v $PWD/edge:/src -w /src golang:1.23 go test ./...
