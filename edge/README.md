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

Any client-supplied header with these names is stripped first (anti-spoofing; covered by
`TestForwardStripsSpoofedHeaders`).

| header | example |
|---|---|
| `x-ja3` | `771,4865-4866-...,0-23-65281-...,29-23-24,0` (GREASE removed) |
| `x-ja3-hash` | `0149f47eabf9a20d0893e2a44e5a6323` (md5 of `x-ja3`) |
| `x-ja4` | `t13d3112h2_e8f1e7e78f70_b26ce05bbdd6` (FoxIO JA4) |
| `x-ja3-grease` | `1` if any GREASE value was in the ClientHello, else `0` (Chrome: 1, curl/Python: 0) |
| `x-tls-exts` | `grease,0,23,65281,10,11,...` raw extension ids in wire order, GREASE as `grease` |
| `x-tls-groups` | `grease,4588,29,23,24` supported_groups (ext 10), decimal, wire order, GREASE as `grease` |
| `x-tls-sigalgs` | `0904,0905,0906,0403,0804,...` signature_algorithms (ext 13), 4-digit hex, wire order |
| `x-tls-alpn` | `h2,http/1.1` ALPN protocols the client offered, wire order |
| `x-tls-alps` | `17613`, `17513` or `none`: which ALPS codepoint (if any) the hello carries |
| `x-tls-conn` | `3f9a1c0b77de` opaque per-connection id (first 12 hex of sha256 of the client random); lets the API count distinct connections |
| `x-h2-fingerprint` | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` (h2 only; Akamai 2017 paper format) |
| `x-h2-fingerprint-labeled` | `S[1:65536;2:0;4:6291456;6:262144]\|WU[15663105]\|P[0]\|PS[m,a,s,p]` (h2 only; lab notation, see below) |
| `x-h2-headers-priority` | `1:0:256` (`exclusive:dep:weight` of the first HEADERS frame, weight = wire byte + 1) or `none` (h2 only) |
| `x-header-order` | h1: `Host,User-Agent,Accept`; h2: `user-agent,accept` (names in wire order, no pseudo-headers) |
| `x-http-proto` | `h2` or `http/1.1` |
| `x-client-ip` | `172.20.0.1` (TCP peer address) |

### Era-marker fields (audit report 1.2 case 1, 2.2)

`x-tls-groups`, `x-tls-sigalgs`, `x-tls-alpn` and `x-tls-alps` are raw observations; the edge
does not interpret them. The API's `tls_fingerprint` and `version_consistency` modules read them:

| marker | meaning |
|---|---|
| group `4588` (0x11EC, X25519MLKEM768) | Chrome 131+ |
| group `25497` (0x6399, Kyber draft) | pre-131 Chrome era |
| ALPS `17613` / `17513` | Chrome 133+ / Chrome <= 132 |
| sigalgs starting `0904,0905,0906` (ML-DSA) | Chrome 150+ (only together with other Chrome marks: Go 1.27 also sends ML-DSA) |

### H2 fingerprint format

`x-h2-fingerprint` is the string format of Akamai's 2017 paper (Shuster, "Passive Fingerprinting
of HTTP/2 Clients"): `S[;]|WU|P[,]|PS[,]`, that is SETTINGS `id:value` pairs in order of
appearance joined by `;`, the first connection-level WINDOW_UPDATE increment, one
`stream:exclusive:dep:weight` tuple per PRIORITY frame joined by `,` (or `0`), and the
pseudo-header letters (m=:method a=:authority s=:scheme p=:path). The paper writes an **absent
WINDOW_UPDATE as `00`**, and the edge does the same (many modern tools print `0`; the API
accepts both). For HTTP/1.1 the h2 headers are omitted.

`x-h2-fingerprint-labeled` (`S[...]|WU[...]|P[...]|PS[...]`) is a **lab convenience notation
only**. The brackets are the paper's way of describing list separators; they are NOT part of
Akamai's literal string, and no Akamai system is known to emit or consume this labeled form.
Nothing in the API scores it.

`x-h2-headers-priority` is an extra signal **outside** the Akamai string. Chrome carries its
priority in the HEADERS-frame priority fields (and, since Chrome 124, in the RFC 9218 `priority`
header); the edge records the first HEADERS frame's exclusive/dependency/weight, or `none`.

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

## Not implemented: TCP/IP (SYN) fingerprint

Audit report 2.12 describes a p0f-style TCP fingerprint (TTL, window, MSS, window scale, option
order). It needs the raw SYN, which `crypto/tls` and `net` never expose (it requires `NET_RAW` and
AF_PACKET/pcap), and Docker's bridge NAT rewrites the TTL seen by the container. The edge therefore
emits no `x-tcp-fp`; the API's `tcp_fingerprint` module is a documented stub (default off).

## Build and test

    docker build edge/            # runs go vet + go test in the build stage
    docker run --rm -v $PWD/edge:/src -w /src golang:1.23 go test ./...
