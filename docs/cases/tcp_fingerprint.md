# `tcp_fingerprint`: TCP/IP (p0f-style) passive fingerprint (deferred stub)

Category: passive · Module: `api/app/modules/tcp_fingerprint.py` · Protected URL: `/protected/tcp_fingerprint`
· Default: **off** (module disabled and flag `tcp_fingerprint` off) · Module tier: **LOW** · Status: **not implemented**

## What it is

The SYN a client sends carries operating-system traits: initial TTL, window size, MSS, window scale, TCP option order,
DF bit. Comparing the inferred OS with the UA's platform exposes, for instance, a Linux scraper claiming Windows or
macOS.

## How real Akamai uses it

The 2017 Akamai white paper lists TCP/IP fingerprinting as one of three passive layers and shows that correlating it
with TLS and HTTP/2 exposes proxies; Content Protector's 2024 press release says it evaluates how the client
connects "at the different layers of the OSI model" (report §2.12, [P]). Akamai does **not** document which TCP fields
it scores today.

## Confidence

Tier **LOW** (report §2.12, §3.1: "2017 paper plus vendor claims"). Unverified, vendor-sourced detail; flag
`tcp_fingerprint` (default off).

## How the lab simulates it

It does not. `evaluate()` always returns SKIP with the reason "deferred: needs raw SYN capture; Docker TTL caveat" and
`details` listing what is missing (`implemented: false`, the flag state, `needs`, and the value of an optional
`x-tcp-fp` header, which nothing emits). Why it is deferred:

1. The SYN is invisible to the Go edge. `net` and `crypto/tls` hand over an established stream; reading the SYN needs raw
   capture (AF_PACKET, libpcap or eBPF) with the `NET_RAW` capability and, under the project's no-cgo rule, a
   hand-written AF_PACKET parser.
2. Docker distorts what would be captured. Published ports go through the bridge's NAT and userland proxy, which
   re-originates the connection and rewrites the observable TTL, so an inferred "initial TTL" would describe Docker, not
   the client. A trustworthy capture needs `network_mode: host` or a capture on the client side of the NAT, which the
   compose topology avoids.

A future implementation would add `TCP_FP=1` and `cap_add: [NET_RAW]` to the edge, emit `x-tcp-fp:
ttl:win:mss:wscale:opts` and compare the inferred OS with the UA platform.

## How a scraper passes it

There is nothing to pass: the module only reports that it is deferred.

## Observed results

Not in the matrix ("documented stub: always SKIP"; listed under "Off by default (LOW confidence)" in `RESULTS.md`).

## Limits and caveats

Listed as a deferred feature in [KNOWN_GAPS](../KNOWN_GAPS.md). `edge/README.md` repeats the reasoning; the edge emits no
`x-tcp-fp`.
