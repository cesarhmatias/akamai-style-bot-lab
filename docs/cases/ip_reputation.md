# `ip_reputation`: rate controls, penalty box and client-reputation categories

Category: network · Module: `api/app/modules/ip_reputation.py` · Protected URL: `/protected/ip_reputation`
· Default: on · Module tier: **HIGH** (rate controls and penalty box; reputation scores are MEDIUM)

## What it is

Per-client request velocity, a "penalty box" that keeps denying a client after it tripped a rate control, and a
coarse behaviour-derived reputation score per attack category.

## How real Akamai uses it

From Akamai's rate-policy API, client-reputation docs and penalty-box blog (report §1.2 case 10, [P]):

- A rate policy has an `averageThreshold` (allowed hits per second during any two-minute interval) and a
  `burstThreshold` (the same during a 1-5 s `burstWindow`). Client identifiers include `ip`, `ip-useragent`,
  `tls-fingerprint`, `api-key`, `cookie:<name>`, `request-header:<name>` and `query-string:<name>`.
- `penaltyBoxDuration` runs from `TEN_MINUTES` to `TWENTY_FOUR_HOURS`: a client that triggered a deny keeps getting the
  action for that long.
- Client Reputation scores IPs per category `DOSATCK`, `SCANTL`, `WEBATCK` and `WEBSCRP` on a 1-10 scale; Akamai's
  docs recommend acting at 8 or higher. It is derived from behaviour across Akamai's whole network. Customers also
  upload their own IP, ASN and TLS-fingerprint client lists.
- Whether Bot Manager applies a generic hosting-ASN penalty is **not** public.

## Confidence

| Sub-feature | Tier | Flag (default) |
|---|---|---|
| Burst and 2-minute average rate controls, penalty box, identifiers | HIGH | none; identifier flags below |
| Identifier `ip-useragent` | HIGH | `rate_id_ip_useragent` (off) |
| Identifier `tls-fingerprint` (JA4 shared across IPs) | HIGH | `rate_id_tls_fingerprint` (off) |
| Reputation categories derived from local behaviour | MEDIUM (approximation: Akamai's scores are network-wide) | none |
| Hosting/datacenter ASN penalty | LOW: unverified, vendor-sourced assumption | `hosting_asn_penalty` (off) |
| Customer client list (`LAB_BAD_CIDRS`) | HIGH concept | env only |

## How the lab simulates it

Only requests that evaluate this module count (`/`, `/protected/all`, `/protected/ip_reputation`).

- **Burst**: hits per second over `LAB_RATE_BURST_WINDOW` seconds (1-5, default 5) from per-second buckets
  (`rate:{cid}:s:{sec}`); triggers above `LAB_RATE_BURST_THRESHOLD` (default 20 hits/s, so more than 100 hits in 5 s).
- **Average**: hits per second over 120 s from 10 s buckets (`rate:{cid}:b:{bucket}`); triggers above
  `LAB_RATE_AVG_THRESHOLD` (default 2 hits/s, so more than 240 hits in 2 minutes).
- **Identifier**: `LAB_RATE_IDENTIFIER` = `ip` (default) | `ip-useragent` | `tls-fingerprint`; the two flags override it
  from the dashboard.
- **Penalty box**: a trigger returns BLOCK 100 and writes `penalty:{cid}`; the client keeps getting BLOCK for
  `LAB_PENALTY_BOX_SECONDS` (default 600, Akamai's minimum; clamped to 24 h). Values below 600 s are a lab convenience
  for tests and the harness, not an Akamai value (`details["penalty_below_akamai_minimum"]`). `POST /api/reset` clears
  the box.
- **Reputation** (1-10, threshold 8, `repcat:<CAT>:{ip}`, 600 s window): `WEBSCRP` = ceil(protected hits / 20) (160 hits
  gives 8), `WEBATCK` = 4 per attack-looking path or query, `DOSATCK` = 4 per rate-control trigger, `SCANTL` = 1 per 404
  probe (fed by the catch-all route). A top score of 8 or more is FAIL 75; 5-7 is WARN 30.
- **Lists**: a non-private IP in `LAB_BAD_CIDRS` (a customer client list) is WARN 40. With `hosting_asn_penalty` on, an address in the
  small built-in datacenter table is WARN 40, labelled an assumption. Private, loopback and link-local addresses count
  as residential.
- Otherwise: pass 0, "Clean IP, normal request rate".

## How a scraper passes it

Keep a human-like request rate from a normal address and avoid probing. A sequential harness run of 40-80 requests
per client stays well under the defaults; a tight loop does not.

## Observed results

All three harness clients pass: "Clean IP, normal request rate" (pass 0). The runner resets state between clients and
each client sends well under the rate controls.

## Limits and caveats

- Reputation here comes only from this server's own counters; Akamai's comes from its network.
- The datacenter table is illustrative (TEST-NET, a few cloud ranges) and off by default (LOW).
- Counters are read-modify-write over a minimal KV store: fine for one client at a time, not atomic across processes.
- `LAB_RATE_FAIL` and `LAB_RATE_BLOCK` (the old fixed 10 s windows that counted only scored requests) no longer exist.
