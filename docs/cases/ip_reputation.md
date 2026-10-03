# Case 10: `ip_reputation` (rate and address space)

Category: network. Module: `api/app/modules/ip_reputation.py`. Protected URL: `/protected/ip_reputation`.

## Mechanism
Per-IP velocity and the kind of network the client comes from (residential vs hosting/cloud).

## How real Akamai uses it
Public knowledge: Akamai scores client IPs with reputation data and request velocity, trusting residential
and mobile ranges more than datacenter or proxy ranges. The lab has no reputation feed: it uses a rate
counter and a tiny illustrative CIDR table.

## How THIS server detects it
For `ctx.client_ip` (the edge's `x-client-ip`):
- **Rate**: fixed 10 s windows (`rate:{ip}:{window}`) blended with the previous window.
  `> 45` in 10 s -> fail 70; `> 90` -> **block** 100. Override with `LAB_RATE_FAIL` / `LAB_RATE_BLOCK`.
- **Datacenter**: IP inside a CIDR in `DATACENTER_CIDRS` (TEST-NET-1/2 and illustrative AWS, GCP, Azure,
  DigitalOcean prefixes) plus `LAB_BAD_CIDRS` -> warn 40. Private, loopback and link-local addresses are
  treated as residential.
- **Reputation**: `rep:{ip}` accumulates strikes (+20 per rate fail, +40 per block) with a 60 s half-life;
  `>= 20` while not bursting -> warn 30.
- Unparseable IP -> warn 30. Otherwise pass 0 "Clean IP, normal request rate".

## How a client passes here
Keep a human-like request rate from a normal address. A whole matrix run per client stays far below 45
requests per 10 s.

## Observed (real run)
All three clients pass 0, "Clean IP, normal request rate" (Docker bridge source `172.20.0.1`, treated as
private). Playwright showed `rate_10s` about 1.6.

## Caveats
- Local-only: from localhost you cannot be in a datacenter range unless you set `LAB_BAD_CIDRS`.
- To see it fail, loop `/protected/ip_reputation` more than 45 times in 10 s.
- Only requests that evaluate this module count toward the rate: `/`, `/protected/all` and `/protected/ip_reputation`. `/protected/<other case>`, control-plane and `/akam/*` calls do not.
