"""IP reputation: request-rate bursts and datacenter address space.

What real Akamai does: scores the client IP using a global reputation feed (known
proxies, hosting/cloud ASNs, IPs seen attacking other customers) and per-IP velocity.
Residential and mobile ranges are trusted; datacenter ranges and bursts are not.

How this lab detects it, per ``ctx.client_ip``:
* Rate: fixed 10 s windows in the store (``rate:{ip}:{window}``), blended with the
  previous window (sliding approximation). Above ``RATE_FAIL`` (45) scored requests in
  10 s -> FAIL 70; above ``RATE_BLOCK`` (90) -> BLOCK 100. The harness sends ~10-40
  requests per client in sequence, so a full run stays under 45 and passes; a tight
  burst loop fails. Override with env ``LAB_RATE_FAIL`` / ``LAB_RATE_BLOCK``.
* Datacenter: a small CIDR table (documentation ranges plus a few well-known cloud
  prefixes, for illustration; extend with env ``LAB_BAD_CIDRS=1.2.3.0/24,...``) -> WARN 40.
* Private, loopback, link-local and docker ranges count as residential for the lab.
* Reputation (``rep:{ip}``) records strikes (+20 per FAIL, +40 per BLOCK) that decay
  with a 60 s half-life; while it is >= 20 and the burst is over -> WARN 30.

How a client passes: come from a clean IP and keep the request rate human-like.
"""

from __future__ import annotations

import ipaddress
import json
import os
import time
from collections.abc import Callable

from app.contract import DetectionModule, RequestContext, Signal, Verdict

WINDOW = 10
RATE_FAIL = 45
RATE_BLOCK = 90
HALF_LIFE = 60.0
REP_WARN_AT = 20.0

DATACENTER_CIDRS = [
    "192.0.2.0/24",  # TEST-NET-1 (illustrative "datacenter")
    "198.51.100.0/24",  # TEST-NET-2
    "3.0.0.0/9",  # AWS (illustrative)
    "34.64.0.0/10",  # Google Cloud (illustrative)
    "20.0.0.0/11",  # Azure (illustrative)
    "138.68.0.0/16",  # DigitalOcean (illustrative)
]

_clock: Callable[[], float] = time.time


def _networks() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    cidrs = list(DATACENTER_CIDRS)
    cidrs += [c.strip() for c in os.environ.get("LAB_BAD_CIDRS", "").split(",") if c.strip()]
    out: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for c in cidrs:
        try:
            out.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            continue
    return out


def datacenter_match(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    for net in _networks():
        if ip.version == net.version and ip in net:
            return str(net)
    return None


class IpReputationModule(DetectionModule):
    slug = "ip_reputation"
    title = "IP reputation and rate"
    description = "Sliding-window request rate per IP plus a datacenter-range table."
    category = "network"

    async def _rep(self, ctx: RequestContext, now: float) -> float:
        raw = await ctx.store.get(f"rep:{ctx.client_ip}")
        if not raw:
            return 0.0
        try:
            d = json.loads(raw)
            return float(d["s"]) * 0.5 ** ((now - float(d["t"])) / HALF_LIFE)
        except (ValueError, KeyError, TypeError):
            return 0.0

    async def _strike(self, ctx: RequestContext, now: float, current: float, pts: int) -> None:
        val = json.dumps({"s": current + pts, "t": now})
        await ctx.store.set(f"rep:{ctx.client_ip}", val, ttl=600)

    async def evaluate(self, ctx: RequestContext) -> Signal:
        try:
            ip = ipaddress.ip_address(ctx.client_ip)
        except ValueError:
            return self.signal(Verdict.WARN, 30, "Unparseable client IP", ip=ctx.client_ip)
        now = _clock()
        fail_at = int(os.environ.get("LAB_RATE_FAIL", RATE_FAIL))
        block_at = int(os.environ.get("LAB_RATE_BLOCK", RATE_BLOCK))

        win = int(now // WINDOW)
        cur = await ctx.store.incr(f"rate:{ctx.client_ip}:{win}", ttl=WINDOW * 3)
        prev_raw = await ctx.store.get(f"rate:{ctx.client_ip}:{win - 1}")
        frac_left = 1 - (now % WINDOW) / WINDOW
        rate = cur + (int(prev_raw) * frac_left if prev_raw else 0)
        rep = await self._rep(ctx, now)
        d = {"rate_10s": round(rate, 1), "reputation": round(rep, 1), "ip": ctx.client_ip}

        if rate > block_at:
            await self._strike(ctx, now, rep, 40)
            return self.signal(Verdict.BLOCK, 100, f"Request burst: {rate:.0f}/10s", **d)
        if rate > fail_at:
            await self._strike(ctx, now, rep, 20)
            return self.signal(Verdict.FAIL, 70, f"High request rate: {rate:.0f}/10s", **d)

        net = None if ip.is_private or ip.is_loopback or ip.is_link_local else datacenter_match(ip)
        if net:
            return self.signal(Verdict.WARN, 40, f"Datacenter address range {net}", cidr=net, **d)
        if rep >= REP_WARN_AT:
            return self.signal(Verdict.WARN, 30, "Recent abusive behaviour (decaying)", **d)
        return self.signal(Verdict.PASS, 0, "Clean IP, normal request rate", **d)
