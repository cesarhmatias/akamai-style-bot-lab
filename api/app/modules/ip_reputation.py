"""IP reputation: Akamai-style rate controls, penalty box and client-reputation categories.

Mechanism: per-client request velocity, a "penalty box" that keeps denying a client after it
tripped a rate control, and a coarse behaviour-derived reputation.

How real Akamai uses it (audit report ``docs/research/akamai-audit-2026-10.md`` section 1.2
case 10, HIGH, Akamai rate-policy API 2026 / client-reputation docs / penalty-box blog):
* A rate policy has an ``averageThreshold`` (allowed hits per second during any two-minute
  interval) and a ``burstThreshold`` (hits per second during a 1-5 s ``burstWindow``).
* Client identifiers include ``ip``, ``ip-useragent`` and ``tls-fingerprint`` (and others).
* ``penaltyBoxDuration`` runs from ``TEN_MINUTES`` to ``TWENTY_FOUR_HOURS``: a client that
  triggered a deny keeps getting the action for that long.
* Client Reputation scores IPs per category ``DOSATCK``, ``SCANTL``, ``WEBATCK`` and ``WEBSCRP``
  on a 1-10 scale; Akamai's docs recommend acting at 8 or higher. Akamai derives it from
  behaviour observed across its whole network; the lab has no such feed.
* Customers add their own IP/ASN/TLS-fingerprint client lists (HIGH). Whether Bot Manager itself
  applies a generic hosting-ASN penalty is NOT public.

How the lab simulates it, for the client identified per request:
* Burst: hits/s over ``LAB_RATE_BURST_WINDOW`` seconds (1-5, default 5) from per-second store
  buckets; trigger when above ``LAB_RATE_BURST_THRESHOLD`` (default 20 hits/s, i.e. > 100 hits in
  5 s). Average: hits/s over 2 minutes from 10 s buckets; trigger above
  ``LAB_RATE_AVG_THRESHOLD`` (default 2 hits/s, i.e. > 240 hits in 2 min). Only requests that
  evaluate this module count (``/``, ``/protected/all``, ``/protected/ip_reputation``). A
  sequential harness run of ~40-80 requests per client therefore passes, a tight loop does not.
* Identifier ``LAB_RATE_IDENTIFIER`` = ``ip`` (default) | ``ip-useragent`` | ``tls-fingerprint``
  (the JA4 alone, shared across IPs as in Akamai); the flags ``rate_id_ip_useragent`` /
  ``rate_id_tls_fingerprint`` override it from the dashboard.
* Penalty box: a trigger denies (BLOCK 100) and keeps denying that client for
  ``LAB_PENALTY_BOX_SECONDS`` (default 600 = Akamai's 10 min minimum, clamped to 24 h at most).
  Values below 600 s are a LAB CONVENIENCE for tests and the harness, not an Akamai value;
  ``details["penalty_below_akamai_minimum"]`` says so. ``POST /api/reset`` clears the box.
* Reputation categories (lab-derived from LOCAL behaviour, 1-10, threshold 8, MEDIUM: Akamai's
  real scores are network-wide): ``WEBSCRP`` from many protected-resource hits (ceil(hits/20),
  10-minute window; 160 hits => 8), ``WEBATCK`` from attack-looking paths/queries (4 per hit),
  ``DOSATCK`` from rate-control triggers (4 per trigger), ``SCANTL`` from 404 probes (1 per
  probe; this module cannot see response codes, so it only reads the counter that the
  response layer may bump via :func:`record_scan_probe`). Score >= 8 => FAIL 75; 5-7 => WARN 30.
* Hosting-ASN penalty: the small built-in datacenter CIDR table is an ASSUMPTION (LOW, not
  verified against Akamai) and only applies when flag ``hosting_asn_penalty`` is on (default
  off). ``LAB_BAD_CIDRS`` models a customer-configured IP client list and always applies.
* Private, loopback, link-local and docker ranges count as residential for the lab.

How a client passes: keep a human-like request rate from a normal address and avoid probing.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import re
import time
from collections.abc import Callable
from typing import Any, ClassVar

from app.contract import Confidence, DetectionModule, FlagSpec, RequestContext, Signal, Verdict

BURST_WINDOW_DEFAULT = 5
BURST_THRESHOLD_DEFAULT = 20.0  # hits per second
AVG_WINDOW = 120  # seconds (Akamai: any two-minute interval)
AVG_BUCKET = 10
AVG_THRESHOLD_DEFAULT = 2.0  # hits per second
PENALTY_MIN = 600  # Akamai TEN_MINUTES
PENALTY_MAX = 86400  # Akamai TWENTY_FOUR_HOURS
REPUTATION_THRESHOLD = 8
REPUTATION_WARN_AT = 5
REPUTATION_TTL = 600
CATEGORIES = ("DOSATCK", "SCANTL", "WEBATCK", "WEBSCRP")
IDENTIFIERS = ("ip", "ip-useragent", "tls-fingerprint")

DATACENTER_CIDRS = [
    "192.0.2.0/24",  # TEST-NET-1 (illustrative "datacenter")
    "198.51.100.0/24",  # TEST-NET-2
    "3.0.0.0/9",  # AWS (illustrative)
    "34.64.0.0/10",  # Google Cloud (illustrative)
    "20.0.0.0/11",  # Azure (illustrative)
    "138.68.0.0/16",  # DigitalOcean (illustrative)
]
_ATTACK = re.compile(
    r"\.\./|<script|union\s+select|or\s+1\s*=\s*1|/etc/passwd|\bexec\(|%3cscript", re.I
)

_clock: Callable[[], float] = time.time


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


def _networks(cidrs: list[str]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    out: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for c in cidrs:
        try:
            out.append(ipaddress.ip_network(c.strip(), strict=False))
        except ValueError:
            continue
    return out


def _match(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, cidrs: list[str]) -> str | None:
    for net in _networks(cidrs):
        if ip.version == net.version and ip in net:
            return str(net)
    return None


def datacenter_match(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    """Built-in hosting table plus ``LAB_BAD_CIDRS`` (kept for callers of the old API)."""
    return _match(ip, DATACENTER_CIDRS + _customer_cidrs())


def _customer_cidrs() -> list[str]:
    return [c for c in os.environ.get("LAB_BAD_CIDRS", "").split(",") if c.strip()]


def penalty_seconds() -> tuple[int, bool]:
    """(duration, below_akamai_minimum). Default 600; clamped to at most 24 h."""
    raw = os.environ.get("LAB_PENALTY_BOX_SECONDS")
    if raw is None:
        return PENALTY_MIN, False
    try:
        secs = int(float(raw))
    except ValueError:
        return PENALTY_MIN, False
    secs = max(1, min(secs, PENALTY_MAX))
    return secs, secs < PENALTY_MIN


async def record_scan_probe(store: Any, client_ip: str) -> None:
    """Bump the SCANTL counter (e.g. from the response layer on a 404). Optional hook."""
    await store.incr(f"repcat:SCANTL:{client_ip}", ttl=REPUTATION_TTL)


def category_scores(counts: dict[str, int]) -> dict[str, int]:
    """Lab-derived 1-10 category scores from local counters (0 = nothing observed)."""
    def clamp(v: int) -> int:
        return min(10, v) if v > 0 else 0

    return {
        "DOSATCK": clamp(4 * counts.get("DOSATCK", 0)),
        "SCANTL": clamp(counts.get("SCANTL", 0)),
        "WEBATCK": clamp(4 * counts.get("WEBATCK", 0)),
        "WEBSCRP": clamp(math.ceil(counts.get("WEBSCRP", 0) / 20)),
    }


class IpReputationModule(DetectionModule):
    slug = "ip_reputation"
    title = "IP reputation and rate controls"
    description = (
        "Burst and 2-minute average rate controls with a penalty box, selectable client "
        "identifier, and lab-derived client-reputation categories."
    )
    category = "network"
    confidence = Confidence.HIGH  # rate controls/penalty box; reputation scores are MEDIUM
    flags: ClassVar[list[FlagSpec]] = [
        FlagSpec(
            name="hosting_asn_penalty",
            description=(
                "ASSUMPTION: penalise addresses in the built-in hosting/datacenter CIDR table "
                "(WARN 40). Whether Bot Manager applies a generic hosting-ASN penalty is not "
                "public; customers do add ASN/IP lists themselves."
            ),
            confidence=Confidence.LOW,
            default=False,
            source="audit report 1.2 case 10 (hosting-ASN penalty not public)",
        ),
        FlagSpec(
            name="rate_id_ip_useragent",
            description="Rate-control client identifier = IP + User-Agent (Akamai ip-useragent).",
            confidence=Confidence.HIGH,
            default=False,
            source="audit report 1.2 case 10 (rate policy API)",
        ),
        FlagSpec(
            name="rate_id_tls_fingerprint",
            description="Rate-control client identifier = JA4 TLS fingerprint (tls-fingerprint).",
            confidence=Confidence.HIGH,
            default=False,
            source="audit report 1.2 case 10 (rate policy API)",
        ),
    ]

    # -- configuration ---------------------------------------------------------------------
    @staticmethod
    def identifier(ctx: RequestContext) -> str:
        if ctx.flag("rate_id_tls_fingerprint"):
            return "tls-fingerprint"
        if ctx.flag("rate_id_ip_useragent"):
            return "ip-useragent"
        env = os.environ.get("LAB_RATE_IDENTIFIER", "ip").strip().lower()
        return env if env in IDENTIFIERS else "ip"

    @staticmethod
    def client_id(ctx: RequestContext, identifier: str) -> str:
        if identifier == "tls-fingerprint" and ctx.ja4:
            return f"ja4:{ctx.ja4}"
        if identifier == "ip-useragent":
            ua = hashlib.sha1(ctx.user_agent.encode(), usedforsecurity=False).hexdigest()[:10]
            return f"{ctx.client_ip}|{ua}"
        return ctx.client_ip

    # -- rate controls ---------------------------------------------------------------------
    @staticmethod
    async def _hits(store: Any, cid: str, now: float, window: int) -> tuple[float, float]:
        """Count this hit; return (burst hits/s over `window` s, average hits/s over 2 min)."""
        sec = int(now)
        await store.incr(f"rate:{cid}:s:{sec}", ttl=AVG_WINDOW + 10)
        bucket = int(now // AVG_BUCKET)
        await store.incr(f"rate:{cid}:b:{bucket}", ttl=AVG_WINDOW + 2 * AVG_BUCKET)
        burst = 0
        for i in range(window):
            raw = await store.get(f"rate:{cid}:s:{sec - i}")
            burst += int(raw) if raw else 0
        total = 0
        for i in range(AVG_WINDOW // AVG_BUCKET):
            raw = await store.get(f"rate:{cid}:b:{bucket - i}")
            total += int(raw) if raw else 0
        return burst / window, total / AVG_WINDOW

    async def _penalty_left(self, ctx: RequestContext, cid: str, now: float) -> float:
        raw = await ctx.store.get(f"penalty:{cid}")
        if not raw:
            return 0.0
        try:
            return max(0.0, float(json.loads(raw)["until"]) - now)
        except (ValueError, KeyError, TypeError):
            return 0.0

    # -- reputation ------------------------------------------------------------------------
    async def _reputation(self, ctx: RequestContext) -> dict[str, int]:
        ip, store = ctx.client_ip, ctx.store
        if ctx.path.startswith("/protected/"):
            await store.incr(f"repcat:WEBSCRP:{ip}", ttl=REPUTATION_TTL)
        probe = ctx.path + " " + " ".join(ctx.query.values())
        if _ATTACK.search(probe):
            await store.incr(f"repcat:WEBATCK:{ip}", ttl=REPUTATION_TTL)
        counts: dict[str, int] = {}
        for cat in CATEGORIES:
            raw = await store.get(f"repcat:{cat}:{ip}")
            counts[cat] = int(raw) if raw else 0
        return category_scores(counts)

    async def evaluate(self, ctx: RequestContext) -> Signal:
        try:
            ip = ipaddress.ip_address(ctx.client_ip)
        except ValueError:
            return self.signal(Verdict.WARN, 30, "Unparseable client IP", ip=ctx.client_ip)
        now = _clock()
        identifier = self.identifier(ctx)
        cid = self.client_id(ctx, identifier)
        window = max(1, min(5, int(_env_float("LAB_RATE_BURST_WINDOW", BURST_WINDOW_DEFAULT))))
        burst_thr = _env_float("LAB_RATE_BURST_THRESHOLD", BURST_THRESHOLD_DEFAULT)
        avg_thr = _env_float("LAB_RATE_AVG_THRESHOLD", AVG_THRESHOLD_DEFAULT)
        box, below_min = penalty_seconds()
        d: dict[str, Any] = {
            "ip": ctx.client_ip, "identifier": identifier, "client_id": cid,
            "burst_window_s": window, "burst_threshold": burst_thr, "avg_threshold": avg_thr,
            "penalty_box_s": box, "penalty_below_akamai_minimum": below_min,
            "reputation_threshold": REPUTATION_THRESHOLD,
        }

        left = await self._penalty_left(ctx, cid, now)
        if left > 0:
            return self.signal(
                Verdict.BLOCK, 100,
                f"Client in penalty box ({left:.0f}s remaining) after a rate-control deny",
                penalty_remaining_s=round(left), **d,
            )

        burst, avg = await self._hits(ctx.store, cid, now, window)
        d["burst_rate"], d["avg_rate"] = round(burst, 2), round(avg, 3)
        trigger = ""
        if burst > burst_thr:
            trigger = f"burst {burst:.1f} hits/s over {window}s > {burst_thr:g}"
        elif avg > avg_thr:
            trigger = f"average {avg:.2f} hits/s over 2 min > {avg_thr:g}"
        if trigger:
            until = now + box
            await ctx.store.set(
                f"penalty:{cid}", json.dumps({"until": until, "why": trigger}), ttl=box
            )
            await ctx.store.incr(f"repcat:DOSATCK:{ctx.client_ip}", ttl=REPUTATION_TTL)
            return self.signal(
                Verdict.BLOCK, 100,
                f"Rate control: {trigger}; penalty box {box}s", **d,
            )

        scores = await self._reputation(ctx)
        d["reputation_categories"] = scores
        top_cat, top = max(scores.items(), key=lambda kv: kv[1])
        if top >= REPUTATION_THRESHOLD:
            return self.signal(
                Verdict.FAIL, 75,
                f"Client reputation {top_cat} {top}/10 (>= {REPUTATION_THRESHOLD}, lab-derived)",
                **d,
            )

        private = ip.is_private or ip.is_loopback or ip.is_link_local
        custom = None if private else _match(ip, _customer_cidrs())
        if custom:
            return self.signal(
                Verdict.WARN, 40, f"Address in customer client list {custom} (LAB_BAD_CIDRS)",
                cidr=custom, **d,
            )
        if not private and ctx.flag("hosting_asn_penalty"):
            net = _match(ip, DATACENTER_CIDRS)
            if net:
                return self.signal(
                    Verdict.WARN, 40,
                    f"Hosting range {net} (ASSUMPTION flag hosting_asn_penalty, LOW)",
                    cidr=net, assumption=True, **d,
                )
        if top >= REPUTATION_WARN_AT:
            return self.signal(
                Verdict.WARN, 30, f"Elevated client reputation {top_cat} {top}/10", **d
            )
        return self.signal(Verdict.PASS, 0, "Clean IP, normal request rate", **d)
