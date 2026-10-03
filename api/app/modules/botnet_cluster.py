"""Botnet clustering: fingerprint clusters that spread across IPs after being flagged (LOW).

Mechanism: one automation framework driven from many IPs presents the SAME transport
fingerprint everywhere (TLS JA4, HTTP/2 string, header order). Grouping requests by that tuple
reveals a distributed bot; once the group is known to be abusive, every new IP that joins it is
suspect without further evidence.

How real Akamai uses it (audit report ``docs/research/akamai-audit-2026-10.md`` section 2.14,
LOW-MEDIUM, unverified detail): Akamai's analytics have a "Botnet ID" dimension and its product
brief describes a "catapult algorithm" that shares a newly detected bot across all customers
"within minutes". The clustering features, thresholds and propagation are not public; this
module is a LAB APPROXIMATION of that network effect on one server, and it ships behind the
``botnet_cluster`` feature flag (LOW, default off) as well as being disabled by default.

How the lab simulates it:
* cluster key = sha256(JA4 | H2 fingerprint | lowercased header order)[:16].
* ``cluster:ips:{key}`` keeps the distinct client IPs seen in the last ``LAB_CLUSTER_WINDOW_MIN``
  minutes (default 10).
* The cluster is marked bad (``cluster:bad:{key}``) when this module observes the same key at a
  high rate: at least ``LAB_CLUSTER_BAD_RATE`` hits in one minute (default 60), from any IPs.
* A request whose cluster is marked bad AND spans at least ``LAB_CLUSTER_MIN_IPS`` distinct IPs
  (default 3) within the window is FAIL 70 "inherits botnet cluster flag". Otherwise PASS.

How a client passes: do not share one fingerprint across many IPs at a high rate, or vary the
fingerprint per exit IP. Real browsers of one release also share a fingerprint, so a real
deployment needs extra features (canvas hash etc.) to avoid merging them; this lab keeps it
simple and the high-rate gate is the only protection against that false positive.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from collections.abc import Callable
from typing import ClassVar

from app.contract import Confidence, DetectionModule, FlagSpec, RequestContext, Signal, Verdict

_clock: Callable[[], float] = time.time
DEFAULT_MIN_IPS = 3
DEFAULT_WINDOW_MIN = 10
DEFAULT_BAD_RATE = 60  # hits per minute on one cluster
MAX_TRACKED_IPS = 50


def _int_env(name: str, default: int) -> int:
    try:
        return max(1, int(os.environ.get(name, default)))
    except ValueError:
        return default


def cluster_key(ctx: RequestContext) -> str:
    order = ",".join(h.lower() for h in ctx.header_order)
    raw = "|".join((ctx.ja4, ctx.h2_fingerprint, order))
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


class BotnetClusterModule(DetectionModule):
    slug = "botnet_cluster"
    title = "Botnet fingerprint clustering"
    description = (
        "Groups requests by (JA4, H2, header order); a cluster marked bad at high rate flags "
        "every new IP that joins it. Lab approximation (LOW, flag-gated)."
    )
    category = "network"
    default_enabled = False
    confidence = Confidence.LOW
    flags: ClassVar[list[FlagSpec]] = [
        FlagSpec(
            name="botnet_cluster",
            description=(
                "UNVERIFIED lab approximation of Akamai's botnet clustering / network effect: "
                "flag IPs joining a fingerprint cluster that was marked bad at high rate."
            ),
            confidence=Confidence.LOW,
            default=False,
            source="audit report 2.14 (Botnet ID dimension; catapult algorithm, brief 10/2023)",
        )
    ]

    async def evaluate(self, ctx: RequestContext) -> Signal:
        if not ctx.flag("botnet_cluster"):
            return self.signal(
                Verdict.SKIP, 0, "Flag botnet_cluster is off (LOW confidence, unverified)"
            )
        if not (ctx.ja4 or ctx.h2_fingerprint) or ctx.store is None:
            return self.signal(Verdict.SKIP, 0, "No transport fingerprint to cluster on")
        store, now = ctx.store, _clock()
        key = cluster_key(ctx)
        min_ips = _int_env("LAB_CLUSTER_MIN_IPS", DEFAULT_MIN_IPS)
        window = _int_env("LAB_CLUSTER_WINDOW_MIN", DEFAULT_WINDOW_MIN) * 60
        bad_rate = _int_env("LAB_CLUSTER_BAD_RATE", DEFAULT_BAD_RATE)

        seen: dict[str, float] = {}
        raw = await store.get(f"cluster:ips:{key}")
        if raw:
            try:
                seen = {ip: float(ts) for ip, ts in json.loads(raw).items()}
            except (ValueError, AttributeError):
                seen = {}
        seen = {ip: ts for ip, ts in seen.items() if now - ts <= window}
        seen[ctx.client_ip] = now
        if len(seen) > MAX_TRACKED_IPS:
            seen = dict(sorted(seen.items(), key=lambda kv: kv[1])[-MAX_TRACKED_IPS:])
        await store.set(f"cluster:ips:{key}", json.dumps(seen), ttl=window)

        hits = await store.incr(f"cluster:hits:{key}:{int(now // 60)}", ttl=120)
        if hits >= bad_rate:
            await store.set(f"cluster:bad:{key}", "1", ttl=window)
        bad = await store.get(f"cluster:bad:{key}") == "1"

        d = {
            "cluster": key, "cluster_ips": len(seen), "cluster_bad": bad,
            "hits_this_minute": hits, "min_ips": min_ips, "bad_rate_per_min": bad_rate,
            "window_min": window // 60, "confidence_note": "LOW: lab approximation",
        }
        if bad and len(seen) >= min_ips:
            return self.signal(
                Verdict.FAIL, 70,
                f"Inherits botnet cluster flag: {len(seen)} IPs share fingerprint {key} "
                "that was marked bad at high rate (lab approximation, unverified)",
                **d,
            )
        if bad:
            return self.signal(
                Verdict.PASS, 0,
                f"Cluster {key} is marked bad but spans only {len(seen)} IP(s) (< {min_ips})", **d,
            )
        return self.signal(Verdict.PASS, 0, "Fingerprint cluster not flagged", **d)
