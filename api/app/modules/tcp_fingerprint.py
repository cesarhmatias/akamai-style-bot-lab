"""TCP/IP (p0f-style) passive fingerprint: DEFERRED stub.

Mechanism: the SYN a client sends carries OS-stack traits (initial TTL, window size, MSS, window
scale, TCP option order, DF bit) that identify the operating system independently of anything
written in HTTP. Comparing the inferred OS with the UA's platform exposes, for instance, a Linux
scraper claiming Windows or macOS.

How real Akamai uses it (audit report ``docs/research/akamai-audit-2026-10.md`` section 2.12,
LOW): the 2017 Akamai white paper lists TCP/IP fingerprinting as one of three passive layers and
shows that correlating it with TLS and HTTP/2 exposes proxies; Content Protector's 2024 press
release says it evaluates how the client connects "at the different layers of the OSI model".
Akamai does not document which TCP fields it scores today (unverified, vendor-sourced detail).

Status in the lab: NOT IMPLEMENTED. This module is a documented stub that always returns SKIP
with the reason "deferred: needs raw SYN capture; Docker TTL caveat". It stays behind the
``tcp_fingerprint`` flag (LOW, default off) and is disabled by default. Why it is deferred:

1. The SYN is invisible to the Go edge. ``net`` and ``crypto/tls`` only hand over an
   already-established stream; reading the SYN needs raw capture (AF_PACKET or libpcap/eBPF) with
   the ``NET_RAW`` capability, i.e. a privileged capture path and, under the project's "no cgo, no
   libpcap" rule, a hand-written AF_PACKET parser.
2. Docker distorts what would be captured. Published ports go through the bridge's NAT/userland
   proxy, which terminates and re-originates the connection and rewrites the observable TTL
   (every hop decrements it), so an inferred "initial TTL" would describe Docker, not the client.
   A trustworthy capture requires ``network_mode: host`` or capture on the client side of the
   NAT, which the compose topology deliberately avoids.

A future implementation would add ``TCP_FP=1`` and ``cap_add: [NET_RAW]`` to the edge, emit
``x-tcp-fp: ttl:win:mss:wscale:opts`` and have this module compare the inferred OS with the UA
platform. Until that capture exists, enabling this module only shows the SKIP reason.
"""

from __future__ import annotations

from typing import ClassVar

from app.contract import Confidence, DetectionModule, FlagSpec, RequestContext, Signal, Verdict

DEFERRED_REASON = "deferred: needs raw SYN capture; Docker TTL caveat"


class TcpFingerprintModule(DetectionModule):
    slug = "tcp_fingerprint"
    title = "TCP/IP fingerprint (deferred)"
    description = (
        "p0f-style SYN fingerprint vs UA platform. Deferred stub: needs raw SYN capture "
        "and Docker rewrites the TTL."
    )
    category = "passive"
    default_enabled = False
    confidence = Confidence.LOW
    flags: ClassVar[list[FlagSpec]] = [
        FlagSpec(
            name="tcp_fingerprint",
            description=(
                "UNVERIFIED, vendor-sourced: compare the TCP SYN fingerprint with the UA "
                "platform. Currently a stub: raw SYN capture is not implemented."
            ),
            confidence=Confidence.LOW,
            default=False,
            source="audit report 2.12 (2017 white paper; current Akamai use not public)",
        )
    ]

    async def evaluate(self, ctx: RequestContext) -> Signal:
        return self.signal(
            Verdict.SKIP, 0, DEFERRED_REASON, implemented=False,
            flag_enabled=ctx.flag("tcp_fingerprint"),
            needs=["edge raw SYN capture (NET_RAW, AF_PACKET)", "non-NAT network path"],
            observed_header=ctx.header("x-tcp-fp"),
        )
