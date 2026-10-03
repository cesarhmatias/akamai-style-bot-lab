"""TLS ClientHello fingerprint (JA3 / JA4) consistency, era markers and extension order.

Mechanism: the TLS handshake is visible before any HTTP byte. Python ``ssl``/OpenSSL, Go's
``crypto/tls`` and curl+OpenSSL produce hellos no browser emits, so a spoofed ``User-Agent`` is
exposed immediately. Chrome additionally changes its hello every few weeks, which gives
version "era" markers.

How real Akamai uses it (audit report ``docs/research/akamai-audit-2026-10.md``):
* TLS is one of three passive layers and the layers are correlated to expose spoofed
  User-Agents (2017 white paper, section 1.2 case 1) [HIGH]; JA4 is exposed to the origin,
  ``TLS_FINGERPRINT`` is a client-list type and ``tls-fingerprint`` a rate-control identifier
  (2026 API docs) [HIGH]; "browser impersonation detection" is advertised [HIGH].
* Era markers (4588, ALPS 17613, ML-DSA) come from Chromium docs and curl_cffi issue
  trackers, not from Akamai: they are what a version-consistency check CAN use [HIGH for
  4588/ALPS, MEDIUM for ML-DSA: one issue plus client-library PRs].
* Akamai has not published whether it uses a non-permuted extension order or "JA4 never seen
  in real traffic" as signals [MEDIUM, lab approximation]. Akamai does say a bot found at one
  customer joins its known-bot library for all customers within minutes.

How this lab simulates it, per request (details carry a per-check ``confidence``):
* family classification (HIGH): structural heuristics that survive Chrome's per-connection
  extension permutation (ALPS 17513/17613, compress_certificate 27, ECH 65037, GREASE; cipher
  prefix: Chrome/BoringSSL 4865,4866,4867; OpenSSL 3: 4866,4867,4865; Go: Chrome prefix without
  ALPS; Firefox/NSS: 4865,4867,4866 plus delegated_credentials 34 / record_size_limit 28;
  Safari/WebKit: Chrome prefix + compress_certificate but NO ALPS, NO ECH and legacy CBC/3DES
  tail ``...-53-47-49160-49170-10``, JA4 family ``t13d2014h2_a09f3c656075_*``). Compared with
  the UA family; iOS browsers all use WebKit so they count as Safari.
* era markers (:func:`chrome_tls_era`, reused by ``version_consistency``): group 4588 (0x11EC,
  X25519MLKEM768) => Chrome 131+; Kyber 25497 (0x6399) => <= 130; ALPS 17613 => 133+; ALPS
  17513 => <= 132; ML-DSA sigalgs 0x0904/0x0905/0x0906 inside a Chrome-shaped hello => 150+
  (MEDIUM: Go 1.27 also sends ML-DSA, so it only counts together with the other Chrome marks).
* extension-order signal (MEDIUM): the edge sends ``x-tls-exts`` (raw order) and ``x-tls-conn``
  (per-connection id). The store remembers the order per ``(client_ip, ja4)``; a Chrome-family
  hello whose order repeats identically over >= 3 DISTINCT connections is WARN 25 (Chrome 110+
  shuffles on every connection).
* rarity (MEDIUM): a Chrome UA with a well-formed JA4 outside the small
  :data:`KNOWN_CHROME_JA4` table is WARN 10, as a cheap stand-in for "fingerprint never seen
  in real traffic". The table is a vendor-database snapshot (Scrapfly, 2026-10) and goes stale
  as Chrome now ships every two weeks (since Chrome 153, 2026-09-08), so the score is low.

How a client passes: use a real, current browser (or an impersonation profile that is current).
Note the harness's curl_cffi ``chrome131`` profile is about 23 majors old and sends the legacy
ALPS 17513, so it passes THIS module but loses on ``version_consistency`` if its UA is newer.

Limits: reconstructed fixtures, not live captures; Safari 26 and Chrome 155+ values unverified.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from app.contract import Confidence, DetectionModule, RequestContext, Signal, Verdict

# Illustrative examples only (not used for matching except KNOWN_CHROME_JA4 below).
# Chrome JA4 per release range: audit report 1.2 case 1 (Scrapfly JA4 DB + Clearcote, MEDIUM).
KNOWN_FINGERPRINTS: dict[str, dict[str, str]] = {
    "chrome-ja4-120-131": {"ja4": "t13d1516h2_8daaf6152771_02713d6af862", "family": "chrome"},
    "chrome-ja4-133-149": {"ja4": "t13d1516h2_8daaf6152771_d8a2da3f94cd", "family": "chrome"},
    "chrome-ja4-152-154": {"ja4": "t13d1517h2_8daaf6152771_cb7bf5808d99", "family": "chrome"},
    "safari-ja4-16-18": {"ja4": "t13d2014h2_a09f3c656075_e7c285222651", "family": "safari"},
    "firefox-ja4": {"ja4": "t13d1717h2_5b57614c22b0_3cbfd9057e0d", "family": "firefox"},
    "python-urllib3-ja4": {"ja4": "t13d1812h1_85036bcba153_375ca2c5e164", "family": "openssl"},
    "curl-openssl-ja4": {"ja4": "t13d3112h2_e8f1e7e78f70_b26ce05498bb", "family": "openssl"},
    "go-ja4": {"ja4": "t13d1312h2_f57a46bbacb6_ab7e3b40a677", "family": "go"},
}

# Rarity table: Chrome JA4 values (about 120-131, 133-149, 152-154). Snapshot, goes stale.
KNOWN_CHROME_JA4 = frozenset(
    v["ja4"] for k, v in KNOWN_FINGERPRINTS.items() if k.startswith("chrome-ja4-")
)
JA4_WELL_FORMED = re.compile(r"^[tq][0-9a-z]{9}_[0-9a-f]{12}_[0-9a-f]{12}$")
# Extension-order tracking (MEDIUM): distinct connections with an identical order -> WARN.
ORDER_REPEAT_WARN = 3
ORDER_TTL = 3600
ORDER_SCORE = 25
RARITY_SCORE = 10

KYBER_GROUP = "25497"  # 0x6399, X25519Kyber768Draft00 (Chrome 124-130)
MLKEM_GROUP = "4588"  # 0x11EC, X25519MLKEM768 (Chrome 131+)
MLDSA_SIGALGS = frozenset({"0904", "0905", "0906"})

GREASE = {n for n in range(0x0A0A, 0xFAFB, 0x1010)}
ALPS_EXTS = {"17513", "17613"}
CHROME_CIPHER_PREFIX = ("4865", "4866", "4867")
OPENSSL_CIPHER_PREFIX = ("4866", "4867", "4865")
FIREFOX_CIPHER_PREFIX = ("4865", "4867", "4866")
ECH_EXT = "65037"
# Safari 16-18 (macOS + iOS) JA4 cipher-suite hash (middle JA4 part): Scrapfly JA4 DB.
SAFARI_JA4_CIPHER_HASH = "a09f3c656075"
# WebKit still offers 3DES (0x000a = 10) and the ECDHE CBC-SHA1 suites; no other
# mainstream stack that shares Chrome's TLS 1.3 prefix does.
SAFARI_LEGACY_TAIL = ("49160", "49170", "10")


def _parse_ja3(ja3: str) -> tuple[list[str], set[str]]:
    parts = ja3.split(",")
    ciphers = [c for c in parts[1].split("-") if c] if len(parts) > 1 else []
    exts = {e for e in parts[2].split("-") if e} if len(parts) > 2 else set()
    ciphers = [c for c in ciphers if int(c) not in GREASE]
    return ciphers, exts - {str(g) for g in GREASE}


def classify_tls(ja3: str, ja4: str, grease_header: str | None, exts_header: str | None) -> dict:
    """Return {family, evidence}; family in chrome|firefox|safari|openssl|go|unknown."""
    ciphers, exts = _parse_ja3(ja3) if ja3 else ([], set())
    if exts_header:
        exts |= {e for e in re.split(r"[,-]", exts_header) if e.isdigit()}
    prefix = tuple(ciphers[:3])
    grease = (grease_header or "").strip().lower() in {"1", "true", "yes"}
    evidence: list[str] = []
    ja4_alpn = ja4[8:10] if len(ja4) >= 10 and ja4[0] in "tq" else ""
    chrome_marks = 0
    if grease:
        chrome_marks += 1
        evidence.append("GREASE present")
    if exts & ALPS_EXTS:
        chrome_marks += 2
        evidence.append("ALPS extension")
    if "27" in exts:
        chrome_marks += 1
        evidence.append("compress_certificate")
    if "65037" in exts:
        chrome_marks += 1
        evidence.append("ECH grease")
    if prefix == CHROME_CIPHER_PREFIX:
        chrome_marks += 1
        evidence.append("cipher prefix 4865,4866,4867")
    ja4_parts = ja4.split("_")
    safari_ja4 = (
        len(ja4_parts) == 3 and ja4_parts[0].startswith("t13")
        and ja4_parts[1] == SAFARI_JA4_CIPHER_HASH
    )
    safari_shape = (
        prefix == CHROME_CIPHER_PREFIX
        and tuple(ciphers[-3:]) == SAFARI_LEGACY_TAIL
        and "27" in exts
    )
    # Safari/WebKit: no ALPS and no ECH (Chrome has both), whether or not GREASE is sent.
    if (safari_shape or safari_ja4) and not exts & (ALPS_EXTS | {ECH_EXT}):
        return {
            "family": "safari",
            "evidence": ["WebKit hello: Chrome-style prefix, no ALPS/ECH, 3DES/CBC tail"]
            + (["JA4 t13d..._a09f3c656075"] if safari_ja4 else []),
        }
    firefox = bool(exts & {"34", "28"}) and prefix == FIREFOX_CIPHER_PREFIX
    if firefox:
        return {"family": "firefox", "evidence": ["delegated_credentials/record_size_limit"]}
    if chrome_marks >= 3 and (grease or exts & ALPS_EXTS or "27" in exts):
        return {"family": "chrome", "evidence": evidence}
    if prefix == OPENSSL_CIPHER_PREFIX or ja4_alpn in {"00", "h1"}:
        return {"family": "openssl", "evidence": ["OpenSSL-style cipher order / no GREASE"]}
    if prefix == CHROME_CIPHER_PREFIX and not exts & ALPS_EXTS:
        return {"family": "go", "evidence": ["Go-style hello: no GREASE, no ALPS"]}
    return {"family": "unknown", "evidence": evidence}


def ua_family(ua: str) -> str:
    low = ua.lower()
    # iOS/iPadOS rule: Apple requires every iOS browser (CriOS, FxiOS, EdgiOS, ...) to
    # use WebKit's network stack, so they all present a Safari/WebKit ClientHello and
    # must be treated as the "safari" family regardless of the browser brand token.
    if re.search(r"crios/|fxios/|edgios/|iphone|ipad|ipod", low):
        return "safari"
    if "firefox/" in low:
        return "firefox"
    if "chrome/" in low or "chromium/" in low or "headlesschrome" in low or "edg/" in low:
        return "chrome"
    if "safari/" in low:
        return "safari"
    if re.search(r"python|requests|urllib|aiohttp|httpx|curl|go-http|wget|java|okhttp", low):
        return "tool"
    return "unknown"


@dataclass
class TlsEra:
    """Chrome release window implied by passive TLS markers (inclusive bounds, None = unknown)."""

    min_major: int | None = None
    max_major: int | None = None
    evidence: list[str] = field(default_factory=list)
    confidence: dict[str, str] = field(default_factory=dict)  # marker -> "high" | "medium"
    # (bound, evidence, tier) per marker, so callers can attribute a violated bound precisely.
    lows: list[tuple[int, str, str]] = field(default_factory=list)
    highs: list[tuple[int, str, str]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "min": self.min_major, "max": self.max_major,
            "evidence": self.evidence, "confidence": self.confidence,
        }


def _split(value: str | None) -> list[str]:
    return [x.strip() for x in (value or "").split(",") if x.strip()]


@dataclass
class TlsView:
    """Era-relevant TLS fields of one request (edge headers with JA3 fallbacks)."""

    groups: list[str]
    sigalgs: list[str]
    alps: str  # "17613" | "17513" | "none" | "" (unknown)
    exts_order: str
    conn_id: str


def tls_view(ctx: RequestContext) -> TlsView:
    """Collect era-relevant fields. ``x-tls-groups`` / ``x-tls-alps`` fall back to the JA3 string
    (curves and extension list, GREASE already removed) when the edge headers are absent."""
    groups = _split(ctx.header("x-tls-groups"))
    if not groups and ctx.ja3.count(",") >= 3:
        groups = [g for g in ctx.ja3.split(",")[3].split("-") if g]
    alps = (ctx.header("x-tls-alps") or "").strip()
    if not alps:
        _, exts = _parse_ja3(ctx.ja3) if ctx.ja3 else ([], set())
        exts |= {e for e in re.split(r"[,-]", ctx.header("x-tls-exts") or "") if e.isdigit()}
        alps = "17613" if "17613" in exts else "17513" if "17513" in exts else ""
    return TlsView(
        groups=[g for g in groups if g != "grease"],
        sigalgs=[x.lower() for x in _split(ctx.header("x-tls-sigalgs"))],
        alps=alps,
        exts_order=(ctx.header("x-tls-exts") or "").strip(),
        conn_id=(ctx.header("x-tls-conn") or "").strip(),
    )


def chrome_tls_era(view: TlsView, *, chrome_shaped: bool) -> TlsEra:
    """Chrome version window from TLS era markers (audit report 1.2 case 1 and 2.2).

    ``chrome_shaped`` must come from :func:`classify_tls` (family == "chrome"); the ML-DSA
    marker is only trusted then, because Go 1.27 also advertises ML-DSA (MEDIUM tier).
    """
    era = TlsEra()

    def lo(v: int, why: str, tier: str) -> None:
        era.min_major = max(era.min_major or 0, v)
        era.lows.append((v, why, tier))
        era.evidence.append(why)
        era.confidence[why] = tier

    def hi(v: int, why: str, tier: str) -> None:
        era.max_major = min(era.max_major or 999, v)
        era.highs.append((v, why, tier))
        era.evidence.append(why)
        era.confidence[why] = tier

    if MLKEM_GROUP in view.groups:
        lo(131, "group 4588 (X25519MLKEM768) => Chrome 131+", "high")
    if KYBER_GROUP in view.groups and MLKEM_GROUP not in view.groups:
        hi(130, "group 25497 (Kyber draft) => Chrome <= 130", "high")
    if view.alps == "17613":
        lo(133, "ALPS 17613 => Chrome 133+", "high")
    elif view.alps == "17513":
        hi(132, "ALPS 17513 => Chrome <= 132", "high")
    if chrome_shaped and MLDSA_SIGALGS & set(view.sigalgs):
        lo(150, "ML-DSA sigalgs (0904/0905/0906) in Chrome-shaped hello => Chrome 150+", "medium")
    return era


class TlsFingerprintModule(DetectionModule):
    slug = "tls_fingerprint"
    title = "TLS fingerprint (JA3/JA4)"
    description = (
        "Compares the TLS ClientHello family with the User-Agent, derives Chrome era markers "
        "and watches for a non-permuted extension order."
    )
    category = "passive"
    confidence = Confidence.HIGH  # family + 4588/ALPS era; extra checks carry their own tier

    async def _extension_order(
        self, ctx: RequestContext, view: TlsView
    ) -> tuple[int, bool]:
        """Remember the raw extension order per (client_ip, ja4); return (distinct connections
        that presented the SAME order, whether a new order was just observed)."""
        if not (view.exts_order and view.conn_id and ctx.store is not None):
            return 0, False
        key = f"tlsorder:{ctx.client_ip}:{ctx.ja4}"
        raw = await ctx.store.get(key)
        rec: dict[str, Any] = {"order": view.exts_order, "conns": []}
        changed = False
        if raw:
            try:
                prev = json.loads(raw)
                if prev.get("order") == view.exts_order:
                    rec = prev
                else:
                    changed = True  # a different order was observed: Chrome-like permutation
            except (ValueError, AttributeError):
                pass
        if view.conn_id not in rec["conns"]:
            rec["conns"] = [*rec["conns"], view.conn_id][-10:]
        await ctx.store.set(key, json.dumps(rec), ttl=ORDER_TTL)
        return len(rec["conns"]), changed

    async def evaluate(self, ctx: RequestContext) -> Signal:
        if not ctx.ja3 and not ctx.ja4:
            return self.signal(
                Verdict.WARN, 40,
                "No TLS fingerprint: request did not arrive through the TLS edge",
            )
        tls = classify_tls(
            ctx.ja3, ctx.ja4, ctx.header("x-ja3-grease"), ctx.header("x-tls-exts")
        )
        fam = tls["family"]
        uaf = ua_family(ctx.user_agent)
        brands = ctx.header("sec-ch-ua") or ""
        view = tls_view(ctx)
        era = chrome_tls_era(view, chrome_shaped=fam == "chrome")
        d: dict[str, Any] = {
            "tls_family": fam, "ua_family": uaf, "evidence": tls["evidence"],
            "ja4": ctx.ja4, "sec_ch_ua": brands,
            "era": era.as_dict() if fam == "chrome" else None,
            "check_confidence": {"family": "high", "era_markers": "high",
                                 "ml_dsa": "medium", "extension_order": "medium",
                                 "ja4_rarity": "medium"},
        }
        if fam == "chrome":
            if uaf == "chrome" or (uaf in {"unknown"} and brands):
                return await self._chrome_pass(ctx, view, uaf, d)
            return self.signal(
                Verdict.FAIL, 85, f"Chrome TLS stack but User-Agent claims {uaf}", **d
            )
        if fam == "safari":
            if uaf == "safari":
                return self.signal(Verdict.PASS, 0, "Safari/WebKit TLS matches Safari UA", **d)
            return self.signal(
                Verdict.FAIL, 85, f"Safari/WebKit TLS stack but User-Agent claims {uaf}", **d
            )
        if fam == "firefox":
            if uaf == "firefox" and not brands:
                return self.signal(Verdict.PASS, 0, "Firefox-like TLS matches Firefox UA", **d)
            return self.signal(
                Verdict.FAIL, 85, f"Firefox TLS stack but User-Agent claims {uaf}", **d
            )
        if fam in {"openssl", "go"}:
            if uaf in {"chrome", "firefox", "safari"}:
                return self.signal(
                    Verdict.FAIL, 85,
                    f"{fam} TLS stack cannot be a real {uaf} browser (UA spoofing)", **d,
                )
            return self.signal(Verdict.FAIL, 75, f"Non-browser TLS stack ({fam})", **d)
        return self.signal(Verdict.WARN, 40, "Unrecognised TLS fingerprint", **d)

    async def _chrome_pass(
        self, ctx: RequestContext, view: TlsView, uaf: str, d: dict[str, Any]
    ) -> Signal:
        """Chrome hello with a Chrome UA: PASS unless the MEDIUM-tier lab signals fire."""
        warns: list[tuple[int, str]] = []
        repeats, changed = await self._extension_order(ctx, view)
        d["extension_order"] = {"distinct_connections_same_order": repeats, "changed": changed}
        if repeats >= ORDER_REPEAT_WARN:
            warns.append((
                ORDER_SCORE,
                f"Chrome-family hello with an identical extension order on {repeats} "
                "connections (Chrome permutes it every connection) [medium]",
            ))
        if (
            uaf == "chrome" and JA4_WELL_FORMED.match(ctx.ja4)
            and ctx.ja4 not in KNOWN_CHROME_JA4
        ):
            warns.append((
                RARITY_SCORE,
                f"JA4 {ctx.ja4} is not in the known Chrome fingerprint table [medium]",
            ))
            d["ja4_known"] = False
        if not warns:
            return self.signal(Verdict.PASS, 0, "Chrome-like TLS matches Chrome UA", **d)
        score = max(sc for sc, _ in warns)
        return self.signal(Verdict.WARN, score, "; ".join(r for _, r in warns), **d)
