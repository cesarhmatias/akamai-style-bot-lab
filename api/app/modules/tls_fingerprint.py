"""TLS ClientHello fingerprint (JA3 / JA4) consistency check.

What real Akamai does: Bot Manager fingerprints the TLS handshake at the edge and
compares the TLS stack with the claimed User-Agent. Python ``ssl``/OpenSSL, Go's
``crypto/tls`` and curl+OpenSSL all produce hellos that no browser emits, so a
spoofed ``User-Agent`` is exposed before a single header is read.

How this lab detects it: the Go edge injects ``x-ja3`` / ``x-ja4`` (and optionally
``x-ja3-grease`` / ``x-tls-exts`` extras). We do NOT match an exact hash. Chrome >= 110
randomises (permutes) the order of TLS extensions on every connection, so the classic
JA3 string/MD5 differs per connection; JA4 fixes this by *sorting* extensions before
hashing. We therefore use structural heuristics that survive permutation: the set of
extensions (ALPS 17513/17613, compress_certificate 27, ECH 65037, GREASE), and the
cipher-suite prefix (Chrome/BoringSSL: 4865,4866,4867 first; OpenSSL 3: 4866,4867,4865;
Go: 4865,4866,4867 then ECDHE-GCM without ALPS; Firefox/NSS: 4865,4867,4866 plus
delegated_credentials 34 and record_size_limit 28; Safari/WebKit: Chrome's cipher
prefix and compress_certificate 27 but NO ALPS, NO ECH and legacy CBC/3DES suites at the
tail, ``...-53-47-49160-49170-10``; JA4 family ``t13d2014h2_a09f3c656075_*``).

How a client passes: use a real browser or an impersonating client (``curl_cffi``
with ``impersonate="chrome"``) so the actual handshake is Chrome's. Changing headers
alone can never fix this signal.
"""

from __future__ import annotations

import re

from app.contract import DetectionModule, RequestContext, Signal, Verdict

# Illustrative examples only (not used for matching; see module docstring).
KNOWN_FINGERPRINTS: dict[str, dict[str, str]] = {
    "chrome-ja4": {"ja4": "t13d1516h2_8daaf6152771_d8a2da3f94cd", "family": "chrome"},
    "firefox-ja4": {"ja4": "t13d1717h2_5b57614c22b0_3cbfd9057e0d", "family": "firefox"},
    "python-urllib3-ja4": {"ja4": "t13d1812h1_85036bcba153_375ca2c5e164", "family": "openssl"},
    "curl-openssl-ja4": {"ja4": "t13d3112h2_e8f1e7e78f70_b26ce05498bb", "family": "openssl"},
    "go-ja4": {"ja4": "t13d1312h2_f57a46bbacb6_ab7e3b40a677", "family": "go"},
}

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


class TlsFingerprintModule(DetectionModule):
    slug = "tls_fingerprint"
    title = "TLS fingerprint (JA3/JA4)"
    description = "Compares the TLS ClientHello family with the User-Agent and Sec-CH-UA claims."
    category = "passive"

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
        d = {"tls_family": fam, "ua_family": uaf, "evidence": tls["evidence"],
             "ja4": ctx.ja4, "sec_ch_ua": brands}
        if fam == "chrome":
            if uaf == "chrome" or (uaf in {"unknown"} and brands):
                return self.signal(Verdict.PASS, 0, "Chrome-like TLS matches Chrome UA", **d)
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
