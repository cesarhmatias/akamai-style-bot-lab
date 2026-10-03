"""HTTP/2 connection fingerprint check (format from Akamai's 2017 paper).

Mechanism: the client's SETTINGS frame (ids and values, in order), the connection-level
WINDOW_UPDATE, PRIORITY frames and the pseudo-header order are fixed per HTTP/2 stack, so they
identify the browser (or library) independently of anything written in headers.

How real Akamai uses it: Akamai published this technique (Shuster, "Passive Fingerprinting of
HTTP/2 Clients", 2017; audit report section 1.2 case 2) [HIGH for the format, which the paper
defines; the paper is old, but nothing indicates the idea was dropped]. The literal string is
``S[;]|WU|P[,]|PS[,]``: SETTINGS ``id:value`` pairs in order of appearance joined by ``;``, the
WINDOW_UPDATE increment (``00`` when the frame is absent), one ``stream:exclusive:dep:weight``
tuple per PRIORITY frame (``0`` if none; weights print as wire byte + 1) and the pseudo-header
letters m/a/s/p. Example (Firefox 53, from the paper):
``1:65536;4:131072;5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1|m,p,a,s``.

How this lab simulates it: the edge emits that string in ``x-h2-fingerprint`` (absent
WINDOW_UPDATE as ``00`` per the paper; modern tools print ``0``, and this module accepts
``00``, ``0`` and ``-``). The canonical Akamai string is reported in ``details["akamai_string"]``.
The edge's ``x-h2-fingerprint-labeled`` (``S[..]|WU[..]|P[..]|PS[..]``) is only a lab convenience
notation: the brackets describe separators in the paper, they are NOT Akamai's format, and this
module does not read it. The string is parsed and compared per component against the profile of
the browser the User-Agent claims (Chrome, Firefox, Safari: macOS and iOS variants; every iOS
browser counts as Safari), with a breakdown in ``details``. HTTP/1.1 with a Chrome/Firefox/Safari
UA fails, because real browsers negotiate h2 over TLS. The first HEADERS frame priority
(``x-h2-headers-priority``) is only echoed in ``details``: it is outside the Akamai string and not
scored.

How a client passes: use an HTTP/2 stack that mimics the browser (``curl_cffi`` impersonate, or a
real browser).

Limits: profile values are 2025 captures (Chrome 136-154, Firefox 138, Safari 18.x; MEDIUM for
Safari, Safari 26 unverified); Firefox's old PRIORITY tree is no longer sent.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.contract import DetectionModule, RequestContext, Signal, Verdict


@dataclass(frozen=True)
class H2Profile:
    settings: dict[int, int]
    window_update: int
    pseudo: str


PROFILES: dict[str, H2Profile] = {
    "chrome": H2Profile({1: 65536, 2: 0, 4: 6291456, 6: 262144}, 15663105, "m,a,s,p"),
    "firefox": H2Profile({1: 65536, 2: 0, 4: 131072, 5: 16384}, 12517377, "m,p,a,s"),
    # Safari 18 (2024-26 values; the pre-2024 profile used WU 10485760 and m,s,p,a).
    # Id 9 = NO_RFC7540_PRIORITIES, id 8 = ENABLE_CONNECT_PROTOCOL (sent by iOS builds).
    "safari": H2Profile({2: 0, 3: 100, 4: 2097152, 9: 1}, 10420225, "m,s,a,p"),
    "safari-ios": H2Profile({2: 0, 3: 100, 4: 2097152, 8: 1, 9: 1}, 10420225, "m,s,a,p"),
}
# A Safari-claiming UA is compared with every WebKit profile and scored by the best match.
PROFILE_GROUPS: dict[str, tuple[str, ...]] = {"safari": ("safari", "safari-ios")}

# Points per component (sum = 100 cap).
W_SETTINGS_IDS = 30
W_SETTINGS_VALUES = 25
W_WINDOW_UPDATE = 20
W_PSEUDO = 25


def parse_h2(fp: str) -> dict | None:
    """Parse the fingerprint; None if malformed."""
    parts = fp.split("|")
    if len(parts) != 4:
        return None
    try:
        settings: list[tuple[int, int]] = []
        for item in parts[0].split(";"):
            if item:
                k, v = item.split(":")
                settings.append((int(k), int(v)))
        # Absent WINDOW_UPDATE: "00" in the Akamai paper, "0" in modern tools.
        wu = int(parts[1]) if parts[1] not in ("", "-") else 0
    except ValueError:
        return None
    pseudo = parts[3].replace(" ", "")
    return {"settings": settings, "window_update": wu, "priority": parts[2], "pseudo": pseudo}


def akamai_string(parsed: dict) -> str:
    """Canonical Akamai string; an absent WINDOW_UPDATE is written ``00`` as in the paper."""
    settings = ";".join(f"{k}:{v}" for k, v in parsed["settings"])
    wu = str(parsed["window_update"]) if parsed["window_update"] else "00"
    return f"{settings}|{wu}|{parsed['priority']}|{parsed['pseudo']}"


def compare(parsed: dict, prof: H2Profile) -> dict[str, int]:
    """Per-component deviation points vs a profile."""
    got = dict(parsed["settings"])
    order = [k for k, _ in parsed["settings"]]
    out = {"settings_ids": 0, "settings_values": 0, "window_update": 0, "pseudo_order": 0}
    if order != list(prof.settings):  # ids and their order
        out["settings_ids"] = W_SETTINGS_IDS
    common = set(got) & set(prof.settings)
    if common and any(got[k] != prof.settings[k] for k in common):
        out["settings_values"] = W_SETTINGS_VALUES
    if parsed["window_update"] != prof.window_update:
        out["window_update"] = W_WINDOW_UPDATE
    if parsed["pseudo"] != prof.pseudo:
        out["pseudo_order"] = W_PSEUDO
    return out


def claimed_browser(ua: str) -> str:
    low = ua.lower()
    # Every iOS browser (CriOS, FxiOS, EdgiOS, ...) runs on WebKit's network stack, so its
    # HTTP/2 connection looks like Safari's whatever the brand token says.
    if re.search(r"crios/|fxios/|edgios/|iphone|ipad|ipod", low):
        return "safari"
    if "firefox/" in low:
        return "firefox"
    if "chrome/" in low or "chromium/" in low or "edg/" in low:  # incl. HeadlessChrome
        return "chrome"
    if "safari/" in low:
        return "safari"
    return "other"


class H2FingerprintModule(DetectionModule):
    slug = "h2_fingerprint"
    title = "HTTP/2 fingerprint"
    description = "Checks HTTP/2 SETTINGS, WINDOW_UPDATE and pseudo-header order against the UA."
    category = "passive"

    async def evaluate(self, ctx: RequestContext) -> Signal:
        fp = ctx.h2_fingerprint.strip()
        claimed = claimed_browser(ctx.user_agent)
        if not fp:
            if claimed in {"chrome", "firefox", "safari"}:
                return self.signal(
                    Verdict.FAIL,
                    80,
                    "HTTP/1.1 with a browser UA: real browsers negotiate h2",
                    claimed=claimed,
                )
            return self.signal(Verdict.FAIL, 70, "HTTP/1.1 client, not a browser stack")
        parsed = parse_h2(fp)
        if parsed is None:
            return self.signal(Verdict.FAIL, 80, "Malformed HTTP/2 fingerprint", fp=fp)
        # Non-browser UA: compare to Chrome (the profile bots try to mimic).
        target = claimed if claimed in PROFILES else "chrome"
        scored = {
            name: compare(parsed, PROFILES[name]) for name in PROFILE_GROUPS.get(target, (target,))
        }
        best = min(scored, key=lambda n: sum(scored[n].values()))
        breakdown = scored[best]
        score = min(100, sum(breakdown.values()))
        d = {
            "profile": target, "variant": best, "breakdown": breakdown, "fp": fp,
            "akamai_string": akamai_string(parsed),
            "window_update_absent": parsed["window_update"] == 0,
        }
        if hp := ctx.header("x-h2-headers-priority"):
            d["headers_priority"] = hp
        if score == 0:
            if claimed == "other":
                return self.signal(Verdict.PASS, 0, "H2 matches Chrome profile", **d)
            return self.signal(Verdict.PASS, 0, f"H2 matches {target} profile", **d)
        verdict = Verdict.FAIL if score >= 50 else Verdict.WARN
        return self.signal(verdict, score, f"H2 deviates from {target} profile", **d)
