"""Account Protector style login risk (audit §2.10, tier MEDIUM).

Mechanism
    Judge a LOGIN by comparing it with what is already known about that account: devices,
    networks, locations and active hours the user was seen with before, plus properties of the
    identifier itself (disposable email domains). A familiar login is low risk; a new device on
    a new network that appears minutes after a login from far away is high risk.

How real Akamai uses it (report §2.10 and §2.9)
    Tier MEDIUM: Akamai's Account Protector brief (09/2024) lists user behavioral profiles
    ("previously observed locations, networks, devices, IP addresses, and activity time"),
    population profiles, source reputation, risk/trust/general indicators, email address and
    email domain intelligence including disposable domains, and actions that include a
    cryptographic and behavioral challenge and serve alternate content. The origin receives an
    ``Akamai-User-Risk`` header, observed as
    ``uuid=…;requestid=…;status=…;score=…;general=…;risk=…;trust=udbp:…|udfp:…|udop:…|ugp:FR|unp:12322|utp:weekday_3;allow=0;action=monitor``.
    The scoring model and the meaning of the codes are NOT public.

How the lab simulates it
    * Applies to ``POST /api/login`` only (``ctx.path``); every other transactional path is SKIP.
    * Per-username profile in the store (key hashed): seen /24 networks, UA families, JA4
      families, active hours, last network and time. The lab has no ASN or geo database; the
      IP prefix stands in for both (a /24 for "network", a /16 for "location").
    * Risk factors (lab weights): new device +25, new JA4 family +10, new network +20,
      impossible travel (different /16 within 5 minutes) +40, disposable email domain +35,
      unusual hour (after 5 logins) +10. Score = sum, capped at 100.
    * ``after_score`` learns the login into the profile only when the engine let it through
      (not deny/tarpit/challenge/serve_alternate) and the risk was below 40, so an attacker
      cannot poison a profile.
    * The signal carries ``details["user_risk"]``; the engine renders it as the
      ``Akamai-User-Risk`` origin header (``status``, ``general`` codes and the ``risk`` /
      ``trust`` abbreviations are LAB-DEFINED, loosely modelled on the observed example).

How a client passes it
    Log in from the user's usual device and network, with a real email domain.

Limits: no population profiles, no source reputation feed, no real geo/ASN.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from collections.abc import Callable
from typing import Any, ClassVar

from app.contract import (
    BLOCKING_ACTIONS,
    DETAIL_USER_RISK,
    Action,
    Confidence,
    DetectionModule,
    EndpointClass,
    RequestContext,
    ScoreReport,
    Signal,
    Verdict,
)

LOGIN_PATH = "/api/login"
PROFILE_TTL = 30 * 24 * 3600
TRAVEL_WINDOW = 300  # seconds
MAX_SEEN = 10
LEARN_BELOW = 40
DISPOSABLE_DOMAINS = frozenset(
    {
        "mailinator.com",
        "guerrillamail.com",
        "10minutemail.com",
        "tempmail.com",
        "yopmail.com",
        "trashmail.com",
        "throwawaymail.com",
        "sharklasers.com",
    }
)
W_NEW_DEVICE, W_NEW_JA4, W_NEW_NET, W_TRAVEL, W_DISPOSABLE, W_HOUR = 25, 10, 20, 40, 35, 10
NOT_LEARNED = frozenset(BLOCKING_ACTIONS | {Action.SERVE_ALTERNATE})


def ua_family(ua: str) -> str:
    """Coarse ``browser-os`` family of a User-Agent (lab approximation)."""
    low = ua.lower()
    os_ = next(
        (
            n
            for k, n in (
                ("windows", "windows"),
                ("android", "android"),
                ("iphone", "ios"),
                ("ipad", "ios"),
                ("mac os x", "macos"),
                ("linux", "linux"),
            )
            if k in low
        ),
        "other",
    )
    browser = next(
        (
            n
            for k, n in (
                ("edg/", "edge"),
                ("firefox/", "firefox"),
                ("chrome/", "chrome"),
                ("safari/", "safari"),
                ("curl", "curl"),
                ("python", "python"),
            )
            if k in low
        ),
        "other",
    )
    return f"{browser}-{os_}"


def ja4_family(ja4: str) -> str:
    """The first JA4 section (``t13d1516h2``): protocol, version, counts and ALPN."""
    return ja4.split("_", 1)[0] if ja4 else ""


def net24(ip: str) -> str:
    if ":" in ip:
        return ":".join(ip.split(":")[:3])
    parts = ip.split(".")
    return ".".join(parts[:3]) if len(parts) == 4 else ip


def net16(ip: str) -> str:
    if ":" in ip:
        return ":".join(ip.split(":")[:2])
    parts = ip.split(".")
    return ".".join(parts[:2]) if len(parts) == 4 else ip


def username_of(body: bytes) -> str:
    try:
        data = json.loads(body or b"{}")
    except ValueError:
        return ""
    user = data.get("username") if isinstance(data, dict) else None
    return user.strip().lower() if isinstance(user, str) else ""


def _remember(seen: list[str], value: str) -> list[str]:
    if value and value not in seen:
        seen = [*seen, value]
    return seen[-MAX_SEEN:]


class AccountProtector(DetectionModule):
    slug: ClassVar[str] = "account_protector"
    title: ClassVar[str] = "Account Protector login risk"
    description: ClassVar[str] = (
        "Per-username profile (networks, devices, JA4 family, hours) scored on /api/login: new "
        "device, new network, impossible travel, disposable email. Emits the Akamai-User-Risk "
        "origin header. MEDIUM-confidence approximation; weights are lab-defined."
    )
    category: ClassVar[str] = "behavioral"
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    applies_to: ClassVar[frozenset[EndpointClass]] = frozenset({EndpointClass.TRANSACTIONAL})

    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self.clock = clock

    @staticmethod
    def _key(user: str) -> str:
        return f"ap:profile:{hashlib.sha256(user.encode()).hexdigest()[:24]}"

    async def _profile(self, ctx: RequestContext, user: str) -> dict[str, Any] | None:
        raw = await ctx.store.get(self._key(user))
        return json.loads(raw) if raw else None

    async def evaluate(self, ctx: RequestContext) -> Signal:
        if ctx.path != LOGIN_PATH:
            return self.signal(Verdict.SKIP, 0, "Account Protector only evaluates logins")
        user = username_of(ctx.body)
        if not user:
            return self.signal(Verdict.SKIP, 0, "no username in the login body")
        now = self.clock()
        ua_fam, ja4_fam = ua_family(ctx.user_agent), ja4_family(ctx.ja4)
        n24, n16 = net24(ctx.client_ip), net16(ctx.client_ip)
        hour = time.gmtime(now).tm_hour
        weekday = time.gmtime(now).tm_wday
        profile = await self._profile(ctx, user)
        risk: list[str] = []
        trust: list[str] = []
        score = 0
        domain = user.rsplit("@", 1)[1] if "@" in user else ""
        if domain in DISPOSABLE_DOMAINS:
            risk.append("udisp")
            score += W_DISPOSABLE
        if profile is None:
            general = ["gnew_user"]
        else:
            general = ["gknown_user"]
            if ua_fam in profile["ua"]:
                trust.append(f"udbp:{ua_fam}")
            else:
                risk.append("unewdev")
                score += W_NEW_DEVICE
            if ja4_fam:
                if ja4_fam in profile["ja4"]:
                    trust.append(f"udfp:{ja4_fam}")
                else:
                    risk.append("unewja4")
                    score += W_NEW_JA4
            if n24 in profile["nets"]:
                trust.append(f"unp:{n24}")
            else:
                risk.append("unewnet")
                score += W_NEW_NET
            if n16 != profile["last16"] and now - profile["last_ts"] < TRAVEL_WINDOW:
                risk.append("utravel")
                score += W_TRAVEL
            if len(profile["hours"]) >= 5 and hour not in profile["hours"]:
                risk.append("uhour")
                score += W_HOUR
            elif hour in profile["hours"]:
                trust.append(f"utp:weekday_{weekday}")
        score = min(100, score)
        user_risk = {
            "uuid": str(uuid.uuid5(uuid.NAMESPACE_URL, f"lab-user:{user}")),
            "status": 0 if profile is None else 4,
            "score": score,
            "general": general,
            "risk": risk,
            "trust": trust,
            "allow": 1 if profile is not None and score == 0 else 0,
        }
        details = {DETAIL_USER_RISK: user_risk, "risk_factors": risk}
        if score == 0:
            return self.signal(
                Verdict.PASS, 0, f"login consistent with the profile ({general[0]})", **details
            )
        verdict = Verdict.FAIL if score >= 50 else Verdict.WARN
        return self.signal(verdict, score, "login risk: " + ", ".join(risk), **details)

    async def after_score(self, ctx: RequestContext, report: ScoreReport) -> None:
        if ctx.path != LOGIN_PATH or ctx.endpoint_class != EndpointClass.TRANSACTIONAL:
            return
        user = username_of(ctx.body)
        sig = next((s for s in report.signals if s.module == self.slug), None)
        if not user or sig is None or report.action in NOT_LEARNED or sig.score >= LEARN_BELOW:
            return
        now = self.clock()
        p = await self._profile(ctx, user) or {
            "ua": [],
            "ja4": [],
            "nets": [],
            "hours": [],
            "logins": 0,
            "last16": "",
            "last_ts": 0.0,
        }
        p["ua"] = _remember(p["ua"], ua_family(ctx.user_agent))
        p["ja4"] = _remember(p["ja4"], ja4_family(ctx.ja4))
        p["nets"] = _remember(p["nets"], net24(ctx.client_ip))
        hour = str(time.gmtime(now).tm_hour)
        p["hours"] = sorted({*map(str, p["hours"]), hour}, key=int)
        p["hours"] = [int(h) for h in p["hours"]]
        p["logins"] += 1
        p["last16"], p["last_ts"] = net16(ctx.client_ip), now
        await ctx.store.set(self._key(user), json.dumps(p), ttl=PROFILE_TTL)
