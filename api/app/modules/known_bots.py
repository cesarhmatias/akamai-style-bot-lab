"""Known-bot verification: impersonators of Googlebot/GPTBot/... versus verified crawlers.

Mechanism: well-known crawlers announce themselves in the User-Agent, which anyone can forge.
A genuine one is verifiable out-of-band, by the source network (published IP ranges, or reverse
DNS plus forward confirmation) or by a cryptographic identity: HTTP Message Signatures
(RFC 9421), as profiled by the Web Bot Auth drafts (``Signature``, ``Signature-Input``,
``Signature-Agent`` plus a public key directory at
``/.well-known/http-message-signatures-directory``).

How real Akamai uses it (audit report ``docs/research/akamai-audit-2026-10.md`` section 2.11,
MEDIUM): Bot Manager has a known-bot directory (about 1,750 bots in 2023) and an "Impersonators
of Known Bots" detection. On 2026-09-03 Akamai split AI bots into AI training crawlers, AI search
crawlers and AI fetchers/agents, and since late 2025 it verifies Web Bot Auth signatures. The
directory contents, the categories' membership and the verification internals are not public.

How the lab simulates it (an APPROXIMATION):
* ``BOTS`` is a lab-local table: UA pattern, Akamai-style category label (AI split included) and
  optional source ranges. The built-in ranges are an illustrative snapshot (Googlebot, Bingbot,
  Applebot) and go stale; override or extend them with
  ``LAB_KNOWN_BOT_RANGES="googlebot=66.249.64.0/19;gptbot=203.0.113.0/28"``. AI bots have no
  built-in range: they verify by signature or by a range you configure. Reverse DNS is NOT
  performed (the lab is offline), so ``details["rdns"]`` says "not performed".
* A UA claiming a known bot passes when its IP is in the bot's range OR it carries a valid RFC
  9421 signature (covered ``@authority``, ``created`` within 5 minutes, ``tag="web-bot-auth"``,
  optional ``nonce`` replay protection, covered ``signature-agent`` when that header is
  present) from a key in the LAB key directory whose bot name matches the claim. Otherwise:
  FAIL 85 "Impersonator of known bot". A valid signature from a lab key is also accepted with a
  non-bot UA (a "signed agent").
* Lab keys are Ed25519, derived at startup from ``LAB_BOT_KEY_SEED`` (hex) or random per process,
  and published at ``GET /.well-known/http-message-signatures-directory`` as a JWKS (extra member
  ``lab_bot`` names the identity). ``lab_sign_headers`` lets tests and demos sign requests. Ed25519
  is implemented in pure Python (RFC 8032) so the lab needs no extra dependency; it is slow-ish and
  for lab use only, not production cryptography.
* Result: PASS with ``bot_name``, ``bot_category`` (e.g. "AI Training Crawlers", the engine
  decides the action per category), ``bot_class`` and ``verified_by``. Non-bot UAs without a
  signature are SKIP.

How a client passes: be the real crawler (come from its published ranges) or sign with a key the
site trusts; a normal browser/scraper simply does not claim to be a bot.

Limits: the lab directory trusts only its own keys (no fetching of remote ``Signature-Agent``
directories); category membership is the lab's labelling; signature-agent is treated as an opaque
header value in the signature base.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from app.contract import Confidence, DetectionModule, EndpointClass, RequestContext, Signal, Verdict

# --------------------------------------------------------------------------------------------
# Ed25519 (RFC 8032, pure Python, lab use only)
# --------------------------------------------------------------------------------------------
_P = 2**255 - 19
_Q = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)
_Point = tuple[int, int, int, int]


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


def _recover_x(y: int, sign: int) -> int | None:
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P:
        return None
    return _P - x if (x & 1) != sign else x


_GY = 4 * _inv(5) % _P
_GX = _recover_x(_GY, 0) or 0
_G: _Point = (_GX, _GY, 1, _GX * _GY % _P)


def _add(a: _Point, b: _Point) -> _Point:
    aa = (a[1] - a[0]) * (b[1] - b[0]) % _P
    bb = (a[1] + a[0]) * (b[1] + b[0]) % _P
    cc = 2 * a[3] * b[3] * _D % _P
    dd = 2 * a[2] * b[2] % _P
    e, f, g, h = bb - aa, dd - cc, dd + cc, bb + aa
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(s: int, pt: _Point) -> _Point:
    q: _Point = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _add(q, pt)
        pt = _add(pt, pt)
        s >>= 1
    return q


def _eq(a: _Point, b: _Point) -> bool:
    return (a[0] * b[2] - b[0] * a[2]) % _P == 0 and (a[1] * b[2] - b[1] * a[2]) % _P == 0


def _compress(pt: _Point) -> bytes:
    zi = _inv(pt[2])
    x, y = pt[0] * zi % _P, pt[1] * zi % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(s: bytes) -> _Point | None:
    y = int.from_bytes(s, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


def _h(data: bytes) -> int:
    return int.from_bytes(hashlib.sha512(data).digest(), "little") % _Q


def _expand(seed: bytes) -> tuple[int, bytes]:
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def ed25519_public_key(seed: bytes) -> bytes:
    return _compress(_mul(_expand(seed)[0], _G))


def ed25519_sign(seed: bytes, msg: bytes) -> bytes:
    a, prefix = _expand(seed)
    pub = _compress(_mul(a, _G))
    r = _h(prefix + msg)
    rs = _compress(_mul(r, _G))
    s = (r + _h(rs + pub + msg) * a) % _Q
    return rs + int.to_bytes(s, 32, "little")


def ed25519_verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    if len(pub) != 32 or len(sig) != 64:
        return False
    a, r = _decompress(pub), _decompress(sig[:32])
    s = int.from_bytes(sig[32:], "little")
    if a is None or r is None or s >= _Q:
        return False
    return _eq(_mul(s, _G), _add(r, _mul(_h(sig[:32] + pub + msg), a)))


# --------------------------------------------------------------------------------------------
# Known-bot table
# --------------------------------------------------------------------------------------------
CAT_SEARCH = "Web Search Engine Bots"
CAT_AI_TRAIN = "AI Training Crawlers"
CAT_AI_SEARCH = "AI Search Crawlers"
CAT_AI_AGENT = "AI Fetchers and Agents"
CAT_SOCIAL = "Link Preview Bots"


@dataclass(frozen=True)
class KnownBot:
    name: str
    pattern: re.Pattern[str]
    category: str
    bot_class: str  # search_engine | ai_training | ai_search | ai_fetcher_agent | link_preview
    ranges: tuple[str, ...] = ()


def _bot(name: str, pat: str, category: str, cls: str, *ranges: str) -> KnownBot:
    return KnownBot(name, re.compile(pat, re.I), category, cls, tuple(ranges))


# More specific patterns first (first match wins). Ranges: illustrative lab snapshot.
BOTS: tuple[KnownBot, ...] = (
    _bot("oai-searchbot", r"OAI-SearchBot", CAT_AI_SEARCH, "ai_search"),
    _bot("chatgpt-user", r"ChatGPT-User", CAT_AI_AGENT, "ai_fetcher_agent"),
    _bot("gptbot", r"\bGPTBot\b", CAT_AI_TRAIN, "ai_training"),
    _bot("claude-searchbot", r"Claude-SearchBot", CAT_AI_SEARCH, "ai_search"),
    _bot("claude-user", r"Claude-User", CAT_AI_AGENT, "ai_fetcher_agent"),
    _bot("claudebot", r"\bClaudeBot\b|anthropic-ai", CAT_AI_TRAIN, "ai_training"),
    _bot("perplexity-user", r"Perplexity-User", CAT_AI_AGENT, "ai_fetcher_agent"),
    _bot("perplexitybot", r"\bPerplexityBot\b", CAT_AI_SEARCH, "ai_search"),
    _bot("duckassistbot", r"DuckAssistBot", CAT_AI_SEARCH, "ai_search"),
    _bot("ccbot", r"\bCCBot\b", CAT_AI_TRAIN, "ai_training"),
    _bot("bytespider", r"Bytespider", CAT_AI_TRAIN, "ai_training"),
    _bot("meta-externalagent", r"meta-externalagent", CAT_AI_TRAIN, "ai_training"),
    _bot("amazonbot", r"\bAmazonbot\b", CAT_SEARCH, "search_engine"),
    _bot("googlebot", r"Googlebot|Google-InspectionTool|AdsBot-Google", CAT_SEARCH,
         "search_engine", "66.249.64.0/19"),
    _bot("bingbot", r"\bbingbot\b|BingPreview", CAT_SEARCH, "search_engine",
         "157.55.39.0/24", "207.46.13.0/24", "40.77.167.0/24", "52.167.144.0/24"),
    _bot("applebot", r"\bApplebot\b", CAT_SEARCH, "search_engine", "17.0.0.0/8"),
    _bot("duckduckbot", r"DuckDuckBot", CAT_SEARCH, "search_engine"),
    _bot("yandexbot", r"YandexBot", CAT_SEARCH, "search_engine"),
    _bot("baiduspider", r"Baiduspider", CAT_SEARCH, "search_engine"),
    _bot("facebookexternalhit", r"facebookexternalhit", CAT_SOCIAL, "link_preview"),
    _bot("twitterbot", r"Twitterbot", CAT_SOCIAL, "link_preview"),
    _bot("slackbot", r"Slackbot", CAT_SOCIAL, "link_preview"),
    _bot("linkedinbot", r"LinkedInBot", CAT_SOCIAL, "link_preview"),
)
BOT_BY_NAME = {b.name: b for b in BOTS}


def identify_bot(user_agent: str) -> KnownBot | None:
    for bot in BOTS:
        if bot.pattern.search(user_agent):
            return bot
    return None


def bot_ranges(bot: KnownBot) -> list[str]:
    """Built-in ranges plus ``LAB_KNOWN_BOT_RANGES`` (``name=cidr,cidr;name2=cidr``)."""
    out = list(bot.ranges)
    for item in os.environ.get("LAB_KNOWN_BOT_RANGES", "").split(";"):
        name, _, cidrs = item.partition("=")
        if name.strip().lower() == bot.name:
            out += [c.strip() for c in cidrs.split(",") if c.strip()]
    return out


def ip_in_ranges(ip: str, cidrs: list[str]) -> str | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for c in cidrs:
        try:
            net = ipaddress.ip_network(c, strict=False)
        except ValueError:
            continue
        if addr.version == net.version and addr in net:
            return str(net)
    return None


# --------------------------------------------------------------------------------------------
# Lab key directory (Ed25519 keys generated at startup)
# --------------------------------------------------------------------------------------------
def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


@dataclass(frozen=True)
class LabKey:
    bot: str
    keyid: str  # RFC 7638 JWK thumbprint
    public: bytes


_SEED_ENV = os.environ.get("LAB_BOT_KEY_SEED", "").strip()
_MASTER = bytes.fromhex(_SEED_ENV) if _SEED_ENV else os.urandom(32)
_DIRECTORY: dict[str, LabKey] | None = None
_SEEDS: dict[str, bytes] = {}


def lab_seed(bot: str) -> bytes:
    """Private seed of a lab identity (for tests and demos that sign requests)."""
    if bot not in _SEEDS:
        _SEEDS[bot] = hmac.new(_MASTER, bot.encode(), hashlib.sha256).digest()
    return _SEEDS[bot]


def jwk_for(public: bytes) -> dict[str, str]:
    return {"kty": "OKP", "crv": "Ed25519", "x": _b64u(public)}


def thumbprint(public: bytes) -> str:
    canon = json.dumps(jwk_for(public), sort_keys=True, separators=(",", ":"))
    return _b64u(hashlib.sha256(canon.encode()).digest())


def lab_key(bot: str) -> LabKey:
    pub = ed25519_public_key(lab_seed(bot))
    return LabKey(bot, thumbprint(pub), pub)


def key_directory() -> dict[str, LabKey]:
    """keyid -> LabKey for every known bot (built once, lazily: ~10 ms per key)."""
    global _DIRECTORY
    if _DIRECTORY is None:
        _DIRECTORY = {k.keyid: k for k in (lab_key(b.name) for b in BOTS)}
    return _DIRECTORY


def directory_jwks() -> dict[str, Any]:
    return {
        "keys": [
            {**jwk_for(k.public), "kid": k.keyid, "lab_bot": k.bot}
            for k in key_directory().values()
        ]
    }


# --------------------------------------------------------------------------------------------
# RFC 9421 (subset): Signature-Input / Signature parsing and verification
# --------------------------------------------------------------------------------------------
SIG_MAX_AGE = 300
_clock: Callable[[], float] = time.time
_PARAM = re.compile(r';\s*([a-z][a-z0-9_*.-]*)=("(?:[^"\\]|\\.)*"|[^;,\s]+)')


def _split_members(value: str) -> list[str]:
    out, depth, quote, cur = [], 0, False, ""
    for ch in value:
        if ch == '"':
            quote = not quote
        elif not quote and ch == "(":
            depth += 1
        elif not quote and ch == ")":
            depth -= 1
        if ch == "," and not quote and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def parse_signature_input(header: str) -> dict[str, tuple[list[str], dict[str, str], str]]:
    """label -> (covered components, params, raw ``@signature-params`` value)."""
    out: dict[str, tuple[list[str], dict[str, str], str]] = {}
    for member in _split_members(header):
        label, eq, raw = member.partition("=")
        raw = raw.strip()
        if not eq or not raw.startswith("("):
            continue
        end = raw.find(")")
        if end < 0:
            continue
        comps = re.findall(r'"([^"]+)"', raw[1:end])
        params = {k: v.strip('"') for k, v in _PARAM.findall(raw[end + 1 :])}
        out[label.strip()] = (comps, params, raw)
    return out


def parse_signatures(header: str) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for member in _split_members(header):
        label, eq, raw = member.partition("=")
        raw = raw.strip()
        if eq and raw.startswith(":") and raw.endswith(":") and len(raw) > 2:
            try:
                out[label.strip()] = base64.b64decode(raw[1:-1], validate=True)
            except ValueError:
                continue
    return out


def _component(ctx: RequestContext, name: str) -> str | None:
    if name == "@authority":
        host = ctx.header("host")
        return host.lower() if host else None
    if name == "@method":
        return ctx.method.upper()
    if name == "@path":
        return ctx.path
    if name == "@scheme":
        return "https"
    if name.startswith("@"):
        return None
    val = ctx.header(name)
    return val.strip() if val is not None else None


def signature_base(
    ctx: RequestContext, comps: list[str], raw_params: str
) -> str | None:
    lines = []
    for c in comps:
        v = _component(ctx, c)
        if v is None:
            return None
        lines.append(f'"{c}": {v}')
    lines.append(f'"@signature-params": {raw_params}')
    return "\n".join(lines)


async def verify_signature(ctx: RequestContext) -> tuple[LabKey | None, str]:
    """(matching lab key, "") on success, else (None, reason). Checks the first usable label."""
    sig_in, sig = ctx.header("signature-input"), ctx.header("signature")
    if not sig_in or not sig:
        return None, "no signature headers"
    inputs, sigs = parse_signature_input(sig_in), parse_signatures(sig)
    reason = "no matching Signature-Input/Signature label"
    for label, (comps, params, raw) in inputs.items():
        if label not in sigs:
            continue
        keyid = params.get("keyid", "")
        key = key_directory().get(keyid)
        if key is None:
            reason = f"unknown keyid {keyid!r} (not in the lab key directory)"
            continue
        if params.get("alg", "ed25519") != "ed25519":
            reason = f"unsupported alg {params.get('alg')!r}"
            continue
        if params.get("tag") != "web-bot-auth":
            reason = 'missing tag="web-bot-auth"'
            continue
        if "@authority" not in comps:
            reason = "@authority is not a covered component"
            continue
        if ctx.header("signature-agent") is not None and "signature-agent" not in comps:
            reason = "signature-agent header present but not covered"
            continue
        try:
            created = int(params["created"])
        except (KeyError, ValueError):
            reason = "missing or invalid created parameter"
            continue
        now = _clock()
        if abs(now - created) > SIG_MAX_AGE:
            reason = f"signature created {abs(now - created):.0f}s away from now (> {SIG_MAX_AGE}s)"
            continue
        if "expires" in params and now > float(params["expires"]):
            reason = "signature expired"
            continue
        base = signature_base(ctx, comps, raw)
        if base is None:
            reason = "covered component not present in the request"
            continue
        if not ed25519_verify(key.public, base.encode(), sigs[label]):
            reason = "signature does not verify"
            continue
        nonce = params.get("nonce")
        if nonce and ctx.store is not None:
            seen = await ctx.store.incr(f"botsig:nonce:{keyid}:{nonce}", ttl=2 * SIG_MAX_AGE)
            if seen > 1:
                reason = "nonce replayed"
                continue
        return key, ""
    return None, reason


def lab_sign_headers(
    bot: str, authority: str, *, method: str = "GET", path: str = "/",
    created: int | None = None, nonce: str | None = None,
    agent: str = '"https://lab.invalid/bots"', label: str = "sig1",
) -> dict[str, str]:
    """Headers (``Signature-Input``, ``Signature``, ``Signature-Agent``) signed with the lab key
    of `bot`, as a Web Bot Auth client would send them. For tests and demos."""
    key = lab_key(bot)
    created = int(_clock()) if created is None else created
    comps = '("@authority" "signature-agent")'
    params = f';created={created};keyid="{key.keyid}";alg="ed25519";tag="web-bot-auth"'
    if nonce:
        params += f';nonce="{nonce}"'
    raw = comps + params
    base = (
        f'"@authority": {authority.lower()}\n"signature-agent": {agent}\n'
        f'"@signature-params": {raw}'
    )
    sig = base64.b64encode(ed25519_sign(lab_seed(bot), base.encode())).decode()
    return {
        "Signature-Input": f"{label}={raw}",
        "Signature": f"{label}=:{sig}:",
        "Signature-Agent": agent,
    }


# --------------------------------------------------------------------------------------------
class KnownBotsModule(DetectionModule):
    slug = "known_bots"
    title = "Known bots and impersonators"
    description = (
        "A UA claiming Googlebot/GPTBot/... must come from the bot's range or carry a valid "
        "RFC 9421 signature; otherwise it is an impersonator. Verified bots are categorised."
    )
    category = "passive"
    confidence = Confidence.MEDIUM
    applies_to = frozenset(EndpointClass)

    def root_router(self) -> Any:
        from fastapi import APIRouter
        from fastapi.responses import JSONResponse

        router = APIRouter()

        @router.get("/.well-known/http-message-signatures-directory", include_in_schema=False)
        async def directory() -> JSONResponse:
            return JSONResponse(
                directory_jwks(),
                media_type="application/http-message-signatures-directory+json",
            )

        return router

    def _verified(self, bot: KnownBot | None, key: LabKey | None, how: str, **d: Any) -> dict:
        name = bot.name if bot else (key.bot if key else "")
        known = bot or (BOT_BY_NAME.get(name) if name else None)
        return {
            "bot_name": name, "bot_category": known.category if known else "",
            "bot_class": known.bot_class if known else "", "verified": True,
            "verified_by": how, "rdns": "not performed (offline lab)", **d,
        }

    async def evaluate(self, ctx: RequestContext) -> Signal:
        bot = identify_bot(ctx.user_agent)
        has_sig = ctx.header("signature") is not None and ctx.header("signature-input") is not None
        key, why = (None, "")
        if has_sig:
            key, why = await verify_signature(ctx)
        if bot is None and key is None:
            if has_sig:
                return self.signal(
                    Verdict.WARN, 20, f"Signed request failed verification: {why}",
                    verified=False, signature_error=why,
                )
            return self.signal(Verdict.SKIP, 0, "Not a known-bot User-Agent")
        if bot is None and key is not None:
            return self.signal(
                Verdict.PASS, 0, f"Signed agent verified ({key.bot}) by RFC 9421 signature",
                **self._verified(None, key, "http-message-signature", keyid=key.keyid),
            )
        if bot is None:  # unreachable: handled above (keeps the type checker honest)
            return self.signal(Verdict.SKIP, 0, "Not a known-bot User-Agent")
        if key is not None:
            if key.bot == bot.name:
                return self.signal(
                    Verdict.PASS, 0, f"{bot.name} verified by RFC 9421 signature",
                    **self._verified(bot, key, "http-message-signature", keyid=key.keyid),
                )
            why = f"signature key belongs to {key.bot}, not {bot.name}"
        net = ip_in_ranges(ctx.client_ip, bot_ranges(bot))
        if net:
            return self.signal(
                Verdict.PASS, 0, f"{bot.name} verified by source range {net} (lab table)",
                **self._verified(bot, key, "ip-range", range=net,
                                 **({"signature_error": why} if why else {})),
            )
        reason = (
            f"Impersonator of known bot: UA claims {bot.name} but {ctx.client_ip} is outside "
            "its lab ranges and no valid RFC 9421 signature was presented"
        )
        return self.signal(
            Verdict.FAIL, 85, reason, bot_name=bot.name, bot_category=bot.category,
            bot_class=bot.bot_class, verified=False, impersonator=True,
            signature_error=why or "none presented", rdns="not performed (offline lab)",
        )
