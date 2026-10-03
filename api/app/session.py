"""Cookie shapes, server-side session secrets and ``_abck`` validation helpers.

Cookie shapes (audit report §1.2 case 4 and case 7, tier MEDIUM: two public captures)::

    bm_sz   = HEX32~YAAQ<base64>~<int>~<int>          seed cookie, about 4 hours
    _abck   = HEX32~<flag>~YAAQ<base64>~-1~-1~-1      32-hex id (NOT 64), three trailing -1
    ak_bmsc = opaque blob                             lab-defined shape

Everything after the ``YAAQ`` prefix is random lab data, not a real Akamai encoding. The
base64 alphabet is restricted (no ``/``, no ``=`` padding) so the value survives Set-Cookie
quoting unchanged; real captures use the full alphabet.

``ctx.session_id`` is the full ``bm_sz`` value. All lab secrets used by the client-side
modules are derived from one per-process secret (``LAB_SECRET`` env var, else random) through
:func:`server_secret`, so a payload minted for one session or one server run never validates
in another.

Cookie attributes (``Max-Age``, ``HttpOnly``) are NOT confirmed by any public capture (report
§3.2 item 2). The lab picks defaults and exposes them through :func:`cookie_attrs`; the one
LOW-confidence attribute (``ak_bmsc`` HttpOnly, vendor-only) sits behind the
``ak_bmsc_httponly`` flag declared by ``pixel_challenge``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
from collections.abc import Mapping
from typing import Any

from .contract import RequestContext, SessionStore

COOKIE_BM_SZ = "bm_sz"
COOKIE_AK_BMSC = "ak_bmsc"
COOKIE_ABCK = "_abck"
COOKIE_BM_SV = "bm_sv"  # LOW (vendor/cookie-database only): session validation counters
COOKIE_BM_MI = "bm_mi"  # LOW: browser validation

BM_SZ_MAX_AGE = 4 * 3600  # "about four hours" (report §1.2 case 7)
ABCK_MAX_AGE = 365 * 24 * 3600  # "about a one-year lifetime" (report §1.2 case 4, vendor)
AK_BMSC_MAX_AGE = 2 * 3600  # lab choice (no public source)
BM_SV_MAX_AGE = 2 * 3600  # cookie-database wording (report §2.7, weak)
SESSION_TTL = BM_SZ_MAX_AGE  # server-side state lives as long as the bm_sz seed

BM_SZ_RE = re.compile(r"^[0-9A-Fa-f]{32}~YAAQ[A-Za-z0-9+_=-]+~\d+~\d+$")
ABCK_RE = re.compile(r"^([0-9A-Fa-f]{32})~(-?\d+)~YAAQ[A-Za-z0-9+_=-]+~-1~-1~-1$")

_PROCESS_SECRET = (
    os.environ["LAB_SECRET"].encode() if os.environ.get("LAB_SECRET") else secrets.token_bytes(32)
)


def server_secret(label: str) -> bytes:
    """Domain-separated sub-key of the per-process lab secret."""
    return hmac.new(_PROCESS_SECRET, label.encode(), hashlib.sha256).digest()


def mac_hex(key: bytes, *parts: str) -> str:
    """HMAC-SHA256 hex over the ``\\n``-joined parts."""
    return hmac.new(key, "\n".join(parts).encode(), hashlib.sha256).hexdigest()


def _blob(nbytes: int) -> str:
    """Random base64 text, cookie-safe alphabet (no '/', no padding)."""
    return base64.b64encode(secrets.token_bytes(nbytes)).decode().rstrip("=").replace("/", "+")


def new_bm_sz() -> str:
    """Seed cookie / session id: ``HEX32~YAAQ<base64>~<int>~<int>``."""
    head = secrets.token_hex(16).upper()
    a = secrets.randbelow(2_000_000) + 3_000_000
    b = a + secrets.randbelow(500_000) + 50_000
    return f"{head}~YAAQ{_blob(60)}~{a}~{b}"


def new_ak_bmsc() -> str:
    """Opaque long blob (lab-defined shape; the real cookie's layout is not documented)."""
    return f"{secrets.token_hex(16).upper()}~{_blob(96)}"


def abck_ident(session_id: str) -> str:
    """Stable 32-hex id for the session's ``_abck`` (real captures keep the id, vary the rest)."""
    return mac_hex(server_secret("abck-id"), session_id)[:32].upper()


def abck_cookie_value(validated: bool, *, tilde0: bool = False, ident: str | None = None) -> str:
    """``HEX32~<flag>~YAAQ<base64>~-1~-1~-1``.

    The flag is ``-1`` unless ``tilde0`` is set AND the session is validated; only the LOW
    ``abck_tilde0_mode`` flag makes the cookie itself carry ``~0~`` (report §3.1: ``~0~`` is a
    convention, not a rule). ``ident`` pins the 32-hex id (refreshes keep it); default random.
    """
    head = (ident or secrets.token_hex(16)).upper()
    flag = 0 if (validated and tilde0) else -1
    return f"{head}~{flag}~YAAQ{_blob(90)}~-1~-1~-1"


def parse_abck(value: str) -> tuple[str, int] | None:
    """``(id, flag)`` of a well-shaped ``_abck`` value, else None."""
    m = ABCK_RE.match(value)
    return (m.group(1).upper(), int(m.group(2))) if m else None


def abck_needs_refresh(current: str | None, validated: bool, tilde0: bool = False) -> bool:
    """Should ``finalize_cookies`` (re)issue ``_abck``? Missing cookie, or, in tilde0 mode only,
    a validated session whose cookie does not show ``~0~`` yet. In the default and n-posts
    modes the sensor POST response already refreshed the cookie; do not churn it."""
    if current is None:
        return True
    parsed = parse_abck(current)
    return bool(tilde0 and validated and parsed is not None and parsed[1] != 0)


def cookie_attrs(name: str, flags: Mapping[str, bool] | None = None) -> dict[str, Any]:
    """``Response.set_cookie`` keyword arguments for a lab cookie.

    ``ak_bmsc`` is HttpOnly only when the LOW ``ak_bmsc_httponly`` flag is on (vendor-only
    claim). Everything else is script-readable (the sensor reads ``bm_sz``). No ``Secure``:
    the lab is also exercised over plain HTTP in tests.
    """
    flags = flags or {}
    max_age = {
        COOKIE_BM_SZ: BM_SZ_MAX_AGE,
        COOKIE_ABCK: ABCK_MAX_AGE,
        COOKIE_AK_BMSC: AK_BMSC_MAX_AGE,
        COOKIE_BM_SV: BM_SV_MAX_AGE,
        COOKIE_BM_MI: BM_SV_MAX_AGE,
    }.get(name)
    return {
        "path": "/",
        "samesite": "lax",
        "httponly": bool(flags.get("ak_bmsc_httponly")) if name == COOKIE_AK_BMSC else False,
        "max_age": max_age,
    }


def bm_sv_value(session_id: str, purpose: str = COOKIE_BM_SV) -> str:
    """Lab-defined ``bm_sv`` / ``bm_mi`` value, a MAC of the session (LOW: shape unknown)."""
    mac = mac_hex(server_secret(f"cookie:{purpose}"), session_id)
    blob = base64.b64encode(bytes.fromhex(mac)).decode().rstrip("=").replace("/", "+")
    return f"{mac[:32].upper()}~YAAQ{blob}"


def extra_cookies(
    session_id: str, flags: Mapping[str, bool] | None = None
) -> list[tuple[str, str, dict[str, Any]]]:
    """``(name, value, set_cookie_kwargs)`` for cookies issued only behind a flag.

    ``bm_sv`` / ``bm_mi`` (flag ``bm_sv_cookies``, LOW: names and purposes come from cookie
    databases and vendors only). ``finalize_cookies`` should issue each one the request lacks.
    """
    if not (flags or {}).get("bm_sv_cookies"):
        return []
    return [
        (n, bm_sv_value(session_id, n), cookie_attrs(n, flags))
        for n in (COOKIE_BM_SV, COOKIE_BM_MI)
    ]


# --- fingerprint continuity (MEDIUM: Akamai's exact binding rules are not public) -------------


def ja4_family(ja4: str) -> str:
    """Resumption-stable part of a JA4: ``<proto/version/sni><cipher count>_<cipher hash>``.

    Drops the ALPN code, the extension count and the extension hash: a resumed TLS 1.3
    handshake adds ``pre_shared_key`` and changes both, and h2/h1 can differ per connection.
    """
    parts = ja4.split("_")
    if len(parts) != 3 or len(parts[0]) < 6:
        return ja4
    return f"{parts[0][:6]}_{parts[1]}"


def ip_prefix(ip: str) -> str:
    """/24 for IPv4, /48 for IPv6; the raw string when it is not an IP literal."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    bits = 24 if addr.version == 4 else 48
    return str(ipaddress.ip_network(f"{addr}/{bits}", strict=False))


def fingerprint_binding(ja4: str, user_agent: str, client_ip: str) -> dict[str, str]:
    return {"ja4": ja4_family(ja4), "ua": user_agent, "net": ip_prefix(client_ip)}


def binding_from_ctx(ctx: RequestContext) -> dict[str, str]:
    return fingerprint_binding(ctx.ja4, ctx.user_agent, ctx.client_ip)


def binding_mismatch(stored: Mapping[str, str], current: Mapping[str, str]) -> list[str]:
    """Names of the binding components that differ (empty list: same client)."""
    return [k for k in ("ja4", "ua", "net") if stored.get(k) != current.get(k)]


# --- server-side _abck truth --------------------------------------------------------------


def _key(session_id: str) -> str:
    return f"abck:{session_id}"


async def mark_abck_validated(
    store: SessionStore, session_id: str, *, binding: Mapping[str, str] | None = None
) -> None:
    """Record server-side validation, optionally with the fingerprint binding at that moment."""
    await store.set(_key(session_id), "validated", ttl=SESSION_TTL)
    if binding is not None:
        await store.set(f"abck:bind:{session_id}", json.dumps(dict(binding)), ttl=SESSION_TTL)


async def is_abck_validated(store: SessionStore, session_id: str) -> bool:
    return bool(session_id) and await store.get(_key(session_id)) == "validated"


async def abck_binding(store: SessionStore, session_id: str) -> dict[str, str] | None:
    raw = await store.get(f"abck:bind:{session_id}") if session_id else None
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else None
