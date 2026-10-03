"""Cookie value generators and abck validation helpers."""

from __future__ import annotations

import base64
import secrets

from .contract import SessionStore

COOKIE_BM_SZ = "bm_sz"
COOKIE_AK_BMSC = "ak_bmsc"
COOKIE_ABCK = "_abck"
SESSION_TTL = 3600


def new_bm_sz() -> str:
    """Session id: 32 hex chars + '~' + 8 hex."""
    return f"{secrets.token_hex(16).upper()}~{secrets.token_hex(4).upper()}"


def new_ak_bmsc() -> str:
    """Opaque long base64-ish blob, like the real ak_bmsc."""
    raw = secrets.token_bytes(96)
    return f"{secrets.token_hex(16).upper()}~" + base64.b64encode(raw).decode().rstrip("=")


def abck_cookie_value(validated: bool) -> str:
    """``<hex>~-1~<b64>~-1~-1`` unvalidated; ``<hex>~0~<b64>~-1~-1`` validated."""
    head = secrets.token_hex(32).upper()
    blob = base64.b64encode(secrets.token_bytes(120)).decode().rstrip("=")
    return f"{head}~{0 if validated else -1}~{blob}~-1~-1"


def _key(session_id: str) -> str:
    return f"abck:{session_id}"


async def mark_abck_validated(store: SessionStore, session_id: str) -> None:
    await store.set(_key(session_id), "validated", ttl=SESSION_TTL)


async def is_abck_validated(store: SessionStore, session_id: str) -> bool:
    return bool(session_id) and await store.get(_key(session_id)) == "validated"
