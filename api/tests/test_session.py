import re

from app.session import (
    abck_cookie_value,
    is_abck_validated,
    mark_abck_validated,
    new_ak_bmsc,
    new_bm_sz,
)
from app.store import MemoryStore


def test_bm_sz_format() -> None:
    assert re.fullmatch(r"[0-9A-F]{32}~[0-9A-F]{8}", new_bm_sz())
    assert new_bm_sz() != new_bm_sz()


def test_ak_bmsc_opaque() -> None:
    assert len(new_ak_bmsc()) > 100


def test_abck_formats() -> None:
    assert "~-1~" in abck_cookie_value(False)
    assert "~0~" not in abck_cookie_value(False)
    assert "~0~" in abck_cookie_value(True)
    assert abck_cookie_value(True).endswith("~-1~-1")


async def test_validated_roundtrip(memory_store: MemoryStore) -> None:
    assert not await is_abck_validated(memory_store, "sid")
    await mark_abck_validated(memory_store, "sid")
    assert await is_abck_validated(memory_store, "sid")
    assert await memory_store.get("abck:sid") == "validated"
    assert not await is_abck_validated(memory_store, "")
