import re

from app.session import (
    ABCK_RE,
    BM_SZ_RE,
    abck_binding,
    abck_cookie_value,
    abck_ident,
    abck_needs_refresh,
    binding_mismatch,
    cookie_attrs,
    extra_cookies,
    fingerprint_binding,
    ip_prefix,
    is_abck_validated,
    ja4_family,
    mark_abck_validated,
    new_ak_bmsc,
    new_bm_sz,
    parse_abck,
    server_secret,
)
from app.store import MemoryStore

# Report §1.2 case 4/7: real captures (httpx #2287), values shortened.
REAL_ABCK = "97471718CACFA8B8712FA08864AE7E33~-1~YAAQF+ZlXwUIabc123=~-1~-1~-1"
REAL_BM_SZ = "118A0D88115C5E503300B088C49F1D00~YAAQFuZlX70Nabc123==~4273478~4404549"


def test_bm_sz_format() -> None:
    sz = new_bm_sz()
    assert re.fullmatch(r"[0-9A-F]{32}~YAAQ[A-Za-z0-9+_-]+~\d+~\d+", sz)
    assert BM_SZ_RE.match(sz) and BM_SZ_RE.match(REAL_BM_SZ)
    assert new_bm_sz() != new_bm_sz()


def test_ak_bmsc_opaque() -> None:
    assert len(new_ak_bmsc()) > 100


def test_abck_shape_matches_real_captures() -> None:
    assert ABCK_RE.match(REAL_ABCK)
    for validated in (False, True):
        value = abck_cookie_value(validated)
        m = ABCK_RE.match(value)
        assert m and len(m.group(1)) == 32  # 32-hex id, not 64
        assert value.endswith("~-1~-1~-1")  # three trailing -1 fields
        assert re.fullmatch(r"[0-9A-F]{32}~-?\d+~YAAQ[A-Za-z0-9+_-]+~-1~-1~-1", value)


def test_abck_flag_only_flips_in_tilde0_mode() -> None:
    assert "~0~" not in abck_cookie_value(True)
    assert "~0~" not in abck_cookie_value(False, tilde0=True)
    assert parse_abck(abck_cookie_value(True, tilde0=True))[1] == 0  # type: ignore[index]
    assert parse_abck("garbage") is None
    ident = abck_ident("sid")
    assert len(ident) == 32 and abck_cookie_value(False, ident=ident).startswith(ident)
    assert abck_ident("sid") == ident != abck_ident("other")


def test_abck_needs_refresh() -> None:
    assert abck_needs_refresh(None, False)
    cur = abck_cookie_value(True)
    assert not abck_needs_refresh(cur, True)  # default mode: do not churn
    assert abck_needs_refresh(cur, True, tilde0=True)
    assert not abck_needs_refresh(abck_cookie_value(True, tilde0=True), True, tilde0=True)


def test_cookie_attrs_and_flags() -> None:
    assert cookie_attrs("bm_sz")["max_age"] == 4 * 3600
    assert cookie_attrs("ak_bmsc")["httponly"] is False
    assert cookie_attrs("ak_bmsc", {"ak_bmsc_httponly": True})["httponly"] is True
    assert cookie_attrs("_abck", {"ak_bmsc_httponly": True})["httponly"] is False
    assert extra_cookies("sid", {}) == []
    names = [n for n, _, _ in extra_cookies("sid", {"bm_sv_cookies": True})]
    assert names == ["bm_sv", "bm_mi"]


def test_server_secret_is_domain_separated() -> None:
    assert server_secret("a") != server_secret("b")
    assert server_secret("a") == server_secret("a")


def test_binding_helpers() -> None:
    assert ja4_family("t13d1516h2_8daaf6152771_02713d6af862") == "t13d15_8daaf6152771"
    # ALPN, extension count and extension hash do not matter (resumption, h1 fallback)
    assert ja4_family("t13d1517h1_8daaf6152771_aaaaaaaaaaaa") == "t13d15_8daaf6152771"
    assert ja4_family("") == ""
    assert ip_prefix("203.0.113.77") == "203.0.113.0/24"
    assert ip_prefix("2001:db8:1:2::5") == "2001:db8:1::/48"
    assert ip_prefix("not-an-ip") == "not-an-ip"
    a = fingerprint_binding("t13d1516h2_aa_bb", "UA/1", "203.0.113.7")
    assert binding_mismatch(a, dict(a)) == []
    b = fingerprint_binding("t13d1516h2_aa_bb", "UA/2", "203.0.114.7")
    assert binding_mismatch(a, b) == ["ua", "net"]


async def test_validated_roundtrip(memory_store: MemoryStore) -> None:
    assert not await is_abck_validated(memory_store, "sid")
    await mark_abck_validated(memory_store, "sid")
    assert await is_abck_validated(memory_store, "sid")
    assert await memory_store.get("abck:sid") == "validated"
    assert not await is_abck_validated(memory_store, "")
    assert await abck_binding(memory_store, "sid") is None


async def test_binding_stored_with_validation(memory_store: MemoryStore) -> None:
    bind = fingerprint_binding("t13d1516h2_aa_bb", "UA/1", "203.0.113.7")
    await mark_abck_validated(memory_store, "sid", binding=bind)
    assert await abck_binding(memory_store, "sid") == bind
    await memory_store.set("abck:bind:bad", "not json")
    assert await abck_binding(memory_store, "bad") is None
