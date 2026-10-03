from __future__ import annotations

from collections.abc import Callable

from app.contract import RequestContext, Verdict
from app.modules.abck_cookie import AbckCookieModule, required_posts
from app.session import abck_cookie_value, fingerprint_binding, mark_abck_validated
from app.store import MemoryStore

SID = "B" * 32 + "~YAAQCAFEBABE~1~2"
JA4 = "t13d1516h2_8daaf6152771_02713d6af862"
UA = "Mozilla/5.0 Chrome/131.0.0.0"
mod = AbckCookieModule()


def ctx_kwargs(**over: object) -> dict[str, object]:
    base: dict[str, object] = {"session_id": SID, "ja4": JA4, "user_agent": UA}
    base.update(over)
    return base


async def test_no_cookie(make_ctx: Callable[..., RequestContext]) -> None:
    s = await mod.evaluate(make_ctx(session_id=SID))
    assert (s.verdict, s.score) == (Verdict.FAIL, 95)


async def test_unvalidated(make_ctx: Callable[..., RequestContext]) -> None:
    s = await mod.evaluate(make_ctx(session_id=SID, cookies={"_abck": abck_cookie_value(False)}))
    assert (s.verdict, s.score, s.reason) == (Verdict.FAIL, 85, "_abck not validated")


async def test_malformed_cookie(make_ctx: Callable[..., RequestContext]) -> None:
    s = await mod.evaluate(make_ctx(session_id=SID, cookies={"_abck": "x" * 64 + "~0~abc~-1~-1"}))
    assert s.verdict == Verdict.FAIL and "malformed" in s.reason


async def test_default_mode_trusts_server_not_cookie_flag(
    make_ctx: Callable[..., RequestContext], memory_store: MemoryStore
) -> None:
    # server validated, cookie says -1: pass (flag not trusted either way)
    await mark_abck_validated(memory_store, SID)
    s = await mod.evaluate(make_ctx(session_id=SID, cookies={"_abck": abck_cookie_value(False)}))
    assert s.verdict == Verdict.PASS and s.details["mode"] == "default"
    # forged ~0~ without server validation: just "not validated" in default mode
    s = await mod.evaluate(
        make_ctx(session_id="other", cookies={"_abck": abck_cookie_value(True, tilde0=True)})
    )
    assert s.verdict == Verdict.FAIL and s.reason == "_abck not validated"


async def test_tilde0_mode_blocks_forged_flag(
    make_ctx: Callable[..., RequestContext], memory_store: MemoryStore
) -> None:
    forged = abck_cookie_value(True, tilde0=True)
    s = await mod.evaluate(
        make_ctx(session_id=SID, cookies={"_abck": forged}, flags={"abck_tilde0_mode": True})
    )
    assert s.verdict == Verdict.BLOCK and "forged" in s.reason
    await mark_abck_validated(memory_store, SID)
    s = await mod.evaluate(
        make_ctx(session_id=SID, cookies={"_abck": forged}, flags={"abck_tilde0_mode": True})
    )
    assert s.verdict == Verdict.PASS and s.details["mode"] == "tilde0"


async def test_n_posts_mode_needs_n_valid_posts(
    make_ctx: Callable[..., RequestContext], memory_store: MemoryStore
) -> None:
    assert required_posts() == 3
    cookies = {"_abck": abck_cookie_value(False)}
    flags = {"abck_n_posts": True}
    await mark_abck_validated(memory_store, SID)
    await memory_store.set(f"sensor:n:{SID}", "2")
    s = await mod.evaluate(make_ctx(session_id=SID, cookies=cookies, flags=flags))
    assert s.verdict == Verdict.FAIL and "3 valid sensor posts" in s.reason
    await memory_store.set(f"sensor:n:{SID}", "3")
    s = await mod.evaluate(make_ctx(session_id=SID, cookies=cookies, flags=flags))
    assert s.verdict == Verdict.PASS and s.details["mode"] == "n_posts"
    assert "~0~" not in cookies["_abck"]


async def test_validated(make_ctx: Callable[..., RequestContext], memory_store: MemoryStore) -> None:
    await mark_abck_validated(memory_store, SID)
    s = await mod.evaluate(make_ctx(session_id=SID, cookies={"_abck": abck_cookie_value(True)}))
    assert (s.verdict, s.score) == (Verdict.PASS, 0)


async def test_binding_replay_is_blocked(
    make_ctx: Callable[..., RequestContext], memory_store: MemoryStore
) -> None:
    bind = fingerprint_binding(JA4, UA, "203.0.113.7")
    await mark_abck_validated(memory_store, SID, binding=bind)
    cookies = {"_abck": abck_cookie_value(True)}
    same = await mod.evaluate(
        make_ctx(**ctx_kwargs(cookies=cookies, client_ip="203.0.113.99"))  # same /24
    )
    assert same.verdict == Verdict.PASS
    other_tls = await mod.evaluate(
        make_ctx(**ctx_kwargs(cookies=cookies, client_ip="203.0.113.7", ja4="t13d1516h2_zz_yy"))
    )
    assert other_tls.verdict == Verdict.BLOCK and "ja4" in other_tls.details["binding_diff"]
    other_ua = await mod.evaluate(
        make_ctx(**ctx_kwargs(cookies=cookies, client_ip="203.0.113.7", user_agent="curl/8"))
    )
    assert other_ua.verdict == Verdict.BLOCK
    other_net = await mod.evaluate(
        make_ctx(**ctx_kwargs(cookies=cookies, client_ip="198.51.100.7"))
    )
    assert other_net.verdict == Verdict.FAIL and other_net.score == 70
