from __future__ import annotations

from collections.abc import Callable

from app.contract import RequestContext, Verdict
from app.modules.abck_cookie import AbckCookieModule
from app.session import abck_cookie_value, mark_abck_validated
from app.store import MemoryStore

SID = "B" * 32 + "~CAFEBABE"
mod = AbckCookieModule()


async def test_no_cookie(make_ctx: Callable[..., RequestContext]) -> None:
    s = await mod.evaluate(make_ctx(session_id=SID))
    assert (s.verdict, s.score) == (Verdict.FAIL, 95)


async def test_unvalidated(make_ctx: Callable[..., RequestContext]) -> None:
    s = await mod.evaluate(make_ctx(session_id=SID, cookies={"_abck": abck_cookie_value(False)}))
    assert (s.verdict, s.score, s.reason) == (Verdict.FAIL, 85, "_abck not validated")


async def test_unvalidated_cookie_but_server_validated(
    make_ctx: Callable[..., RequestContext], memory_store: MemoryStore
) -> None:
    await mark_abck_validated(memory_store, SID)
    s = await mod.evaluate(make_ctx(session_id=SID, cookies={"_abck": abck_cookie_value(False)}))
    assert s.verdict == Verdict.FAIL


async def test_forged(make_ctx: Callable[..., RequestContext]) -> None:
    s = await mod.evaluate(make_ctx(session_id=SID, cookies={"_abck": abck_cookie_value(True)}))
    assert s.verdict == Verdict.BLOCK


async def test_validated(
    make_ctx: Callable[..., RequestContext], memory_store: MemoryStore
) -> None:
    await mark_abck_validated(memory_store, SID)
    s = await mod.evaluate(make_ctx(session_id=SID, cookies={"_abck": abck_cookie_value(True)}))
    assert (s.verdict, s.score) == (Verdict.PASS, 0)
