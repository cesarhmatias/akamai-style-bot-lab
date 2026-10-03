from collections.abc import Callable
from typing import ClassVar

from app.contract import DetectionModule, RequestContext, Signal, Verdict
from app.engine import RING_SIZE, Engine, aggregate
from app.registry import Registry, discover_modules
from app.store import MemoryStore


class Dummy(DetectionModule):
    slug: ClassVar[str] = "dummy"
    title = "Dummy"
    description = "d"
    category = "passive"
    score = 0
    verdict = Verdict.PASS

    async def evaluate(self, ctx: RequestContext) -> Signal:
        return self.signal(self.verdict, self.score, "x")


def make(slug: str, score: int, verdict: Verdict = Verdict.FAIL) -> DetectionModule:
    cls = type(slug, (Dummy,), {"slug": slug, "score": score, "verdict": verdict})
    return cls()  # type: ignore[no-any-return]


class Boom(Dummy):
    slug: ClassVar[str] = "boom"

    async def evaluate(self, ctx: RequestContext) -> Signal:
        raise RuntimeError("kaput")


def sig(score: int, verdict: Verdict = Verdict.FAIL) -> Signal:
    return Signal(module="m", verdict=verdict, score=score, reason="r")


def test_aggregate() -> None:
    assert aggregate([]) == (0, False)
    assert aggregate([sig(40)]) == (40, False)
    assert aggregate([sig(40), sig(40), sig(40)]) == (60, True)
    assert aggregate([sig(100), sig(100)]) == (100, True)
    assert aggregate([sig(5, Verdict.BLOCK)]) == (5, True)


async def test_run_single_and_all(
    memory_store: MemoryStore, make_ctx: Callable[..., RequestContext]
) -> None:
    eng = Engine(Registry(memory_store, [make("a", 30), make("b", 20)]), memory_store)
    one = await eng.evaluate(make_ctx(), slug="a")
    assert [s.module for s in one.signals] == ["a"] and one.score == 30
    allr = await eng.evaluate(make_ctx())
    # 35 is the "strict" segment, whose default protected action is a challenge (blocked);
    # before the Bot Score policy this was below the flat 50 threshold and passed
    assert allr.score == 35 and allr.segment == "strict" and allr.blocked


async def test_toggle_and_default_disabled(
    memory_store: MemoryStore, make_ctx: Callable[..., RequestContext]
) -> None:
    off = make("off", 90)
    type(off).default_enabled = False
    reg = Registry(memory_store, [make("a", 60), off])
    eng = Engine(reg, memory_store)
    assert (await eng.evaluate(make_ctx())).blocked
    await reg.set_enabled("a", False)
    assert not (await eng.evaluate(make_ctx(), slug="a")).blocked
    assert await memory_store.get("toggle:a") == "0"
    await reg.set_enabled("off", True)
    assert (await eng.evaluate(make_ctx(), slug="off")).score == 90


async def test_exception_becomes_warn(
    memory_store: MemoryStore, make_ctx: Callable[..., RequestContext]
) -> None:
    eng = Engine(Registry(memory_store, [Boom()]), memory_store)
    rep = await eng.evaluate(make_ctx())
    assert rep.signals[0].verdict == Verdict.WARN and "kaput" in rep.signals[0].reason


async def test_ring_buffer_and_subscribers(
    memory_store: MemoryStore, make_ctx: Callable[..., RequestContext]
) -> None:
    eng = Engine(Registry(memory_store, [make("a", 1)]), memory_store)
    q = eng.subscribe()
    for _ in range(RING_SIZE + 5):
        await eng.evaluate(make_ctx())
    assert len(eng.reports) == RING_SIZE
    assert q.qsize() == RING_SIZE + 5
    assert eng.recent(3)[0] is eng.reports[-1]
    eng.unsubscribe(q)
    await eng.evaluate(make_ctx())
    assert q.qsize() == RING_SIZE + 5
    await eng.reset()
    assert not eng.reports


def test_discover_modules_runs() -> None:
    assert isinstance(discover_modules(), list)
