import asyncio

from app.store import MemoryStore, make_store


async def test_get_set_delete(memory_store: MemoryStore) -> None:
    assert await memory_store.get("k") is None
    await memory_store.set("k", "v")
    assert await memory_store.get("k") == "v"
    await memory_store.delete("k")
    assert await memory_store.get("k") is None


async def test_ttl_expires(memory_store: MemoryStore) -> None:
    await memory_store.set("k", "v", ttl=1)
    assert await memory_store.get("k") == "v"
    memory_store._data["k"] = ("v", 0.0)  # force expiry
    assert await memory_store.get("k") is None


async def test_incr(memory_store: MemoryStore) -> None:
    assert await memory_store.incr("c", ttl=60) == 1
    assert await memory_store.incr("c") == 2
    memory_store._data["c"] = ("2", 0.0)
    assert await memory_store.incr("c") == 1


async def test_clear(memory_store: MemoryStore) -> None:
    await memory_store.set("a", "1")
    await asyncio.sleep(0)
    await memory_store.clear()
    assert await memory_store.get("a") is None


def test_make_store_selects(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.delenv("REDIS_URL", raising=False)
    assert isinstance(make_store(), MemoryStore)
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
    assert type(make_store()).__name__ == "RedisStore"


async def test_sliding_window(memory_store: MemoryStore) -> None:
    from app.store import window_add, window_count

    assert await window_count(memory_store, "w", 60, now=100.0) == 0
    assert await window_add(memory_store, "w", 60, now=100.0) == 1
    assert await window_add(memory_store, "w", 60, now=130.0) == 2
    assert await window_count(memory_store, "w", 60, now=150.0) == 2
    assert await window_count(memory_store, "w", 60, now=170.0) == 1  # first fell out
    assert await window_add(memory_store, "w", 60, now=400.0) == 1
