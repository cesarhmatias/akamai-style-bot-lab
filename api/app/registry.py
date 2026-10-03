"""Auto-discovery of detection modules and persisted enable/disable toggles."""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from collections.abc import Iterable

from . import modules as modules_pkg
from .contract import DetectionModule, SessionStore


def discover_modules() -> list[DetectionModule]:
    """Import every submodule of ``app.modules`` and instantiate concrete subclasses."""
    found: dict[str, DetectionModule] = {}
    for info in pkgutil.iter_modules(modules_pkg.__path__):
        mod = importlib.import_module(f"{modules_pkg.__name__}.{info.name}")
        for _, cls in inspect.getmembers(mod, inspect.isclass):
            if (
                issubclass(cls, DetectionModule)
                and cls is not DetectionModule
                and not inspect.isabstract(cls)
                and cls.__module__ == mod.__name__
                and hasattr(cls, "slug")
            ):
                found[cls.slug] = cls()
    return sorted(found.values(), key=lambda m: m.slug)


class Registry:
    """Holds module instances and their enabled state (store key ``toggle:{slug}``)."""

    def __init__(self, store: SessionStore, modules: Iterable[DetectionModule] | None = None):
        self.store = store
        mods = list(modules) if modules is not None else discover_modules()
        self._modules: dict[str, DetectionModule] = {m.slug: m for m in mods}

    def all(self) -> list[DetectionModule]:
        return list(self._modules.values())

    def get(self, slug: str) -> DetectionModule | None:
        return self._modules.get(slug)

    async def is_enabled(self, slug: str) -> bool:
        module = self._modules[slug]
        raw = await self.store.get(f"toggle:{slug}")
        if raw is None:
            return module.default_enabled
        return raw == "1"

    async def set_enabled(self, slug: str, enabled: bool) -> None:
        if slug not in self._modules:
            raise KeyError(slug)
        await self.store.set(f"toggle:{slug}", "1" if enabled else "0")

    async def enabled_modules(self) -> list[DetectionModule]:
        return [m for m in self.all() if await self.is_enabled(m.slug)]
