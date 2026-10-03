"""Auto-discovery of detection modules and persisted enable/disable toggles."""

from __future__ import annotations

import importlib
import inspect
import os
import pkgutil
from collections.abc import Iterable

from . import modules as modules_pkg
from .contract import DetectionModule, FlagSpec, SessionStore


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

    # --- feature flags (v2) ----------------------------------------------------------

    def flag_specs(self) -> dict[str, FlagSpec]:
        """All flags declared by modules (plus engine-level ones), keyed by name."""
        specs: dict[str, FlagSpec] = {f.name: f for f in ENGINE_FLAGS}
        for m in self.all():
            for f in m.flags:
                specs[f.name] = f
        return specs

    async def flag_value(self, spec: FlagSpec) -> bool:
        raw = await self.store.get(f"flag:{spec.name}")
        if raw is not None:
            return raw == "1"
        env = os.environ.get(f"LAB_FLAG_{spec.name.upper()}")
        if env is not None:
            return env.strip().lower() in {"1", "true", "yes", "on"}
        return spec.default

    async def resolved_flags(self) -> dict[str, bool]:
        return {name: await self.flag_value(spec) for name, spec in self.flag_specs().items()}

    async def set_flag(self, name: str, value: bool) -> None:
        if name not in self.flag_specs():
            raise KeyError(name)
        await self.store.set(f"flag:{name}", "1" if value else "0")


# Engine-level flags (not owned by a module) are declared here.
ENGINE_FLAGS: list[FlagSpec] = []
