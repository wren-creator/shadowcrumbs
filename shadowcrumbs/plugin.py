"""Plugin base class, registry and loader.

A data source is a class with a name, a tier and a run() generator that yields Finding objects.
Drop a .py file in plugins_user/ and it is picked up on the next start, no core changes needed.
"""
import importlib
import importlib.util
import pkgutil
from dataclasses import dataclass, field
from typing import Callable

from . import config

REGISTRY: dict = {}
LOAD_ERRORS: dict = {}


@dataclass
class Finding:
    category: str
    value: str
    url: str | None = None
    confidence: int = 50
    notes: str | None = None


@dataclass
class Context:
    target: dict          # company, domain, ip (None when not given)
    search: object        # SearchClient
    http: object          # HttpClient
    store: object         # Store, so plugins can read earlier findings
    log: Callable = field(default=lambda msg: None)


class Plugin:
    name = ""
    tier = "search"           # "search" or "deep"
    description = ""
    categories: tuple = ()
    needs_any: tuple = ()     # runs when at least one of these target fields is set
    order = 50                # lower runs first, so discovery goes before enrichment
    touches_target = False    # True when it sends traffic straight to the client

    def applicable(self, target):
        return not self.needs_any or any(target.get(k) for k in self.needs_any)

    def unavailable(self):
        """Return a short reason when the plugin cannot run right now (a missing API key, say), else None.
        The run is recorded as skipped with that reason instead of failing."""
        return None

    def run(self, ctx):
        raise NotImplementedError


def register(cls):
    inst = cls()
    if not inst.name:
        raise ValueError(f"{cls.__name__} needs a name")
    if inst.tier not in ("search", "deep"):
        raise ValueError(f"{inst.name}: tier must be 'search' or 'deep'")
    REGISTRY[inst.name] = inst
    return cls


def load_plugins():
    from . import plugins as builtin

    for mod in pkgutil.iter_modules(builtin.__path__):
        importlib.import_module(f"{builtin.__name__}.{mod.name}")

    LOAD_ERRORS.clear()
    for d in [config.user_plugins_dir(), *config.personal_plugin_dirs()]:
        if not d.is_dir():
            continue
        for f in sorted(d.glob("*.py")):
            if f.name.startswith("_"):
                continue
            try:
                spec = importlib.util.spec_from_file_location(f"shadowcrumbs_user_{f.stem}", f)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
            except Exception as e:  # a broken user plugin must not take the app down
                LOAD_ERRORS[f.name] = f"{type(e).__name__}: {e}"


def describe():
    rows = []
    for p in sorted(REGISTRY.values(), key=lambda p: (p.tier != "search", p.order, p.name)):
        rows.append({
            "name": p.name, "tier": p.tier, "description": p.description,
            "categories": list(p.categories), "needs_any": list(p.needs_any),
            "touches_target": p.touches_target,
        })
    return rows
