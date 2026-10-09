import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("SHADOWCRUMBS_DATA", str(tmp_path / "data"))
    monkeypatch.setenv("SHADOWCRUMBS_PLUGINS", str(tmp_path / "plugins_user"))
    monkeypatch.setenv("SHADOWCRUMBS_SEARCH", "fixture")
    monkeypatch.setenv("SHADOWCRUMBS_FIXTURE", str(ROOT / "fixtures" / "demo.json"))
    monkeypatch.setenv("SHADOWCRUMBS_SEARCH_DELAY", "0")
    monkeypatch.setenv("SHADOWCRUMBS_ALLOWED_HOSTS", "testserver")   # TestClient's default Host
    from shadowcrumbs import engine
    engine.STATE.clear()


@pytest.fixture
def demo():
    from shadowcrumbs.store import Store
    return Store.create("Acme Demo", company="Acme Demo Corp", domain="acme-demo.test")
