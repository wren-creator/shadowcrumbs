import json

import pytest
import requests

from shadowcrumbs.plugin import REGISTRY, Context, load_plugins
from shadowcrumbs.plugins import subdomain_sources as ss
from shadowcrumbs.store import Store

load_plugins()


class Resp:
    def __init__(self, status=200, text=""):
        self.status_code, self.text = status, text


class Http:
    def __init__(self, by_host):
        self.by_host = by_host

    def get(self, url, **kw):
        for key, reply in self.by_host.items():
            if key in url:
                if isinstance(reply, Exception):
                    raise reply
                return reply
        raise AssertionError(url)


@pytest.fixture
def store():
    return Store.create("Subs", company="Acme", domain="acme.test")


def run(name, store, http=None):
    meta = store.meta()
    logs = []
    ctx = Context(target={k: meta[k] for k in ("company", "domain", "ip")}, search=None, http=http, store=store,
                  log=lambda m, level="info": logs.append((level, m)))
    return list(REGISTRY[name].run(ctx)), logs


def test_parsers_keep_only_real_subdomains_of_the_target():
    d = "acme.test"
    assert ss.parse_hackertarget("intranet.acme.test,1.2.3.4\nevil.com,5.6.7.8\nacme.test,1.1.1.1\nAPI count exceeded", d) == {"intranet.acme.test"}
    assert ss.parse_otx(json.dumps({"passive_dns": [{"hostname": "A.acme.test"}, {"hostname": "x.other.test"}]}), d) == {"a.acme.test"}
    assert ss.parse_certspotter(json.dumps([{"dns_names": ["*.dev.acme.test", "acme.test", "notacme.test"]}]), d) == {"dev.acme.test"}
    assert ss.parse_jldc(json.dumps(["vpn.acme.test", "bad host.acme.test"]), d) == {"vpn.acme.test"}
    assert ss.parse_jldc("not json", d) == set()


def test_passive_merges_sources_and_survives_one_being_down(store):
    http = Http({
        "certspotter": Resp(200, json.dumps([{"dns_names": ["intranet.acme.test"]}])),
        "hackertarget": Resp(200, "intranet.acme.test,1.2.3.4\nautodiscover.acme.test,5.6.7.8"),
        "otx": requests.ConnectTimeout(),
        "jldc": Resp(503),
    })
    found, logs = run("passive_subdomains", store, http)
    by = {f.value: f for f in found}
    assert set(by) == {"intranet.acme.test", "autodiscover.acme.test"}
    assert by["intranet.acme.test"].confidence == 85 and "certspotter, hackertarget" in by["intranet.acme.test"].notes
    assert by["autodiscover.acme.test"].confidence == 75
    assert len(logs) == 2


def test_passive_errors_when_every_source_is_down(store):
    http = Http({k: Resp(500) for k in ("certspotter", "hackertarget", "otx", "jldc")})
    with pytest.raises(RuntimeError, match="none of the four"):
        run("passive_subdomains", store, http)


def test_brute_keeps_names_that_resolve_and_skips_known_ones(store, monkeypatch, tmp_path):
    wl = tmp_path / "w.txt"
    wl.write_text("# c\nintranet\nautodiscover\nnothere\nwww\n")
    monkeypatch.setenv("SHADOWCRUMBS_SUBDOMAIN_WORDLIST", str(wl))
    store.add_findings = None
    live = {"intranet.acme.test": {"10.0.0.5"}, "autodiscover.acme.test": {"10.0.0.6"}}
    monkeypatch.setattr(ss, "a_records", lambda n: live.get(n, set()))
    found, _ = run("subdomain_brute", store)
    assert {f.value for f in found} == {"intranet.acme.test", "autodiscover.acme.test"}
    assert "10.0.0.5" in next(f for f in found if f.value.startswith("intranet")).notes


def test_brute_ignores_a_wildcard_zone(store, monkeypatch, tmp_path):
    wl = tmp_path / "w.txt"
    wl.write_text("intranet\ndev\n")
    monkeypatch.setenv("SHADOWCRUMBS_SUBDOMAIN_WORDLIST", str(wl))
    answers = {"intranet.acme.test": {"9.9.9.9", "10.0.0.5"}}      # one real address mixed in with the wildcard one
    monkeypatch.setattr(ss, "a_records", lambda n: answers.get(n, {"9.9.9.9"}))
    found, logs = run("subdomain_brute", store)
    assert [f.value for f in found] == ["intranet.acme.test"]
    assert "10.0.0.5" in found[0].notes and "9.9.9.9" not in found[0].notes
    assert any("wildcard" in m for _, m in logs)


def test_the_shipped_wordlist_has_the_mainframe_names():
    words = set(ss.load_words())
    assert {"mainframe", "intranet", "autodiscover", "tn3270", "cics", "remote"} <= words
