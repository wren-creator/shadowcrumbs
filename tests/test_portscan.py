import pytest

from shadowcrumbs import config
from shadowcrumbs.plugin import REGISTRY, Context, load_plugins
from shadowcrumbs.plugins import portscan as ps
from shadowcrumbs.store import Store

load_plugins()


@pytest.fixture
def store():
    s = Store.create("Ports", company="Acme", domain="acme.test")
    s.add_finding("subdomains", "mainframe.acme.test", "t", "search")
    s.add_finding("subdomains", "internal.acme.test", "t", "search")
    return s


def run(store, monkeypatch, dns, open_ports, ip=None):
    """open_ports: {(ip, port): banner bytes}. Anything else is closed."""
    monkeypatch.setattr("shadowcrumbs.plugins.subdomain_sources.a_records", lambda h: dns.get(h, set()))
    seen = []
    monkeypatch.setattr(ps, "probe_port", lambda a, p: (seen.append((a, p)), open_ports.get((a, p)))[1])
    meta = store.meta()
    logs = []
    ctx = Context(target={"company": "Acme", "domain": "acme.test", "ip": ip}, search=None, http=None, store=store,
                  log=lambda m, level="info": logs.append(m))
    return list(REGISTRY["port_scan"].run(ctx)), seen, logs


DNS = {"acme.test": {"93.184.216.34"}, "mainframe.acme.test": {"93.184.216.34"}, "internal.acme.test": {"10.0.0.5"}}


def test_open_ports_become_findings_with_hosts_banner_and_mainframe_context(store, monkeypatch):
    found, _, _ = run(store, monkeypatch, DNS, {("93.184.216.34", 23): b"\xff\xfd\x18\xff\xfd\x1b", ("93.184.216.34", 443): b""})
    by = {f.value: f for f in found}
    assert set(by) == {"93.184.216.34:23 open (telnet)", "93.184.216.34:443 open (https)"}
    t = by["93.184.216.34:23 open (telnet)"]
    assert "acme.test, mainframe.acme.test" in t.notes and "TN3270" in t.notes
    assert "Mainframe related" in t.notes and "Telnet is sent in the clear" in t.notes
    assert "Mainframe" not in by["93.184.216.34:443 open (https)"].notes


def test_private_addresses_are_never_scanned(store, monkeypatch):
    found, seen, logs = run(store, monkeypatch, DNS, {("10.0.0.5", 23): b""})
    assert found == [] and all(a == "93.184.216.34" for a, _ in seen)
    assert any("10.0.0.5" in m and "not a public address" in m for m in logs)


def test_the_address_cap_holds(store, monkeypatch):
    monkeypatch.setattr(config, "MAX_PORTSCAN_IPS", 2)
    dns = {"acme.test": {f"8.8.8.{i}" for i in range(1, 6)}}
    _, seen, logs = run(store, monkeypatch, dns, {})
    assert {a for a, _ in seen} == {"8.8.8.1", "8.8.8.2"} and any("first 2" in m for m in logs)


def test_a_single_ip_target_is_scanned_but_a_range_is_not(store, monkeypatch):
    _, seen, _ = run(store, monkeypatch, {}, {}, ip="9.9.9.9")
    assert {a for a, _ in seen} == {"9.9.9.9"}
    _, seen, _ = run(store, monkeypatch, {}, {}, ip="9.9.9.0/24")
    assert seen == []


def test_ports_come_from_the_environment_and_bad_entries_are_dropped(monkeypatch):
    monkeypatch.setenv("SHADOWCRUMBS_PORTS", "23, 3270,abc,99999,0,23, 8000")
    assert config.scan_ports() == [23, 3270, 8000]
    monkeypatch.setenv("SHADOWCRUMBS_PORTS", "junk")
    assert config.scan_ports() == list(config.DEFAULT_PORTS)
    monkeypatch.delenv("SHADOWCRUMBS_PORTS")
    assert {23, 992, 3270, 448, 2809, 50000} <= set(config.scan_ports())


def test_banners_are_made_readable_and_binary_is_named():
    assert ps.describe_banner(22, b"SSH-2.0-OpenSSH_9.6\r\n") == "SSH-2.0-OpenSSH_9.6"
    assert "TN3270" in ps.describe_banner(23, b"\xff\xfd\x18")
    assert ps.describe_banner(21, b"") == ""


def test_public_ip_rejects_private_loopback_and_junk():
    assert ps.public_ip("203.0.113.10") is None          # documentation range, not a real host
    assert ps.public_ip("8.8.8.8") == "8.8.8.8"
    assert ps.public_ip("10.1.2.3") is None and ps.public_ip("127.0.0.1") is None and ps.public_ip("not an ip") is None
