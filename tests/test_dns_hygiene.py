import dns.xfr
import pytest

from shadowcrumbs import config
from shadowcrumbs.plugin import REGISTRY, Context, load_plugins
from shadowcrumbs.plugins import dns_hygiene as dh

load_plugins()


def run(name, monkeypatch, records=None, axfr=None, a=None):
    """records: {(host, type): (list, status)}. axfr: {server ip: (outcome, names)}. a: {host: set of ips}."""
    records = records or {}
    monkeypatch.setattr(dh, "dns_lookup", lambda h, t: records.get((h, t), ([], "empty")))
    monkeypatch.setattr("shadowcrumbs.plugins.subdomain_sources.a_records", lambda h: (a or {}).get(h, set()))
    monkeypatch.setattr(dh, "attempt_axfr", lambda ip, d: (axfr or {}).get(ip, ("failed", set())))
    logs = []
    ctx = Context(target={"domain": "acme.test"}, search=None, http=None, store=None,
                  log=lambda m, level="info": logs.append(m))
    return list(REGISTRY[name].run(ctx)), logs


def values(found):
    return [f.value for f in found]


def test_a_bare_domain_gets_no_caa_and_unsigned_flags(monkeypatch):
    found, _ = run("dns_hygiene", monkeypatch)
    assert values(found) == ["No CAA record", "DNSSEC not signed"]


def test_a_failed_lookup_is_never_called_a_missing_record(monkeypatch):
    err = ([], "error")
    found, _ = run("dns_hygiene", monkeypatch, {("acme.test", "CAA"): err, ("acme.test", "DNSKEY"): err, ("acme.test", "DS"): err})
    assert found == []


def test_caa_and_full_dnssec_are_reported_as_in_place(monkeypatch):
    found, _ = run("dns_hygiene", monkeypatch, {
        ("acme.test", "CAA"): (['0 issue "letsencrypt.org"'], "ok"),
        ("acme.test", "DNSKEY"): (["257 3 13 abc"], "ok"), ("acme.test", "DS"): (["1 13 2 abc"], "ok")})
    assert values(found) == ['CAA: 0 issue "letsencrypt.org"', "DNSSEC signed"]


def test_keys_without_a_ds_record_is_called_half_set_up(monkeypatch):
    found, _ = run("dns_hygiene", monkeypatch, {("acme.test", "DNSKEY"): (["257 3 13 abc"], "ok")})
    assert "DNSSEC half set up" in values(found)


def test_two_spf_records_and_ptr_are_flagged(monkeypatch):
    found, _ = run("dns_hygiene", monkeypatch, {("acme.test", "TXT"): (['"v=spf1 ptr -all"', '"v=spf1 mx -all"'], "ok")})
    assert "2 SPF records published" in values(found)
    assert "SPF uses the ptr mechanism" in values(found)


def test_spf_lookup_counting():
    rec = "v=spf1 ip4:1.2.3.4 " + " ".join(f"include:s{i}.test" for i in range(9)) + " mx a:x.test ~all"
    assert dh.spf_lookups(rec) == 11
    assert dh.spf_lookups("v=spf1 ip4:1.2.3.4 ip6:::1 -all") == 0


def test_over_ten_spf_lookups_is_a_finding(monkeypatch):
    rec = "v=spf1 " + " ".join(f"include:s{i}.test" for i in range(11)) + " -all"
    found, _ = run("dns_hygiene", monkeypatch, {("acme.test", "TXT"): ([f'"{rec}"'], "ok")})
    assert any(v.startswith("SPF needs 11 DNS lookups") for v in values(found))


def test_a_single_name_server_is_flagged(monkeypatch):
    found, _ = run("dns_hygiene", monkeypatch, {("acme.test", "NS"): (["ns1.acme.test."], "ok")})
    assert "Only one name server" in values(found)


NS = {("acme.test", "NS"): (["ns1.acme.test.", "ns2.acme.test."], "ok")}
A = {"ns1.acme.test": {"203.0.113.1"}, "ns2.acme.test": {"203.0.113.2"}}


def test_refused_transfers_are_reported_as_good(monkeypatch):
    found, _ = run("zone_transfer", monkeypatch, NS, {"203.0.113.1": ("refused", set()), "203.0.113.2": ("refused", set())}, A)
    assert values(found) == ["Zone transfer refused by ns1.acme.test", "Zone transfer refused by ns2.acme.test"]


def test_an_open_transfer_is_a_high_confidence_finding_and_feeds_the_subdomains(monkeypatch):
    names = {"mainframe.acme.test", "vpn.acme.test", "mail.elsewhere.test"}
    found, _ = run("zone_transfer", monkeypatch, NS, {"203.0.113.1": ("open", names), "203.0.113.2": ("refused", set())}, A)
    by = {f.value: f for f in found}
    assert by["Zone transfer allowed by ns1.acme.test"].confidence == 99
    assert "3 names" in by["Zone transfer allowed by ns1.acme.test"].notes
    subs = sorted(f.value for f in found if f.category == "subdomains")
    assert subs == ["mainframe.acme.test", "vpn.acme.test"]          # a name outside the domain is not ours to add


def test_a_server_that_does_not_resolve_or_answer_is_not_called_refused(monkeypatch):
    found, logs = run("zone_transfer", monkeypatch, NS, {"203.0.113.1": ("failed", set())}, {"ns1.acme.test": {"203.0.113.1"}})
    assert values(found) == ["Zone transfer to ns1.acme.test could not be tried"]
    assert found[0].confidence < 50 and any("ns2.acme.test" in m for m in logs)


class Msg:
    def __init__(self, *names):
        self.answer = [type("R", (), {"name": type("N", (), {"to_text": lambda s, n=n: n})()})() for n in names]


def test_attempt_axfr_reads_names_and_treats_a_transfer_error_as_refused(monkeypatch):
    monkeypatch.setattr(dh.dns.query, "xfr", lambda *a, **k: iter([Msg("acme.test.", "www.acme.test."), Msg("vpn.acme.test.")]))
    assert dh.attempt_axfr("203.0.113.1", "acme.test") == ("open", {"www.acme.test", "vpn.acme.test"})

    def refuse(*a, **k):
        raise dns.xfr.TransferError(5)
        yield
    monkeypatch.setattr(dh.dns.query, "xfr", refuse)
    assert dh.attempt_axfr("203.0.113.1", "acme.test") == ("refused", set())

    def dead(*a, **k):
        raise ConnectionRefusedError()
        yield
    monkeypatch.setattr(dh.dns.query, "xfr", dead)
    assert dh.attempt_axfr("203.0.113.1", "acme.test")[0] == "failed"


def test_the_name_cap_stops_a_huge_zone(monkeypatch):
    monkeypatch.setattr(config, "MAX_AXFR_NAMES", 3)
    monkeypatch.setattr(dh.dns.query, "xfr", lambda *a, **k: iter([Msg(*[f"h{i}.acme.test." for i in range(5)]), Msg("late.acme.test.")]))
    outcome, names = dh.attempt_axfr("203.0.113.1", "acme.test")
    assert outcome == "open" and "late.acme.test" not in names
