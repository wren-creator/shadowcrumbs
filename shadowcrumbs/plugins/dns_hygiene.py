"""DNS hygiene and zone transfer. Two things a client's DNS should get right and often does not.

dns_hygiene reads what is published: CAA, DNSSEC, the SPF record's shape, how many name servers there are.
zone_transfer asks each name server for the whole zone (AXFR). Servers should refuse. One that does not hands over
every host name the client has, so it is both a finding and a very good subdomain source.
"""
import re

import dns.exception
import dns.name
import dns.query
import dns.rdatatype
import dns.xfr

from .. import config
from ..plugin import Finding, Plugin, register
from ..util import clip, in_domain
from . import subdomain_sources
from .deep_plugins import dns_check, dns_lookup

AXFR_LIFETIME = 10
AXFR_TIMEOUT = 5
# SPF counts these toward its limit of ten DNS lookups (RFC 7208, section 4.6.4)
SPF_LOOKUP_TERM = re.compile(r"^[+\-~?]?(include:|a(:|/|$)|mx(:|/|$)|ptr(:|$)|exists:|redirect=)", re.I)


def spf_lookups(record):
    """How many terms in one SPF record cost a DNS lookup. Only the top record, includes are not followed,
    so the real count can be higher."""
    return sum(1 for term in record.split()[1:] if SPF_LOOKUP_TERM.match(term))


def attempt_axfr(ip, domain):
    """Ask one server for the zone. Returns (outcome, names): open with the host names it gave, refused, or failed."""
    names, seen = set(), 0
    try:
        for msg in dns.query.xfr(ip, domain, lifetime=AXFR_LIFETIME, timeout=AXFR_TIMEOUT):
            for rrset in msg.answer:
                seen += 1
                n = rrset.name.to_text().rstrip(".").lower()
                if n and n != domain.lower():
                    names.add(n)
            if len(names) >= config.MAX_AXFR_NAMES:
                break
    except dns.xfr.TransferError:
        return "refused", set()
    except (dns.exception.DNSException, OSError, EOFError):
        return ("open", names) if seen else ("failed", set())
    return ("open", names) if seen else ("refused", set())


@register
class DnsHygiene(Plugin):
    name = "dns_hygiene"
    tier = "deep"
    description = (
        "What the domain's DNS publishes about its own safety: CAA (who may issue certificates), DNSSEC, "
        "an SPF record that is broken or over the ten lookup limit, and a single point of failure in the name servers."
    )
    categories = ("infrastructure",)
    needs_any = ("domain",)
    order = 11
    touches_target = True

    def verify(self, http):
        return dns_check()

    def run(self, ctx):
        d = ctx.target["domain"]

        caa, st = dns_lookup(d, "CAA")
        if caa:
            yield Finding("infrastructure", f"CAA: {clip('; '.join(caa), 200)}", confidence=90,
                          notes="Only the listed authorities may issue certificates for this domain.")
        elif st == "empty":
            yield Finding("infrastructure", "No CAA record", confidence=85,
                          notes="Any certificate authority may issue a certificate for this domain. "
                                "A CAA record narrows that to the ones the client actually uses.")

        keys, kst = dns_lookup(d, "DNSKEY")
        ds, dst = dns_lookup(d, "DS")
        if keys and ds:
            yield Finding("infrastructure", "DNSSEC signed", confidence=85,
                          notes="Keys are published and the parent zone holds a DS record. "
                                "This checks they exist, not that the signatures validate.")
        elif keys:
            yield Finding("infrastructure", "DNSSEC half set up", confidence=80,
                          notes="The zone publishes keys but the parent has no DS record, so no resolver will validate it.")
        elif kst == "empty" and dst == "empty":
            yield Finding("infrastructure", "DNSSEC not signed", confidence=85,
                          notes="Answers for this domain cannot be checked for tampering in transit.")

        txt, _ = dns_lookup(d, "TXT")
        spf = [t.strip('"') for t in txt if t.strip('"').lower().startswith("v=spf1")]
        if len(spf) > 1:
            yield Finding("infrastructure", f"{len(spf)} SPF records published", confidence=90,
                          notes="A domain gets one SPF record. With more, receivers treat SPF as a permanent error "
                                "and the protection is gone.")
        for s in spf[:1]:
            n = spf_lookups(s)
            if n > 10:
                yield Finding("infrastructure", f"SPF needs {n} DNS lookups, the limit is 10", confidence=80,
                              notes="Over the limit, receivers return a permanent error and ignore the record. "
                                    "Counted from the top record only, so the real number can be higher.")
            if re.search(r"(^|\s)[+\-~?]?ptr(:|\s|$)", s, re.I):
                yield Finding("infrastructure", "SPF uses the ptr mechanism", confidence=80,
                              notes="RFC 7208 says not to use it. It is slow and easy to get wrong.")

        ns, _ = dns_lookup(d, "NS")
        if len({n.lower() for n in ns}) == 1:
            yield Finding("infrastructure", "Only one name server", confidence=90,
                          notes=f"{ns[0].rstrip('.')} is a single point of failure. Registries ask for at least two.")


@register
class ZoneTransfer(Plugin):
    name = "zone_transfer"
    tier = "deep"
    description = (
        "Asks each of the domain's name servers for a full zone transfer (AXFR). A properly set up server refuses. "
        "If one hands the zone over, every host name in it is reported and added to the subdomains. "
        "The name servers may belong to a hosting provider, but the request is only ever for the client's own zone."
    )
    categories = ("infrastructure", "subdomains")
    needs_any = ("domain",)
    order = 12
    touches_target = True

    def verify(self, http):
        return dns_check()

    def run(self, ctx):
        d = ctx.target["domain"]
        ns, _ = dns_lookup(d, "NS")
        servers = sorted({n.rstrip(".").lower() for n in ns})
        if not servers:
            ctx.log("zone_transfer: no name servers found for the domain", "warning")
        for server in servers:
            ips = sorted(subdomain_sources.a_records(server))
            if not ips:
                ctx.log(f"zone_transfer: {server} does not resolve, skipped", "warning")
                continue
            outcome, names = attempt_axfr(ips[0], d)
            if outcome == "refused":
                yield Finding("infrastructure", f"Zone transfer refused by {server}", confidence=90,
                              notes="Good. The server would not hand over the zone.")
            elif outcome == "failed":
                yield Finding("infrastructure", f"Zone transfer to {server} could not be tried", confidence=40,
                              notes="The server did not answer a transfer request in time. Not a clean result either way.")
            else:
                shown = ", ".join(sorted(names)[:8])
                yield Finding("infrastructure", f"Zone transfer allowed by {server}", confidence=99,
                              notes=f"Anyone can download the whole zone from this server. {len(names)} names, "
                                    f"for example: {shown}. Restrict AXFR to the secondary servers by address or key.")
                for n in sorted(names):
                    if in_domain(n, d):
                        yield Finding("subdomains", n, confidence=95, notes=f"From a zone transfer on {server}")
