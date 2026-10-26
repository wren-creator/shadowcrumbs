"""A plain TCP connect scan of the addresses the client's hostnames point at.

Connect only: it opens a socket, listens briefly for a banner on services that speak first, and closes. It never
sends anything to the service. Mainframe ports are on the default list because that is where a z/OS shop shows itself.
"""
import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor

from .. import config
from ..plugin import Finding, Plugin, register
from ..util import clip
from . import subdomain_sources

CONNECT_TIMEOUT = 2.0
BANNER_WAIT = 1.5
# services that talk first, so listening is worth a moment. The rest wait for the client, listening would only stall.
SPEAKS_FIRST = {21, 22, 23, 25, 110, 143, 3270, 5900}

SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 80: "http", 110: "pop3", 143: "imap", 175: "vmnet", 443: "https",
    445: "smb", 446: "db2 drda", 448: "db2 drda over tls", 992: "telnet over tls", 993: "imaps", 995: "pop3s",
    1414: "ibm mq", 1433: "mssql", 1521: "oracle", 2809: "websphere bootstrap", 3270: "tn3270", 3306: "mysql",
    3389: "rdp", 5432: "postgres", 5900: "vnc", 8080: "http alt", 8443: "https alt", 9080: "http alt", 9443: "https alt",
    50000: "db2",
}
# ports that point at a mainframe or its middleware, and the one line saying why
MAINFRAME = {
    23: "Telnet is how most z/OS shops reach TSO and TN3270.", 175: "VMNET, used by z/VM.",
    446: "DB2 DRDA, the DB2 for z/OS network port.", 448: "DB2 DRDA over TLS.", 992: "Telnet over TLS, often TN3270.",
    1414: "IBM MQ listener.", 2809: "WebSphere bootstrap, often next to CICS.", 3270: "The conventional TN3270 port.",
    50000: "DB2 default port.",
}
# these send credentials or data in the clear, worth a line in the report
CLEARTEXT = {21: "FTP", 23: "Telnet", 25: "SMTP", 110: "POP3", 143: "IMAP", 5900: "VNC"}


def describe_banner(port, data):
    """One short readable line from the first bytes a service sent, or ''. Telnet negotiation is binary, so name it."""
    if not data:
        return ""
    if data[:1] == b"\xff":
        return "telnet option negotiation" + (" (asks for a terminal type, typical of TN3270)" if b"\xff\xfd\x18" in data[:12] else "")
    text = data.decode("latin-1", "replace")
    text = "".join(c if 32 <= ord(c) < 127 else " " for c in text).strip()
    return clip(" ".join(text.split()), 100)


def probe_port(ip, port):
    """None when the port is closed or filtered. Otherwise the banner bytes, b'' when the service said nothing."""
    try:
        s = socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT)
    except OSError:
        return None
    try:
        if port in SPEAKS_FIRST:
            s.settimeout(BANNER_WAIT)
            try:
                return s.recv(128)
            except OSError:
                return b""
        return b""
    finally:
        s.close()


def public_ip(text):
    """The address as a string if it is a public one, else None. Private, loopback and reserved addresses are never scanned."""
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return None
    return str(ip) if ip.is_global else None


@register
class PortScan(Plugin):
    name = "port_scan"
    tier = "deep"
    description = (
        "TCP connect scan of the addresses the domain and its subdomains resolve to, on a mainframe-aware port list "
        "(telnet, TN3270, DB2, MQ, WebSphere and the common exposed services). Listens for a banner, never sends data. "
        "Skips private addresses. An address on shared hosting may belong to other tenants, so confirm scope."
    )
    categories = ("infrastructure",)
    needs_any = ("domain", "ip")
    order = 45
    touches_target = True

    def run(self, ctx):
        names = {}                                   # address -> hostnames that point at it
        if ctx.target.get("domain"):
            d = ctx.target["domain"]
            for h in [d] + [f["value"] for f in ctx.store.findings("subdomains")][: config.MAX_RESOLVE_HOSTS]:
                for ip in subdomain_sources.a_records(h):
                    names.setdefault(ip, []).append(h)
        given = ctx.target.get("ip")
        if given and "/" not in given:
            names.setdefault(given, []).append(given)
        targets = []
        for ip in sorted(names):
            if public_ip(ip):
                targets.append(ip)
            else:
                ctx.log(f"port_scan: {ip} is not a public address, skipped", "warning")
        if len(targets) > config.MAX_PORTSCAN_IPS:
            ctx.log(f"port_scan: {len(targets)} addresses, scanning the first {config.MAX_PORTSCAN_IPS}", "warning")
            targets = targets[: config.MAX_PORTSCAN_IPS]
        jobs = [(ip, p) for ip in targets for p in config.scan_ports()]
        with ThreadPoolExecutor(max_workers=32) as pool:
            for (ip, port), banner in zip(jobs, pool.map(lambda j: probe_port(*j), jobs)):
                if banner is None:
                    continue
                service = SERVICES.get(port, "unknown service")
                hosts = ", ".join(sorted(set(names[ip]))[:4])
                said = describe_banner(port, banner)
                notes = [f"Resolves from {hosts}."]
                if said:
                    notes.append(f"Banner: {said}.")
                if port in MAINFRAME:
                    notes.append(f"Mainframe related. {MAINFRAME[port]}")
                if port in CLEARTEXT:
                    notes.append(f"{CLEARTEXT[port]} is sent in the clear.")
                yield Finding("infrastructure", f"{ip}:{port} open ({service})", confidence=95, notes=" ".join(notes))
