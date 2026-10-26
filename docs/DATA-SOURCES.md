# Data sources: the pentester's search engine list

A reference list of 24 services pentesters lean on for recon, and where each one could plug into Shadowcrumbs. crt.sh, urlscan.io and GitHub code search are built today. The rest are a menu, so pick what you have keys for and write the plugin. See [CONTRIBUTING.md](../CONTRIBUTING.md).

I wrote the notes from what I know of these services. Free tiers, pricing and terms change, so check each one's current docs before you build on it. Nothing here has been tested against the live service.

## How they would fit

Shadowcrumbs has a rule worth keeping: the **search tier** only reads public search listings and never touches the client, and the **deep tier** is for direct lookups and APIs behind the authorization gate. Every keyed service below goes in the deep tier. Most of them never send a packet to the client (they answer from their own scans), so those set `touches_target = False`. They do send the client's domain or IP to a third party, so say so in each plugin's description, the way the credential sources do.

Keys come from environment variables, one per service, and a source without its key shows as **skipped**, not failed. Use `unavailable()` for that. Name them like the existing ones, for example `HUNTER_API_KEY`.

## Already in the project

| # | Service | What it is | Where it lives |
|---|---|---|---|
| 22 | crt.sh | Certificate transparency search | `crtsh` plugin, deep tier, no key |
| 16 | urlscan.io | Hosts, IPs and server software from public scans of the domain | `urlscan_search` plugin, deep tier, no key needed. The free search reaches back 30 days, and `URLSCAN_API_KEY` raises the limits. Response shape and rate limits checked against the live API on 2026-10-09 |
| n/a | GitHub code search (not on the original list) | Public code that mentions the domain: repos, hostnames, addresses, config-like files | `github_code_search` plugin, deep tier, needs `GITHUB_TOKEN`. Checked against the live API on 2026-10-09. Keeps no code, drops private repos and vendored library copies. Config-like file hits and the hosts and addresses found land as their own findings now, each with the file's URL, not only a repo-level count |
| n/a | web.archive.org (not on the original list) | Historical URLs that look like admin pages, backups, configs or old logins | `wayback_urls` plugin (`plugins_user/`), deep tier, no key | 
| n/a | passive and guessed subdomains (not on the original list) | CertSpotter, HackerTarget, AlienVault OTX and JLDC (keyless, the domain is sent to each), plus a wordlist guess that keeps names which resolve, with wildcard DNS detected and ignored | `passive_subdomains` and `subdomain_brute` (`shadowcrumbs/plugins/subdomain_sources.py`), deep tier. The brute force is gated like the rest of the deep tier. Wordlist: `source_packs/subdomains.txt`, or `SHADOWCRUMBS_SUBDOMAIN_WORDLIST` |
| n/a | links on the client's own sites (not on the original list) | Follows links six clicks deep on the domain and each live subdomain and reports linked documents, other hosts, ports named in links, contact addresses and login or upload forms | `site_spider` (`shadowcrumbs/plugins/spider.py`), deep tier, touches the client so it is gated. Stays inside the domain, follows redirects by hand only while they stay inside it, 200 page cap and 30 pages per host, so a big site is cut off by the caps before the depth. Linked documents go to `doc_metadata` and `doc_content`, which open and read them |
| n/a | open TCP ports (not on the original list) | Connect scan of the public addresses the domain and each subdomain resolve to, on a mainframe-aware list (telnet, TN3270, DB2, MQ, WebSphere, plus common exposed services). Listens for a banner on services that speak first and never sends data. Notes cleartext protocols and which hostnames point at the address | `port_scan` (`shadowcrumbs/plugins/portscan.py`), deep tier, gated. Private and reserved addresses are skipped, 20 address cap, 32 at a time. An address on shared hosting may belong to other tenants, confirm scope first. `SHADOWCRUMBS_PORTS` replaces the list |
| n/a | directory, backup, admin, login and debug path discovery (not on the original list) | Classifies URLs (from search listings, the Archive, GitHub code, and its own request) into an open directory, an exposed backup or secrets file, an admin page, a login portal, a debug/status page, a `/.well-known/` metadata file (OIDC config, app links, AI plugin manifest) or a sitemap/feed. The Archive plugin also keeps data files (json, xml, csv, xls, log) | `shadowcrumbs/paths.py` (shared classifier), used by `exposure_search` (search tier, indexed pages via `inurl:`/`intitle:`), `wayback_urls` and `exposure_probe` (deep tier, one GET per well-known path, including `/.well-known/*`, `robots.txt`, `sitemap.xml` and feeds, on the domain and each subdomain found so far) |
| 2 | google.com | Dork queries | The search tier already runs dork style queries (`site:`, `filetype:`, quoted `@domain`) through DuckDuckGo, and through Brave on a deep dive |

## Good fits, worth building

| # | Service | Best for | Shadowcrumbs category | Needs |
|---|---|---|---|---|
| 9 | hunter.io | Email addresses at a domain, plus the address pattern | `emails` | API key, small free tier |
| 4 | grep.app | Code search across public repos, for the domain's name in configs and leaked secrets | `infrastructure` | No official API, use with care |
| 1 | shodan.io | Hosts and open services on the client's addresses | `infrastructure`, `tech` | API key |
| 8 | censys.io | Hosts, services and certificates | `infrastructure`, `subdomains` | API id and secret |
| 14 | app.netlas.io | Same family: internet scan data | `infrastructure` | API key |
| 6 | onyphe.io | Same family | `infrastructure` | API key |
| 5, 20 | binaryedge.io | Same family (rows 5 and 20 are one vendor) | `infrastructure` | API key |
| 11 | zoomeye.org | Same family | `infrastructure` | API key |
| 10 | fofa.info | Same family, strong on Asia | `infrastructure` | API key and email |
| 18 | fullhunt.io | Attack surface and subdomains | `subdomains`, `infrastructure` | API key, free tier |
| 12 | leakix.net | Exposed services and known leaks | `infrastructure` | API key, free tier |
| 13 | intelx.io | Leak and OSINT search | `emails` | API key. Credential results must follow the no-password rule below |
| 23 | vulners.com | Turns the product and version strings you found into known vulnerabilities | `tech` | API key |
| 17 | publicwww.com | Finds sites by the HTML or JavaScript they serve, good for tech and shared tracking IDs | `tech` | Paid API |

The internet scanner family (Shodan, Censys, Netlas, ONYPHE, BinaryEdge, ZoomEye, FOFA, FullHunt, LeakIX) all do roughly the same job: give them a domain or IP range and get back hosts, ports and banners. Build one shared helper for turning a host record into findings, then each service is a short plugin on top.

## Poor fits, for now

| # | Service | What it is | Why it's low on the list |
|---|---|---|---|
| 15 | searchcode.com | Used to be a search across all public code | Checked 2026-10-09: the old search API now returns 404. It has become a per-repository analyzer built for AI assistants, and every call needs a repository you name. It could scan the client's own public repos for leaked secrets, but only once something else has found those repos |
| 3 | wigle.net | Wi-Fi network database | Looks up by location or SSID, not by company or domain. Useful for a physical or wireless assessment, which is a different tool |
| 7 | viz.greynoise.io | Mass internet scanner noise | Tells you whether an IP is background noise. Good for triage, not for discovery |
| 19 | socradar.io | Threat intelligence platform | Mostly a paid platform, with little open API for this use |
| 24 | pulsedive.com | Threat intelligence and indicator lookups | Enriches IPs and domains you already have. Could add notes to infrastructure findings later |
| 21 | ivre.rocks | IVRE, an open source recon framework | A self-hosted tool more than a service. A bridge to your own instance would be the way in |

## Rules for any new source

1. **Never store a password.** Credential style results record the address, where it was exposed and what kind of secret leaked, never any part of the secret. `tests/test_credentials.py` shows the test.
2. **Say what leaves the machine.** If the plugin sends the client's domain, IP or addresses to a third party, the description and the README must say so.
3. **Be polite.** Pace calls, cache results (`ctx.store.cache_get` and `cache_put`), and stop with a clear message on a 401 or 429 instead of hammering the service.
4. **Test with fakes.** No live network in the test suite. If you could not try the real service, say so in the README.
