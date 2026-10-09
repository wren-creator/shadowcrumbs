# Roadmap

## Next up (start 2026-10-09)

In order. Items marked **needs a key** can wait until there is one, so skip down the list.

- [ ] Re-measure DuckDuckGo from a different network (2026-10-09: from this IP one query works and the next, a minute or two later, is blocked, same pattern as before. The IP may be flagged, or DDG's HTML endpoint may just be hostile to scrapers). One check query, then `tools/measure_ddg.py --paces 10,5,2.5 --per-pace 20`. If a fresh IP takes the slow paces, the 8 second default is right. If not, make a Brave key the recommended route
- [ ] hunter.io plugin: emails and the address pattern for the domain (**needs a key**, small free tier)
- [ ] Shared helper for the internet scanners, then short plugins on top: Shodan, Censys, Netlas, ONYPHE, BinaryEdge, ZoomEye, FOFA, FullHunt, LeakIX (**each needs a key**)
- [ ] Live-verify the HIBP and DeHashed plugins, they were built from the vendors' docs and fake responses (**needs keys**)
- [ ] Decide whether to keep the Firefox-style default user agent, the README discloses it

## Backlog

- [ ] Vulners plugin: turn product and version strings from the tech findings into known CVEs
- [ ] IntelX credential source, following the no-password rule
- [ ] PublicWWW plugin for tech and shared tracking IDs (paid API)
- [ ] More search providers (Bing, SearXNG) as a fallback for DDG throttling
- [ ] Optional opt-in to keep plaintext secrets, with masked exports, if a real engagement needs it
- [ ] Optional config flag to relax the authorization gate

The full list of candidate sources, and where each one fits, is in [docs/DATA-SOURCES.md](docs/DATA-SOURCES.md).

## Done

- [x] Verify the DuckDuckGo parser against the live site (2026-10-07: layout confirmed, sponsored results now filtered)
- [x] Handle DDG throttling: stop on the first block and stay quiet for an hour (blocks measured at 50+ minutes, retrying cannot help)
- [x] Credentials/breach sources: HIBP, DeHashed, local feed import (2026-10-07), never stores passwords
- [x] Refuse unknown Host and cross-site Origin headers (DNS rebinding)
- [x] GPL-3.0 licence, responsible use section, CONTRIBUTING.md, repo public (2026-10-08)
- [x] urlscan.io plugin (2026-10-09): hosts, IPs grouped by network, and server software from public scans. Checked against the live API, no key needed
- [x] Dashboard safety tests (2026-10-09): a source check plus a real browser test with hostile findings, both proven to catch deliberate breakage
- [x] GitHub code search plugin (2026-10-09): public repos, hostnames and addresses that mention the domain, no code kept, private repos dropped. Checked against the live API
- [x] Catalog of 24 pentester search engines mapped to Shadowcrumbs categories, pushed (2026-10-09)
