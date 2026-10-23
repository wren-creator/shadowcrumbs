# Roadmap

## Next up (start 2026-10-09)

In order. Items marked **needs a key** can wait until there is one, so skip down the list.

- [ ] Re-measure DuckDuckGo from a different network (2026-10-09: from this IP one query works and the next, a minute or two later, is blocked, same pattern as before. A browser on the same network gets results from html.duckduckgo.com, so the IP is not banned and the script is what gets flagged). One check query, then `tools/measure_ddg.py --paces 10,5,2.5 --per-pace 20`. If a fresh IP takes the slow paces, the 8 second default is right. If not, make a Brave key the recommended route
- [ ] Look on GitHub for how SearXNG gets around the DuckDuckGo throttling (tip from Kev Milne, who says it is the secret to the DDG issue). Check the searxng/searxng repo's DuckDuckGo engine and its request headers, pacing and retry handling, then see what we can apply to our own DDG provider or to `tools/searxng.sh`
- [ ] A plugin that asks SearXNG's `it` category (`categories=it`: gitlab, bitbucket, codeberg, the vulnerability database) by company name and domain, since they are on but a dork never reaches them. Codeberg timed out on 2026-10-22, so give it a short timeout
- [ ] Find which SearXNG engines answer from a clean network. From this one only Bing and Yandex did (2026-10-22). Run the same dork from another IP and see whether google, brave, startpage and qwant survive
- [ ] hunter.io plugin: emails and the address pattern for the domain (**needs a key**, small free tier)
- [ ] Shared helper for the internet scanners, then short plugins on top: Shodan, Censys, Netlas, ONYPHE, BinaryEdge, ZoomEye, FOFA, FullHunt, LeakIX (**each needs a key**)
- [ ] Live-verify the HIBP and DeHashed plugins, they were built from the vendors' docs and fake responses (**needs keys**; DeHashed key and 500 credits confirmed live on 2026-10-22, one real domain search still to run). The new Verify page exercises the HIBP key check, so run it with a key and report what it says
- [ ] Decide whether to keep the Firefox-style default user agent, the README discloses it

## Backlog

- [ ] Measure the exposure queries on a domain that really has something exposed (a client, or a lab you set up). toysrus.com (2026-10-22, search tier only, public listings) gave 0 true hits from the new exposure queries, which is expected for a large retail site, so it proves the noise filters but not the hit rate
- [ ] Show an estimated Brave cost next to a scan (queries times the per-query price, set by the user), so nobody is surprised by a bill. A full scan is about 40 queries, 20 cents at $5 per 1,000

- [ ] Measure the hit rate of the new exposure queries on an authorised domain from the new network, then keep what earns its 8 seconds and drop the rest
- [ ] Snippet-free extractor for custom sources, so backup and config file searches (`ext:bak`, `ext:sql`) can be added without keeping text that might hold a secret

- [ ] Vulners plugin: turn product and version strings from the tech findings into known CVEs
- [ ] IntelX credential source, following the no-password rule
- [ ] PublicWWW plugin for tech and shared tracking IDs (paid API)
- [ ] More search providers (Bing) as a fallback for DDG throttling
- [ ] Ideas from Kev Milne's EZRecon (github.com/kmilne40/ezrecon, a different licence, so write our own from the ideas, credit in README): favicon hash pivot (same icon on other hosts), DNS-only subdomain takeover check, cloud bucket name guessing, document metadata (authors, software versions) from files we already find, GitHub dorking, a graph view of findings
- [ ] Optional opt-in to keep plaintext secrets, with masked exports, if a real engagement needs it
- [ ] Optional config flag to relax the authorization gate
- [ ] Custom sources: an optional regex extractor, once there is a safe way to bound its run time
- [ ] ROE register export (CSV or PDF) for the engagement file, with spreadsheet formula characters escaped
- [ ] Keep a ledger of deleted engagements (name, ROE history, deleted at) outside the engagement databases, so the register can still list them. Today only the app log remembers
- [ ] Log retention setting, and a way to clear one engagement's run events from the admin page

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
- [x] SearXNG provider plus `tools/searxng.sh` (2026-10-09): local Docker instance, checked live. Only one upstream engine answered from this network, the rest were CAPTCHA or suspended
- [x] ROE audit trail (2026-10-21): every authorization change records who and when, append only, mirrored to the app log. Admin page lists it per engagement
- [x] Scan logs (2026-10-21): per-run events in each engagement database plus a rotating app log, one redaction function in front of both, viewable on the admin page
- [x] Plugin templates and `tools/new_plugin.py` (2026-10-21): search and deep starters, name and path checks, never overwrites, tested by scaffolding and running one against the demo data
- [x] Sources page (2026-10-21): the team adds search data points from the dashboard with no code, hot reloaded, shareable by export or one shared file, with a revision lock. Data only, so it cannot run code or reach a client
- [x] Verify step (2026-10-21): checks each source's endpoint and key plus the search engines, on the admin page and with `tools/verify_sources.py`. Asks about example.com only, never queries DuckDuckGo live, keys scrubbed. Public services checked live; DeHashed's key is checked free through its account info endpoint (2026-10-22), HIBP still needs a real key
- [x] SearXNG suspended-engine handling (2026-10-21, idea from Kev Milne's EZRecon): an empty answer caused by throttled upstream engines retries once, then raises a block naming the engines, so it is never cached as "no footprint" for a week
- [x] `.env` loading and a search fallback chain (2026-10-21): Brave, then SearXNG, then DuckDuckGo, moving on when one is throttled. Brave runs at a query a second. First live run 2026-10-22: 34 searches through Brave in 61 seconds, no block, on a small domain with little exposed, so the query hit rate is still unmeasured
- [x] Mainframe label tightened (2026-10-22): `z/OS mainframe` needs the text `z/OS`. The bare word `mainframe` becomes `Mainframe (platform not stated)`, because a web emulator titled "Gibson Mainframe" was reported as z/OS at confidence 75. Applies to job posts, snippets, headers and titles alike
- [x] DMARC falls back to the parent domain (2026-10-22): a subdomain with no `_dmarc` record of its own inherits the parent's, as receivers do (RFC 7489), so intranet and remote stop being reported as unprotected when the apex has a policy. Found in a real report, checked live. `sp=` is honoured, and `sp=none; p=reject` is no longer misread as `p=none`
- [x] Clear search cache (2026-10-22): a dashboard button and `DELETE /api/engagements/{slug}/search-cache` forget the saved search answers for one engagement and keep its findings. Found when a report showed the search tier had run without Brave (a `.env` that was not 0600 loaded nothing) and a re-run would have been served the weak engines' cached answers for a week
- [x] Client-side search balancing (2026-10-22, opt-in with `SHADOWCRUMBS_SEARCH_BALANCE=1`): smooth weighted round robin over the engines with a share (Brave 3, SearXNG 2, DuckDuckGo and Exa 0 = reserve, `SHADOWCRUMBS_SEARCH_WEIGHTS` changes them). A throttled engine is replaced for that query and rejoins after `SHADOWCRUMBS_ENGINE_COOLDOWN` (300 seconds); a refused key, used up credits or a DuckDuckGo block stays out for the run. Pacing is per engine. The cache is deliberately not keyed by engine, so a re-run costs nothing. Per engine counts are in the run summary. Off by default because from this network Brave beat SearXNG on every measure (39 of 39 on-site against 4 of 21) and SearXNG's 8 second pace makes a balanced scan slower
- [ ] When an engine answers with nothing on the site (the off-target filter dropped everything), try the next engine for that same query instead of returning empty, and count it against the engine
- [ ] Let the shares follow measured quality: weight each engine by how many of its results survive the off-target filter over the last few queries, so one that mostly ignores `site:` fades out by itself
- [x] Off-target `site:` filter (2026-10-22): any answer to a query with a positive `site:host` term keeps only results on that host or its subdomains, whichever engine answered, and logs a warning naming the engine that ignored it. `-site:` exclusions and canned demo data are left alone. An answer where nothing was on the site is not cached, so a later run asks again. Checked live: Bing through SearXNG gave 12 results for `site:mozilla.org filetype:pdf`, 10 of them `bbb.org`, and 2 survived. Not filtered: `filetype:`, which the same engines also ignore (the 2 survivors were not PDFs)
- [ ] Count how often the off-target filter fires per engine over a few real scans, and decide whether an engine that ignores `site:` most of the time should be dropped from the chain. Also consider the same check for `filetype:`
- [x] `--searxng-port N` on the front door (2026-10-22): SearXNG on another port, remembered so `status` and `stop` follow it. Checked live by moving the container to 8899 and back
- [x] SearXNG on by default in the front door (2026-10-22): `./shadowcrumbs.sh start` brings it up when Docker is running and carries on without it when not, `--no-searxng` skips it and `--searxng` insists. `tools/searxng/settings.yml` now keeps 13 named engines and `up` recreates the container so settings edits apply (a replaced single-file mount is otherwise ignored by `restart`)
- [x] Exa checked live (2026-10-22, one query, `site:mozilla.org filetype:pdf`): HTTP 200 in 1.7 seconds, the request and response shape match what the code assumes (`x-api-key`, `results[].highlights` as a list, no notices). All 10 results were on mozilla.org, against 2 of 12 through SearXNG's Bing. `filetype:pdf` was mostly ignored (2 of 10 were PDFs). The API reported the cost as $0.007 for that one query, which is about 28 cents for a 40 query scan, more than Brave. Highlights come back as raw markdown (`## Heading ...`), left as is
- [x] Exa as the last search fallback (2026-10-22): `EXA_API_KEY`, after Brave, SearXNG and DuckDuckGo, so a free account's credits only go on queries the others missed. A refusal or a used up balance switches it off for the run. Exa drops a `site:` restriction when nothing matches, so that answer counts as empty. Run live once on 2026-10-22: see the entry below
- [x] Custom search queries (2026-10-21): `exposure_search` plugin plus a seven-query importable pack in `source_packs/`. Hit rate on a real domain not measured yet
- [x] Larger public domain check (2026-10-22, toysrus.com, search tier only): 36 searches through Brave in 70 seconds, no throttling. Found that 8 of 10 emails were example addresses from email-format sites and one cloud storage hit was a textbook page, both now filtered. Wayback fix: patient retries, and the interesting-URL filter no longer matches host names
