# Roadmap

- [x] Verify the DuckDuckGo parser against the live site (2026-10-07: layout confirmed, sponsored results now filtered)
- [ ] Make live search survive DDG throttling: it blocked this IP after about 3 queries in a minute at the old pace. Try a longer default delay, jitter, and automatic backoff, or lean on a keyed provider
- [ ] Credentials/breach plugin (HIBP, DeHashed, or internal feed), first plugin to write
- [ ] More search providers (Bing, SearXNG) as a fallback for DDG throttling
- [ ] Optional config flag to relax the authorization gate
- [ ] Add the dashboard sanitization check (script tags, javascript: URLs) to pytest, currently manual
