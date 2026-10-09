# Roadmap

- [x] Verify the DuckDuckGo parser against the live site (2026-10-07: layout confirmed, sponsored results now filtered)
- [x] Handle DDG throttling: stop on the first block and stay quiet for an hour (blocks measured at 50+ minutes, retrying cannot help)
- [ ] Re-run `tools/measure_ddg.py` once the IP is clear, with sparse probes, to learn the true cooldown and whether polling extends it
- [x] Credentials/breach sources: HIBP, DeHashed, local feed import (2026-10-07), never stores passwords
- [ ] Verify the HIBP and DeHashed plugins against the live services once there are keys (built against docs and fake responses)
- [ ] Optional opt-in to keep plaintext secrets, with masked exports, if a real engagement needs it
- [ ] More search providers (Bing, SearXNG) as a fallback for DDG throttling
- [ ] Optional config flag to relax the authorization gate
- [ ] Add the dashboard sanitization check (script tags, javascript: URLs) to pytest, currently manual
