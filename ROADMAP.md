# Roadmap

- [x] Verify the DuckDuckGo parser against the live site (2026-10-07: layout confirmed, sponsored results now filtered)
- [x] Survive DDG throttling: slower default pace, cool-off and retry, stop after giving up (2026-10-07)
- [ ] Measure DDG's real limit over a long live run and tune the default delay and backoff from data instead of guesses
- [x] Credentials/breach sources: HIBP, DeHashed, local feed import (2026-10-07), never stores passwords
- [ ] Verify the HIBP and DeHashed plugins against the live services once there are keys (built against docs and fake responses)
- [ ] Optional opt-in to keep plaintext secrets, with masked exports, if a real engagement needs it
- [ ] More search providers (Bing, SearXNG) as a fallback for DDG throttling
- [ ] Optional config flag to relax the authorization gate
- [ ] Add the dashboard sanitization check (script tags, javascript: URLs) to pytest, currently manual
