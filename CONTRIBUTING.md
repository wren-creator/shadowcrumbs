# Contributing to Shadowcrumbs

Glad you're here. This is a small tool built by one person who got tired of tab juggling, so there is no committee and no process to wade through. Open an issue or a pull request and I'll look at it.

## The ground rules

These are the few things I won't bend on, mostly because this tool handles client data.

1. **Authorized use only.** Shadowcrumbs is for engagements you have written permission to test, and your own systems. Don't contribute anything aimed at getting around the authorization gate or hiding what the tool does.
2. **Never store a password.** Not plaintext, not a prefix, not a masked hint with real characters in it. Credential sources record the address, where it was exposed, and what kind of secret leaked (plaintext and its length, or what sort of hash). `shadowcrumbs/plugins/credential_plugins.py` shows how, and `tests/test_credentials.py` has the test that plants a password and checks it never shows up anywhere. Keep that test passing.
3. **No real client data, ever.** Tests, fixtures, screenshots and issues use the fictional Acme Demo Corp on a `.test` domain. Don't paste real findings into an issue, even redacted.
4. **The dashboard renders text, never HTML.** Everything scraped from the web goes through `textContent`. No `innerHTML`, and only `http` and `https` links. A hostile web page is a normal input for this tool, so keep that wall up if you touch `static/app.js`. `tests/test_dashboard_safety.py` checks it, in a real browser if you have Chromium (`playwright install chromium`).
5. **Be polite to the sites we search.** DuckDuckGo blocks fast and for a long time. Don't lower the default search pace (8 seconds, 5 to 10 is the safe range) and don't add retries that hammer a blocked engine. Tests never touch the live internet.

## Getting set up

```bash
git clone https://github.com/wren-creator/shadowcrumbs.git
cd shadowcrumbs
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt -r requirements-dev.txt
.venv/bin/python -m pytest
./start.sh --demo     # fictional data, no network, open http://127.0.0.1:8470
```

All the tests should pass before you start (the browser test skips itself if there is no Chromium), and again before you open a pull request.

## Adding a data source

This is the contribution I'd love most, and it needs no changes to the core. A source is one Python class:

```python
from shadowcrumbs.plugin import Finding, Plugin, register

@register
class MySource(Plugin):
    name = "my_source"
    tier = "search"            # "search" never touches the client, "deep" does or uses an API
    description = "What it does, one line."
    needs_any = ("domain",)    # runs if any of these target fields is set
    order = 50                 # lower runs first

    def run(self, ctx):
        yield Finding("tech", "Something", url="https://...", confidence=60, notes="why you think so")
```

- `plugins_user/wayback_urls.py` is a small working example. The README has the full contract.
- Categories are `employees`, `emails`, `documents`, `tech`, `subdomains`, `infrastructure`.
- **Search tier** sources go through `ctx.search`, which caches every query and paces them. **Deep tier** sources go through `ctx.http`. Anything that sends traffic to the client sets `touches_target = True` so the dashboard shows the ACTIVE badge.
- If your source needs an API key or a file, override `unavailable()` to return a short reason like `"needs MY_API_KEY"`. The run is then recorded as skipped with that reason, not as a failure.
- Write a test with a fake `http` or `search` object. `tests/test_deep.py` and `tests/test_credentials.py` show the pattern. If a source sends data to a third party, say so in its description and in the README.

## Other things that would help

The [ROADMAP](ROADMAP.md) is the honest list. Right now I'd especially like:

- More search providers, so DuckDuckGo throttling stops being the weak spot.
- Live verification of the HIBP and DeHashed plugins. They were built from the vendors' docs and tested against fake responses, so someone with keys will probably find a field name that needs fixing.
- Better tech signatures in `shadowcrumbs/signatures.py`. A row per product is all it takes.
- Anything that breaks. An issue with the steps to reproduce is a real contribution.

## Pull requests

- **One logical change per pull request.** Don't bundle unrelated fixes.
- **Say why before what.** The description should open with the problem you hit, then what you changed.
- **Commit messages** start with `feat:`, `fix:`, `docs:` or `refactor:`.
- **Keep the docs honest.** If you change behavior, update the README or ROADMAP in the same pull request. If something is untested against the live service, say so in the README, the way the credential sources do.
- Match the style of the code around yours. Plain names, short comments that explain why.

## Reporting a security problem

If you find a way to make Shadowcrumbs leak client data, run something it shouldn't, or be driven from a web page, please **don't open a public issue**. Email britleyhoff@britleyhoffconsulting.com with the details and I'll fix it quickly.

## Licence

Shadowcrumbs is GPL-3.0. By contributing you agree your work is released under the same licence.

## Say hello

The community lives at britleydev.slack.com. Come ask questions, share a data source you built, or tell me what broke.
