# Shadowcrumbs

The crumbs a company leaves behind, collected in one place before you ever touch the target.

Give it a company name, a domain, or an IP range. It pulls what search engines already know: subdomains, exposed documents, email addresses and their format, employee names and titles, and the tech stack people brag about in job posts and LinkedIn blurbs. Every client gets its own tab and its own database. Export the lot as Markdown, PDF, or JSON when it's time to write it up.

## Run it

```bash
./start.sh              # background, then open http://127.0.0.1:8470
./start.sh --demo       # fixture data, no network (see below)
./start.sh --status     # is it up?
./stop.sh               # stop it
```

Switches for `start.sh`: `--demo`, `--port N`, `--delay SECS` (pause between live search queries), `--foreground` (stay in the terminal, Ctrl-C to stop), `--status`, `--help`. It builds `.venv` on first run if one isn't there. Logs go to `shadowcrumbs.log`.

Prefer to do it by hand?

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python run.py
```

Open http://127.0.0.1:8470. It binds to localhost on purpose. This holds client data, so keep it there.

Want to see it work with no network? `./start.sh --demo` runs on the bundled demo data, a fictional company on a reserved `.test` domain.

Make an engagement for `Acme Demo Corp` / `acme-demo.test` and hit Run.

Just want to show it off? Open `docs/mockup.html` in any browser. It is the real dashboard with a captured demo run baked in, no server needed, read-only, safe to screen share. Rebuild it with `python docs/build_mockup.py DATA_DIR` after capturing the API output from a `--demo` run.

## How a recon goes

1. **New engagement.** Name, plus any of company, domain, IP or CIDR. That's the tab.
2. **Search tier.** Runs on search engine results only. Nothing touches the client. Every query is cached per engagement, so re-runs are free and quiet.
3. **Deep dive.** Direct lookups and live requests: DNS, RDAP, certificate transparency, subdomain resolution with dangling CNAME checks, an HTTP probe, and metadata from the documents you found. Flip the toggle when search has given you what it can.
4. **Triage.** Mark findings verified, drop the junk, filter the list.
5. **Export.** Markdown, PDF, or JSON, with scope and run history baked in.

## The scope gate

Deep dive is locked until the engagement has an authorization reference (SOW number, ROE date, ticket, whatever you can point to later). Search tier works without one because it only reads public listings. The reference prints on every export. It's a speed bump, not a lecture: it forces the paperwork question before packets go out.

Sources marked **ACTIVE** in the dashboard send traffic to the client's own systems.

## Adding a data source

Drop a `.py` file in `plugins_user/`. It loads on the next start, no core changes. See `plugins_user/wayback_urls.py` for a working one. The whole contract:

```python
from shadowcrumbs.plugin import Finding, Plugin, register

@register
class MySource(Plugin):
    name = "my_source"
    tier = "search"            # or "deep"
    description = "What it does, one line."
    needs_any = ("domain",)    # runs if any of these target fields is set
    order = 50                 # lower runs first

    def run(self, ctx):
        # ctx.target: company, domain, ip
        # ctx.search.search(query): cached search results
        # ctx.http: get_json, download, probe (deep tier)
        # ctx.store.findings("subdomains"): what earlier plugins found
        yield Finding("tech", "Something", url="https://...", confidence=60, notes="why you think so")
```

Categories are `employees`, `emails`, `documents`, `tech`, `subdomains`, `infrastructure`. A plugin that crashes gets logged in run history and the rest carry on. A plugin file that fails to load shows up in the dashboard instead of taking the app down.

Tech signatures live in `shadowcrumbs/signatures.py`. Add a row for any product you want flagged. The list already leans toward IBM i, z/OS, z/TPF, RACF, and the common PLC and SCADA vendors.

## Search providers

| Provider | When | Needs |
|---|---|---|
| `ddg` | Search tier default | Nothing |
| `brave` | Deep dive, automatically, when the key exists | `BRAVE_API_KEY` |
| `fixture` | Demos and tests | `SHADOWCRUMBS_FIXTURE` |

Other settings: `SHADOWCRUMBS_SEARCH_DELAY` (seconds between live queries, default 2.5), `SHADOWCRUMBS_DATA` (where engagements live), `SHADOWCRUMBS_UA` (user agent).

## Straight talk on limits

- **DuckDuckGo throttles.** Scraping its HTML endpoint works until it doesn't. When it blocks you, the run records the error and says so. Wait, raise the delay, or set a Brave key and run a deep dive. I could not reach DuckDuckGo from the build environment, so the parser is tested against a sample page, not the live site. If your first live run comes back empty, that's the first place to look.
- **LinkedIn is read through search snippets only.** Shadowcrumbs never scrapes LinkedIn itself. You get names and titles from the result listings, which is also the quieter way to do it.
- **No breach or credential lookups yet.** Passwords and leaked accounts need a source with a key (HaveIBeenPwned, DeHashed, an internal feed). That's the first plugin worth writing, and the plugin contract above is all it takes.
- **Confidence scores are rough.** They say how direct the evidence is, nothing more. Verify before you rely on a finding.
- **Document metadata is the juiciest and the loudest.** It downloads files from the client's own site. That's why it's deep tier.
- **Not multi-user.** One operator, one machine, no login. Don't put it on a network.

## Layout

```
start.sh / stop.sh           background start and stop
run.py                       the server itself
shadowcrumbs/
  app.py                     API and dashboard host
  engine.py                  runs plugins, tracks progress, enforces the gate
  store.py                   one SQLite file per engagement
  search.py                  search providers, per-engagement query cache
  netclient.py               HTTP for deep dive plugins
  exporters.py               markdown, JSON, PDF
  signatures.py              tech fingerprints
  plugins/search_plugins.py  search tier sources
  plugins/deep_plugins.py    deep dive sources
plugins_user/                your own sources
static/                      the dashboard
fixtures/demo.json           offline demo data
tests/                       pytest suite
```

## Tests

```bash
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest
```

Planned work lives in [ROADMAP.md](ROADMAP.md).

Covers the store, every plugin, the scope gate, failure handling, all three exports, and the API. Hostile input is in there too: booby-trapped Office files and throttled search.

The dashboard renders everything it scrapes as plain text, never HTML, and only turns http and https URLs into links. That part is not in the pytest suite. I checked it by planting script tags and `javascript:` URLs in findings and loading the page in a headless DOM. Keep it that way if you edit `static/app.js`.
