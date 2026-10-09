# Shadowcrumbs

The crumbs a company leaves behind, collected in one place before you ever touch the target.

Give it a company name, a domain, or an IP range. It pulls what search engines already know: subdomains, exposed documents, email addresses and their format, employee names and titles, and the tech stack people brag about in job posts and LinkedIn blurbs. Every client gets its own tab and its own database. Export the lot as Markdown, PDF, or JSON when it's time to write it up.

## Use it on engagements you are authorized for

This is a recon tool. Point it only at companies and domains you have written permission to test, or your own. Two parts of it deserve a straight word:

- **It collects personal information.** The search tier pulls employee names and job titles out of public search listings, and the email sources collect staff addresses. That is normal pen test recon, and it is still personal data. Keep it inside the engagement, protect the exports, and delete it when the engagement closes. If GDPR or similar rules apply to you, they apply to this.
- **The credential sources send data to third parties.** `hibp_breaches` and `dehashed_domain` ship the addresses you found to Have I Been Pwned and DeHashed. They stay off until you set a key, and no password is ever stored.

The deep dive tier, the part that sends traffic to the target, stays locked until you record an authorization reference (SOW, ROE, ticket). It will not stop anyone determined to misuse it, and it is not meant to. It is there to make you answer the paperwork question first. How you use the tool is on you.

Licensed GPL-3.0, see [LICENSE](LICENSE). No warranty, as the licence says.

## Run it

```bash
./start.sh              # background, then open http://127.0.0.1:8470
./start.sh --demo       # fixture data, no network (see below)
./start.sh --status     # is it up?
./stop.sh               # stop it
```

Switches for `start.sh`: `--demo`, `--port N`, `--delay SECS` (pause between live search queries), `--foreground` (stay in the terminal, Ctrl-C to stop), `--status`, `--help`. It builds `.venv` on first run if one isn't there. Logs go to `shadowcrumbs.log`.

Click the **SHADOWCRUMBS** logo in the header to flip between the green screen and a rose theme. It remembers your pick.

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
3. **Deep dive.** Direct lookups and live requests: DNS, RDAP, certificate transparency, public urlscan.io scans, GitHub code search, subdomain resolution with dangling CNAME checks, an HTTP probe, and metadata from the documents you found. Flip the toggle when search has given you what it can.
4. **Triage.** Mark findings verified, drop the junk, filter the list.
5. **Export.** Markdown, PDF, or JSON, with scope and run history baked in.

## The scope gate

Deep dive is locked until the engagement has an authorization reference (SOW number, ROE date, ticket, whatever you can point to later). Search tier works without one because it only reads public listings. The reference prints on every export. It's a speed bump, not a lecture: it forces the paperwork question before packets go out.

Sources marked **ACTIVE** in the dashboard send traffic to the client's own systems.

## Adding a data source

Drop a `.py` file in `plugins_user/`. It loads on the next start, no core changes. For tools you do not want in a public repo, keep them in a folder of your own and set `SHADOWCRUMBS_PERSONAL_PLUGINS` to it (several folders separated by `:`). Those load too, and never touch this repo. See `plugins_user/wayback_urls.py` for a working one. The whole contract:

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

There is a reference list of other services worth wiring in, with where each one fits, in [docs/DATA-SOURCES.md](docs/DATA-SOURCES.md).

Categories are `employees`, `emails`, `documents`, `tech`, `subdomains`, `infrastructure`. A plugin that crashes gets logged in run history and the rest carry on. A plugin file that fails to load shows up in the dashboard instead of taking the app down.

Tech signatures live in `shadowcrumbs/signatures.py`. Add a row for any product you want flagged. The list already leans toward IBM i, z/OS, z/TPF, RACF, and the common PLC and SCADA vendors.

## API keys and tokens

Keys live in environment variables, never in a file inside this repo: `BRAVE_API_KEY`, `HIBP_API_KEY`, `DEHASHED_API_KEY`, `URLSCAN_API_KEY` (optional), `GITHUB_TOKEN`. `.env` files are gitignored as a backstop, and GitHub secret scanning is on for the repo. Shadowcrumbs only ever puts a key in the request header that needs it. It never writes one to a finding, a log, the query cache, or an error message, and the tests check that.

For `github_code_search`, make a **fine-grained token with read access to public repositories only**, no private repo access. A broader token such as the one from `gh auth token` can make GitHub's search return hits from your own private repos. The plugin drops anything that is not public, but a token that cannot see private code in the first place is the better guard. The plugin keeps only the repo, file path, hostnames and addresses from a hit, never the code itself, because public repos leak secrets and none of that belongs in an engagement database. Code search allows about 10 requests a minute, so a run reads two pages at most.

## Credential exposure

Three deep dive sources, all off until you give them something. Without a key or file they show as **skipped** with the reason, not as errors.

| Source | What it does | Needs |
|---|---|---|
| `hibp_breaches` | Looks up each address already found in the Emails tab (up to 100) in Have I Been Pwned | `HIBP_API_KEY` |
| `dehashed_domain` | One DeHashed search for the whole domain, up to 3 pages | `DEHASHED_API_KEY` |
| `breach_file_import` | Reads your own feed: `.csv` (columns email, password or hash, source), `.jsonl`, or `email:secret` lines in any other file | `SHADOWCRUMBS_BREACH_FILE` |

**No password is ever stored.** A finding records the address, which breach or file it came from, and the kind of secret that leaked: plaintext and how many characters, or what sort of hash it looks like. That is enough to write the report and plan a spray, and nothing you would mind losing from a laptop. If you need the actual secrets, they are in your source feed or the vendor's console, which is where they belong.

Heads up: HIBP and DeHashed are third parties. Running them sends the addresses you found to them. Lookups are cached for a week per address, so re-runs do not burn credits. HIBP is paced at one call every 6.5 seconds to stay inside the entry-level key limit.

## Search providers

| Provider | When | Needs |
|---|---|---|
| `searxng` | Both tiers, first choice whenever the URL is set | `SHADOWCRUMBS_SEARXNG_URL`, your own [SearXNG](https://docs.searxng.org/) instance with `json` under `search.formats` |
| `ddg` | Search tier default | Nothing |
| `brave` | Deep dive, automatically, when the key exists | `BRAVE_API_KEY` |
| `fixture` | Demos and tests | `SHADOWCRUMBS_FIXTURE` |

Other settings: `SHADOWCRUMBS_SEARCH_DELAY` (seconds between live queries, default 8), `SHADOWCRUMBS_BLOCK_MINUTES` (how long to stay quiet after DuckDuckGo blocks you, default 60), `SHADOWCRUMBS_IGNORE_BLOCK=1` (try anyway), `SHADOWCRUMBS_DATA` (where engagements live), `SHADOWCRUMBS_UA` (user agent, see the limits below), `SHADOWCRUMBS_ALLOWED_HOSTS` (extra Host names the server will answer to, for a reverse proxy).

## Straight talk on limits

- **DuckDuckGo throttles, hard.** The parser reads the real page correctly and drops the sponsored results DDG mixes in. The throttle is the problem. In live testing (2026-10-07) two queries less than a second apart tripped it, and the block then lasted over 50 minutes, which is as long as I watched. Published guidance agrees: a reset can take an hour or more, and the safe pace is one query every 5 to 10 seconds. The default is 8 seconds with jitter, so a full run of about 28 queries takes around 4 minutes. Do not lower it. If DDG does block you, the run stops sending queries right away, because retrying cannot help and may extend the block. The block is remembered, and the next run stays quiet for an hour (`SHADOWCRUMBS_BLOCK_MINUTES`) instead of poking it. Cached queries cost nothing on a re-run. A browser on the same network gets DDG results fine (checked 2026-10-09), so it is the script being flagged, not the address. The fix I trust is a SearXNG instance you run yourself, which Shadowcrumbs uses automatically once `SHADOWCRUMBS_SEARXNG_URL` is set. For anything beyond light use, set a Brave key and run a deep dive. `tools/measure_ddg.py` repeats the measurement from your own network, and it will get your IP blocked on purpose.
- **LinkedIn is read through search snippets only.** Shadowcrumbs never scrapes LinkedIn itself. You get names and titles from the result listings, which is also the quieter way to do it.
- **Credential lookups need a key or your own feed.** The three sources below are tested against fake API responses and a fake feed, not the live HIBP or DeHashed services (no keys on hand when I built them). Expect to fix a field name or two on your first real call, and tell me what you see.
- **Confidence scores are rough.** They say how direct the evidence is, nothing more. Verify before you rely on a finding.
- **Document metadata is the juiciest and the loudest.** It downloads files from the client's own site. That's why it's deep tier.
- **Not multi-user.** One operator, one machine, no login. Don't put it on a network. It also refuses any request that arrives under a Host name other than localhost, or from another site's page, so a web page you happen to browse cannot drive it through DNS rebinding. That is protection for a localhost tool, not a reason to expose it.
- **The default user agent looks like Firefox.** That is what makes the DuckDuckGo HTML endpoint answer at all, and scraping it is a gray area under their terms. If that bothers you, set `SHADOWCRUMBS_UA` to something honest and expect to be blocked sooner, or use a Brave key and skip the scraping.

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

Planned work lives in [ROADMAP.md](ROADMAP.md). Want to add a data source or fix something? Start with [CONTRIBUTING.md](CONTRIBUTING.md).

Covers the store, every plugin, the scope gate, failure handling, all three exports, and the API. Hostile input is in there too: booby-trapped Office files and throttled search.

The dashboard renders everything it scrapes as plain text, never HTML, and only turns http and https URLs into links. `tests/test_dashboard_safety.py` holds that line two ways. A source check bans every way of turning a string into markup or code (`innerHTML`, `insertAdjacentHTML`, `eval` and friends), and a real browser test starts the app, loads it with findings full of script tags, `javascript:` and `data:` URLs and attribute breakouts, then checks that nothing ran, nothing became an element, and every link is http or https. I broke the dashboard on purpose in two ways to prove the tests catch it. The browser test needs Chromium and skips with a message if it cannot find one: run `playwright install chromium`, or point `SHADOWCRUMBS_TEST_BROWSER` at a chrome binary. Keep that rule intact if you edit `static/app.js`.
