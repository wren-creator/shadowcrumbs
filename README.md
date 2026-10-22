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

**Who recorded it, and when.** Every change to the authorization (granted, updated, revoked) adds a row to that engagement's ROE history: the reference, the name of the person who recorded it, and the date and time in UTC. The dashboard asks for your name whenever you change the authorization, and remembers it in your browser. The API refuses a change without one (`authorized_by`). Rows are append only: nothing in the app edits or deletes one. Be straight about what that is worth: it is a log kept in a SQLite file on your machine, so anyone who can write to the file can change it, and it goes away with the engagement. So every change is also written to the app log, and deleting an engagement writes its whole ROE history there first. Databases made before this existed get one row marked "unknown (recorded before the audit trail)" with no time, because nobody recorded one.

## The admin panel

**ADMIN** in the dashboard header (or `http://127.0.0.1:8470/admin.html`) opens a page with three sections.

- **ROE register.** Every engagement with its full authorization history: the action, the reference, who recorded it, the date and time in UTC, and the same moment on your local clock. Read only. The dashboard also shows the latest line under Scope, so you can see at a glance who unlocked deep dive and when.
- **Run events.** The troubleshooting trail for one engagement, filterable by run and by level, with optional auto refresh while a scan is going. This is where to look first when a source comes back empty.
- **App log.** The tail of `data/logs/shadowcrumbs.log`, filterable by level.

There is no login, same as the rest of the tool: it is one operator on one machine and it only answers on localhost. The admin page shows the same client confidential data as the dashboard, so the same rule applies. Do not expose it. Like the dashboard, it only ever renders text, and `tests/test_dashboard_safety.py` loads it in a real browser with hostile names and log lines to check that.

Sources marked **ACTIVE** in the dashboard send traffic to the client's own systems.

## Adding a data point from the dashboard (no code)

Click **SOURCES** in the header (or open `/sources.html`). This is the page for the whole team: nobody has to write Python to add a search.

A source is a few searches plus a rule for what to keep:

1. **Name** it and say what it finds.
2. Pick the **tab** the findings land in (Tech Stack, Subdomains, and so on).
3. Say what it **needs** from the target: the domain, the company name, or both. A target without them is skipped, with the reason in the run history.
4. Type the **searches**, one per line. Click `{domain}` or `{company}` to drop in the target's values. Search operators work: `site:`, `filetype:`, `"exact phrase"`, `OR`. The page tells you how many searches that is and how long a run takes at the current pace.
5. Optionally **keep only** results that mention certain words, or that sit on the target's own domain.
6. Choose how each result is **recorded**: its page title, its hostname, the email addresses in it, or a document link (PDF, Office files).
7. Put in your **name**. It is saved with the source and shown to the team.

**Show the searches** previews the exact queries for one of your engagements, with no network and nothing saved, before you commit. **Save** and the source is live straight away: it shows up in the dashboard's search sources with a CUSTOM badge, ready to run. Edit and Delete are on the same page.

What it will not do, on purpose. A source made here is data, never code. It cannot run anything, fetch a URL, call an API or touch the client, and there is no regular expression box. That is what makes it safe to hand to a whole team. Searches go to your search engine, so keep client secrets and internal code names out of them. If you need a source that calls an API or the client's own site, that is a plugin file (next section). Limits: 10 searches per source, 100 sources.

**Sharing with the team.** The list is one JSON file, `data/custom_sources.json`. Two ways to share:

- **Export all / Import** on the page. A teammate exports, you import. If a name already exists you choose to skip it, overwrite it, or keep both.
- **One shared file.** Set `SHADOWCRUMBS_SOURCES_FILE` to a file in a shared folder or a git checkout and everyone uses the same list. Each save bumps a revision number. If two people save at once the second gets "Someone else changed the sources, reload" instead of silently wiping the first. Last write does not win quietly.

A damaged shared file never takes the app down and is never overwritten: the page shows what it could not read, and a single bad entry is skipped and kept while the rest load. Every create, edit, delete and import is written to the app log with the person's name.

## Adding a data source in code

**Start from the template.** One command makes a working file with your name, category and queries filled in:

```bash
python tools/new_plugin.py careers_tech --tier search --category tech \
    --query 'site:{d} careers' --query '"{company}" "experience with"'

python tools/new_plugin.py vendor_api --tier deep --category infrastructure --key-env VENDOR_API_KEY
```

`{d}` is the target domain and `{company}` the company name. A query that needs a field the target does not have is dropped, not searched as the word "None". The search file works as soon as you restart: its three numbered comments mark the only spots you edit (the queries, what counts as theirs, what gets recorded). The deep file shows as skipped until you fill in the endpoint, and it keeps the key in a header and out of the URL. The command refuses to overwrite a file, refuses a name that is taken, and writes a name only if it is plain `snake_case`, so it cannot be steered outside the folder. `--dir` writes somewhere else, for example one of your `SHADOWCRUMBS_PERSONAL_PLUGINS` folders. The two templates themselves are `plugins_user/_template_search.py` and `plugins_user/_template_deep.py`, real Python you can read and copy by hand. Files starting with `_` are never loaded.

Or by hand: drop a `.py` file in `plugins_user/`. It loads on the next start, no core changes. For tools you do not want in a public repo, keep them in a folder of your own and set `SHADOWCRUMBS_PERSONAL_PLUGINS` to it (several folders separated by `:`). Those load too, and never touch this repo. See `plugins_user/wayback_urls.py` for a working one. The whole contract:

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

## Troubleshooting a scan

When a source comes back empty or red, the answer is usually in the logs. There are two, and they say the same things in the same words.

- **Run events**, per engagement and per run. They live in that engagement's database. Every source logs when it starts and finishes (status, new findings, seconds), every live search (provider, result count, time, the query), every cache hit, every search block, every HTTP call (method, URL, status, time), and the full traceback when a source fails. `GET /api/engagements/{slug}/events?level=warning&run_id=12` returns them. The last 5000 are kept.
- **The app log**, `data/logs/shadowcrumbs.log`, rotated at 2 MB with 5 old files kept. It also has startup, ROE changes and crashes outside a run. Times are UTC, same as the databases.

`SHADOWCRUMBS_LOG_LEVEL` sets how much the app log file keeps: `INFO` (default) is lifecycle, searches and failures, `DEBUG` adds every HTTP request and cache hit. Run events always keep everything, and you filter them when you read them (`?level=warning` and up). A 4xx or 5xx response always shows as a warning.

**Keys never get logged.** One function (`shadowcrumbs/log.py`, `redact()`) scrubs both logs and the run history: secret-looking query parameters, `Authorization`, cookie and `X-...-Key` values, `Bearer` and `Basic` tokens, passwords inside URLs, and the literal value of any environment variable whose name contains KEY, TOKEN, SECRET, PASS, AUTH or CRED. Request headers and bodies are never logged at all, only the URL, status and timing. The tests plant a key in an error message and check it is nowhere in either log or the API.

What the logs do contain is your targets and your search queries. That makes them as client confidential as the databases. They sit under `data/`, which is gitignored. Do not paste them into a public issue without reading them first.

## Verifying sources: endpoints and keys

Before you trust a scan to a source, check that it can actually work. **Verify keys and endpoints** on the admin page makes one cheap request per source and says what it found. From a terminal:

```bash
python tools/verify_sources.py                  # everything
python tools/verify_sources.py github_code_search hibp_breaches
python tools/verify_sources.py --strict         # a missing key or a warning also counts as a failure
```

It exits 1 when a check fails, so it also works as a preflight before an engagement. Each result is one of:

| Status | Meaning |
|---|---|
| **OK** | The address answered, and the key (if there is one) was accepted |
| **FAILED** | Unreachable, or the key was rejected. The detail says which |
| **WARNING** | It works, but look: crt.sh is overloaded, a SearXNG engine is down, or your GitHub token can see private repos |
| **NOT SET UP** | A key or file the source needs is not configured, with the variable to set. Not a failure |
| **NOT CHECKED** | There is no safe check. DeHashed (the only test of a key is a billable search) and the sources that only talk to the client's own systems |

What it sends, so there are no surprises. Every request asks a service about `example.com`, never your client, and keys travel in request headers only, as in a real run. The search engine for each tier is checked too. DuckDuckGo is **never** queried live, because a test query is exactly what trips its throttle: you get the recorded block state instead. A Brave check uses one search from your quota, and the page says so. SearXNG gets one query through your own instance and reports any upstream engines that are not answering. The GitHub check uses the free rate limit call, so it costs nothing, and it warns if the token has the `repo` scope.

Results are remembered in `data/verify.json` and shown as a **Check:** line on each source in the dashboard, so a teammate sees a rejected key before they press Run. A run happens in the background and the table fills in as each check finishes. Keys are scrubbed from every result, the file and the log, and the tests plant one to prove it.

Honest limits. The HIBP check was written from the vendor's docs and tested against a fake response, like the rest of that plugin, because there was no key to try it live. The public services (RDAP, crt.sh, urlscan.io, the Internet Archive, DNS) were checked live on 2026-10-21.

**Your own plugins** can take part by adding a `verify(self, http)` method that makes one request and returns `("ok" | "warn" | "fail", "what happened")`. The deep template (`plugins_user/_template_deep.py`) has a working one. Sources without it show as not checked.

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

**Running your own SearXNG.** `./tools/searxng.sh up` starts one in Docker, bound to 127.0.0.1:8888 with JSON output on and a random secret generated on your machine (`tools/searxng/.secret`, gitignored). Then `export SHADOWCRUMBS_SEARXNG_URL=http://127.0.0.1:8888` before `./start.sh`. `./tools/searxng.sh down` stops it. Checked live on 2026-10-09: it returned 10 results per query for `site:`, `filetype:` and `OR` searches. Honest caveat: SearXNG relays to other engines, and from my network DuckDuckGo and Startpage showed it CAPTCHAs and Brave suspended it for too many requests, so one engine did all the answering. Check `unresponsive_engines` in its JSON output if results look thin.

Other settings: `SHADOWCRUMBS_SEARCH_DELAY` (seconds between live queries, default 8), `SHADOWCRUMBS_BLOCK_MINUTES` (how long to stay quiet after DuckDuckGo blocks you, default 60), `SHADOWCRUMBS_IGNORE_BLOCK=1` (try anyway), `SHADOWCRUMBS_LOG_LEVEL` (INFO or DEBUG, see Troubleshooting a scan), `SHADOWCRUMBS_DATA` (where engagements live and logs go), `SHADOWCRUMBS_UA` (user agent, see the limits below), `SHADOWCRUMBS_ALLOWED_HOSTS` (extra Host names the server will answer to, for a reverse proxy).

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
  log.py                     app log, and the one place secrets are scrubbed from logs
  custom_sources.py          sources added from the dashboard (data, never code)
  verify.py                  checks each source's endpoint and key, and the search engines
  store.py                   one SQLite file per engagement
  search.py                  search providers, per-engagement query cache
  netclient.py               HTTP for deep dive plugins
  exporters.py               markdown, JSON, PDF
  signatures.py              tech fingerprints
  plugins/search_plugins.py  search tier sources
  plugins/deep_plugins.py    deep dive sources
plugins_user/                your own sources, plus the two templates (files starting with _ are never loaded)
tools/new_plugin.py          makes a new source from the template
tools/verify_sources.py      checks every source's endpoint and key from the terminal
static/                      the dashboard (index.html), the sources page (sources.html), the admin page (admin.html)
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
