# Getting your keys

Shadowcrumbs runs with no keys at all, but the search half will not be reliable. DuckDuckGo throttles scripts after a query or two, and a blocked scan finds nothing. A search API key fixes that. The other keys add sources.

This page is the shortlist: what each key does, where to get it, and how to check it worked.

## What you need for a successful scan

| You want | You need |
|---|---|
| A scan that finishes (documents, emails, employees, tech clues) | **Brave**. This is the one that matters. |
| Subdomains, hosting, mail and registration | Nothing. Certificate logs, DNS, RDAP and urlscan need no key. |
| Public repos that mention the client | **GitHub token** (free) |
| Faster, bigger urlscan searches | urlscan key (optional, the free anonymous tier works) |
| Breached accounts for the client's domain | HIBP key and/or DeHashed key (both paid, deep dive only) |

Minimum for a reliable first scan: Brave plus the GitHub token.

## The keys

### Brave Search API (`BRAVE_API_KEY`)
Why: a real search API. No CAPTCHAs, no throttling by IP. When it is set, Brave leads the search chain on both tiers, at about a query a second.
Get it: https://brave.com/search/api/ (sign up, pick a plan, create a key in the dashboard).
Cost: it is a paid service, and plans change, so read the plan page before you enter a card. As of 2026-10-22 one plan listed $5 per 1,000 requests (half a cent a query), $5 of free credit every month, and 50 requests per second. A full scan is roughly 36 to 40 queries, so about 20 cents, and results are cached per engagement for a week, so a re-run costs nothing. The verify check prints requests left per second and per month, and a monthly 0 there means the plan has no monthly cap, not that you are out.
Pace: Brave queries go out about a second apart by default, which is safe on slower plans. On a 50 per second plan you can speed a scan up with `SHADOWCRUMBS_SEARCH_DELAY=0.2` in `.env`. Too fast on a slow plan gets a 429, and the scan moves on to the next search engine.

### Exa (`EXA_API_KEY`)
Why: a backup for when everything ahead of it in the search chain is throttled. It is an API, so no CAPTCHAs and no IP throttling.
Get it: https://dashboard.exa.ai/api-keys (a free account works).
Cost: the free account has a credit limit, which is why Exa sits at the very end of the chain and is only asked after Brave, SearXNG and DuckDuckGo have all failed. Check the pricing page for the current free credit. If the credits run out (402) or the key is refused, Exa is switched off for the rest of that run and the scan carries on without it.
Caveat: Exa is a neural search engine, not a keyword one. It reads `site:` and quoted phrases, but it treats them loosely and can answer a dork with pages that only look related. If nothing matches a `site:` restriction, Exa quietly drops it and answers anyway, so Shadowcrumbs treats that case as no results instead of keeping the unrelated pages. Expect thinner and fuzzier dork results than from Brave.
Pace: about two queries a second unless you set `SHADOWCRUMBS_SEARCH_DELAY`. Exa's default limit is ten a second.

### GitHub token (`GITHUB_TOKEN`)
Why: GitHub code search finds public repos, hostnames and addresses that mention the domain. It only returns metadata, no code is kept, and private repos are dropped.
Get it: https://github.com/settings/personal-access-tokens/new (a fine-grained token).
Settings: repository access **Public repositories (read-only)**, no extra permissions, a short expiry such as 90 days. Code search only needs you to be signed in.
Cost: free.

### urlscan.io (`URLSCAN_API_KEY`)
Why: hosts, IPs and server software from public scans. It works without a key, and a key raises your limits.
Get it: sign in at https://urlscan.io/, then open your profile and create an API key (https://urlscan.io/user/profile/). Their API docs: https://docs.urlscan.io/
Cost: free accounts exist. Plans and quotas: https://urlscan.io/pricing/

### Have I Been Pwned (`HIBP_API_KEY`)
Why: which accounts at the client's domain appear in known breaches. It records the breach names, never passwords.
Get it: https://haveibeenpwned.com/API/Key (sign in, subscribe, copy the key).
Cost: paid subscription. Deep dive only.

### DeHashed (`DEHASHED_API_KEY`)
Why: a second breach source for the client's domain. It never stores passwords.
Get it: sign in at https://app.dehashed.com/ and look for the API key in your account settings. DeHashed blocks scripted checks, so I could not confirm the exact page. If it moved, their site search will find "API".
Cost: paid, and each search uses a credit. You need **two** things: a search subscription (the gate) and search credits. Credits alone get a 401 with "You need a search subscription and API credits". The Verify step calls the free account info endpoint, so it reports a bad key, a missing subscription or an empty balance without spending a credit.

## Putting them in

Keys go in a file called `.env`, never in your shell history, a script, a ticket or a chat.

```bash
cp env.example .env
chmod 600 .env          # required, a file other users can read is not loaded
# then edit .env and paste each key after its name, no quotes needed
```

Shadowcrumbs loads `.env` at start. A variable already set in your shell wins. `.env` is gitignored, and a test fails if it is ever tracked.

## Check that it worked

```bash
./shadowcrumbs.sh status                       # shows which of the Brave and GitHub keys are set, names only
.venv/bin/python tools/verify_sources.py       # asks each service, about example.com, never the client
```

Verify shows `OK`, `FAIL` (the service rejected the key), `WARN` (a limit or a quirk) or `MISSING` (no key). The Brave check uses one query from your quota. Nothing prints a key.

If a check fails, the usual causes are a stray space or quote when pasting, a key for the wrong service, an expired token, or a plan that has run out.

## If a key leaks

Treat it as burned. Revoke it at the page where you made it and make a new one. Keys are never written to the logs or the databases, but a key pasted into a chat, an issue, a commit or a screenshot has left your hands. Then update `.env`.

If you ever commit one by accident, rotating it matters more than rewriting history.
