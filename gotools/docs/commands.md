# srt command reference

Every command reads a list from `-l <file>` **or stdin**, and writes to stdout
**or `-o <file>`**. Status/progress goes to **stderr**, so stdout stays clean to
pipe into the next tool. Run `srt <command> -h` for the live flag list.

Most target-list commands also fall back to the project's results database
(`.srt/srt.db`, see [results](#results)) when **none** of `-l`, a positional
arg, or piped/redirected stdin is given **and** stdin is an interactive
terminal — so running one bare, by hand, after an earlier run or pipeline
already saved what it needs, uses that instead of hanging waiting for you to
type targets. A real pipe (even an empty one) is never affected: existing
scripts and `cmd1 | cmd2` chains behave exactly as before. `-from <kinds>`
(comma list, e.g. `-from domain,subdomain`) picks which result kind(s) to
read instead of the command's own default, and `-where "status=<list/
ranges>"` narrows that further by HTTP status (e.g. `-where
"status=200,301-399"`). A command's own `-h` says which kind(s) it defaults
to; `srt results -kind` lists every kind actually saved so far. Commands
with this fallback: `probe`, `portscan`, `resolve`, `traceroute`,
`subdomains`, `gau`, `dork`, `sensitive`, `params`, `robots`, `validate`,
`ftp`, `telnet`, `smb`, `ldap`, `ssh`, `mssql`, `vnc`, `rdp`.

If a command is still working 5 seconds after it starts, it logs a
`still running (Ns elapsed)...` line to stderr every 5 seconds until it's
done — so a long run on a big input never looks hung. `fuzz` and `portscan`
show their own richer live counters instead of this generic line.

Jump to: [ipexpand](#ipexpand) · [ipports](#ipports) · [resolve](#resolve) ·
[portscan](#portscan) · [traceroute](#traceroute) · [domains](#domains) · [scopecheck](#scopecheck) ·
[subdomains](#subdomains) · [probe](#probe) · [burphosts](#burphosts) ·
[burpscope](#burpscope) · [gau](#gau) · [dork](#dork) · [sensitive](#sensitive) ·
[params](#params) · [paramdiscover](#paramdiscover) · [dirlist](#dirlist) ·
[robots](#robots) · [validate](#validate) · [snyk](#snyk) ·
[relpaths](#relpaths) · [fuzz](#fuzz) ·
[ftp · telnet · smb · ldap · ssh · mssql · vnc · rdp](#protocol-clients-ftp--telnet--smb--ldap--ssh--mssql--vnc--rdp) ·
[pipeline](#pipeline) ·
[results](#results) · [runs](#runs) · [export](#export) · [db](#db) ·
[shell](#shell) · [version](#version)

---

## ipexpand

Expand a scope file of IPs and CIDRs into a unique, numerically sorted list of
individual IPs. (Port of `legacy/HOST/ipparser.py`.)

| Flag | Default | Meaning |
|---|---|---|
| `-l` | stdin | input scope file |
| `-o` | stdout | output file |

```bash
srt ipexpand -l scope.txt            # 10.0.0.0/30 -> 10.0.0.0..3
cat scope.txt | srt ipexpand | httpx -silent
```

Invalid lines are skipped with a warning on stderr. A `/8` costs nothing to hold
because membership is tested lazily elsewhere, but `ipexpand` does expand fully —
don't feed it enormous ranges unless you want every address.

---

## ipports

Append ports to each IP, one `host:port` per line, ready for `httpx`.
(Port of `legacy/HOST/format-ips.py`.)

| Flag | Default | Meaning |
|---|---|---|
| `-l` | stdin | input IP file |
| `-o` | stdout | output file |
| `-ports` | `8080,8443` | comma-separated ports |

```bash
srt ipexpand -l scope.txt | srt ipports -ports 8080,8443,9090 | httpx -silent
```

---

## resolve

Forward (A/AAAA) or reverse (PTR) DNS lookup, concurrent. Covers the HOST
methodology's "DNS check" (forward) and the reverse-lookup half of its
excluded-host handling (see [methodology.md](methodology.md)).

| Flag | Default | Meaning |
|---|---|---|
| `-l` | stdin | hostnames, or IPs with `-reverse` |
| `-reverse` | off | treat input as IPs and do a PTR lookup instead |
| `-type` | — | forward lookups only: also collect these record types, comma list of `cname,mx,ns,txt` (not `soa` — no stdlib primitive for it) |
| `-c` | `40` | concurrent lookups |
| `-timeout` | `5s` | per-lookup timeout |
| `-o` | stdout | output file |
| `-json` | off | JSON lines (one per query, including failures) |

```bash
srt resolve -l hosts.txt                    # host -> ip1,ip2
srt ipexpand -l scope.txt | srt resolve -reverse   # ip -> ptr-name
srt resolve -l hosts.txt -type mx,txt        # + per-host MX/TXT lines
```

Failed lookups are reported to stderr and left out of plain-text output; with
`-json`, every query gets a line, successes and failures alike.

`-type`'s extra records print as additional lines per query —
`example.com MX -> 10 mail.example.com`, `example.com TXT -> v=spf1 ...` —
and land in `-json`'s `extra` field (`{"CNAME":[...],"MX":[...], ...}`),
keyed by uppercase type. A type with no records for a given query is just
missing from the output/JSON, not an error — a domain with no MX/TXT is the
common case. `-type` only applies to forward lookups (`-reverse` + `-type`
together is an error): DNS record types like MX/TXT are properties of a
name, not something to look up for a raw IP in reverse mode. `srt resolve
-type cname example.com` returns `example.com` itself when it has no CNAME
(DNS's definition: a name's "canonical name" is itself when it isn't an
alias — see `go doc net.Resolver.LookupCNAME`), same as `dig` would.

---

## portscan

Native concurrent TCP connect port scanner — common ports, uncommon/specialty
ports worth flagging, a full 1-65535 sweep, or an explicit list/range, plus a
best-effort banner grab. This is `srt`'s replacement for shelling out to
naabu; see [methodology.md](methodology.md)'s external-tool policy.

| Flag | Default | Meaning |
|---|---|---|
| `-l` | stdin | input IP/host list |
| `-p` | `common` | `common`, `uncommon`, `all`, or explicit e.g. `80,443,8000-9000` — comma-combinable, e.g. `common,uncommon` |
| `-c` | `200` | concurrent connection attempts |
| `-timeout` | `1s` | per-port connect timeout |
| `-banner` | `true` | best-effort read of a service's greeting banner |
| `-o` | stdout | output file |
| `-json` | off | JSON lines instead of `host:port [banner]` |

```bash
srt ipexpand -l scope.txt | srt portscan -p common,uncommon -json -o scan.json
echo 10.0.0.5 | srt portscan -p 1-65535 -c 500   # full sweep, higher concurrency
```

`uncommon` is the specialty/legacy-service list worth a manual look — rsync
(873) and Java RMI (1098/1099) are the two examples called out in
[methodology.md](methodology.md); `srt pipeline`'s HOST stage flags any open
port from this list automatically.

---

## traceroute

Native ICMP route trace — one echo per TTL (1 up to `-max-hops`), matching
each reply to its probe by id/sequence so unrelated ICMP traffic on the host
is ignored. `srt`'s replacement for shelling out to `traceroute`/`tracert`;
backs the HOST methodology's route trace for `pipeline`'s
[excluded-but-tracked hosts](pipeline.md#steps). IPv4 only for now.

| Flag | Default | Meaning |
|---|---|---|
| `-l` | stdin | input host/IP list |
| `-max-hops` | `30` | maximum TTL to probe |
| `-timeout` | `1s` | per-hop wait for a response before moving to the next TTL |
| `-o` | stdout | output file |
| `-json` | off | JSON lines (`target`, `addr`, `reached`, `hops: [{ttl, addr, rttMs}]`) instead of a plain per-hop listing |

```bash
echo 8.8.8.8 | srt traceroute
srt traceroute -l hosts.txt -max-hops 20 -json -o trace.json
```

**Needs a raw ICMP socket** — `CAP_NET_RAW` on Linux, or root. Without it,
`traceroute` fails once up front with that explanation rather than per
target. Not implemented on Windows yet (needs a different raw-socket API);
the binary still builds and runs there, this one command just reports it
can't.

---

## domains

Extract unique hostnames from `httpx` output (or any text). IPs are ignored —
a trailing alphabetic TLD is required. (Port of `legacy/HOST/domain-extracter.py`.)

| Flag | Default | Meaning |
|---|---|---|
| `-l` | stdin | input file |
| `-o` | stdout | output file |

```bash
srt domains -l httpx_out | srt scopecheck -scope scopeips > domains
```

---

## scopecheck

Resolve each host and keep only those whose IP falls inside a scope file.
Concurrent DNS. (Port of `legacy/HOST/domain_enum.py`.)

| Flag | Default | Meaning |
|---|---|---|
| `-l` | stdin | hosts/subdomains file |
| `-scope` | — (required) | scope file of IPs/CIDRs |
| `-o` | stdout | output file |
| `-c` | `40` | concurrent DNS resolutions |
| `-timeout` | `5s` | per-host DNS timeout |

```bash
srt subdomains -d example.com | srt scopecheck -scope scopeips -c 80 > subs
```

---

## subdomains

Find subdomains for a domain: passive, via crt.sh certificate transparency
logs (always runs), plus optional active DNS brute force when a wordlist of
labels (`www`, `api`, `dev`, ...) is given. `srt`'s replacement for
subfinder.

| Flag | Default | Meaning |
|---|---|---|
| `-d` | — | single target domain |
| `-l` | stdin | file of target domains |
| `-w` | — | wordlist of labels for active DNS brute force; omit to skip active enum |
| `-passive` | `true` | passive enumeration via crt.sh |
| `-active` | `true` | active DNS brute force (needs `-w`) |
| `-c` | `100` | concurrent DNS resolutions (active) |
| `-timeout` | `30s` | HTTP timeout for crt.sh |
| `-resolve-timeout` | `5s` | per-lookup DNS timeout (active) |
| `-o` | stdout | output file |

```bash
srt subdomains -d example.com -w subdomain-wordlist.txt -o subs.txt
srt subdomains -d example.com | srt probe   # passive only, then recon each
```

---

## probe

Native httpx-lite: for each target, fetch the root page and report status,
content-length, title, `Server` header, and a best-effort tech-detect
(WordPress/Drupal/Joomla/Laravel/Django/Express/PHP/ASP.NET/nginx/Apache/
IIS/Cloudflare — a small, conservative signature set, not a
wappalyzer-equivalent). Covers the methodology's "recon on root" step.

| Flag | Default | Meaning |
|---|---|---|
| `-l` | stdin | target list: URLs or bare hosts |
| `-timeout` | `10s` | per-request timeout |
| `-insecure` | `true` | skip TLS verification |
| `-c` | `40` | concurrent probes |
| `-o` | stdout | output file |
| `-json` | off | JSON lines instead of a table |
| `-color` | `auto` | color the table output: `auto`\|`always`\|`never` (ignored with `-json`); status 2xx/3xx/4xx/5xx in green/cyan/yellow/red, detected tech in magenta, a failed probe's whole row in red |

A bare host (no scheme) tries `https://` then falls back to `http://`.

```bash
srt subdomains -d example.com | srt probe -json -o probe.json
```

---

## burphosts

Parse a Burp Suite scope JSON export and emit `host[/dir]` entries (no scheme)
for `httpx`/`katana`. Wildcard hosts (`*.example.com`) are collapsed to the apex
so they resolve. (Port of `legacy/WEB/domains-to-httpx.py`.)

| Flag | Default | Meaning |
|---|---|---|
| `-l` | stdin | Burp scope JSON |
| `-o` | stdout | output file |

```bash
srt burphosts -l target_scope.json | httpx -title -tech-detect -sc -o httpx_out
srt burphosts -l target_scope.json | katana -jc -o katana_out
```

---

## burpscope

Parse a Burp scope JSON and print a readable, colored path list: **green** =
include, **red** = exclude. Wildcard/apex duplicates are collapsed.
(Port of `legacy/WEB/domains-parser.py`.)

| Flag | Default | Meaning |
|---|---|---|
| `-l` | stdin | Burp scope JSON |
| `-o` | stdout | output file |
| `-color` | `auto` | `auto` \| `always` \| `never` |

```bash
srt burpscope -l target_scope.json
```

---

## gau

Collect archived URLs for a domain from the Wayback Machine CDX API. Needs
outbound internet to `web.archive.org`. (Port of `legacy/WEB/gau_recon.py`.)

| Flag | Default | Meaning |
|---|---|---|
| `-d` | — | single target domain |
| `-l` | stdin | file of domains |
| `-sub` | off | include subdomains (`*.domain`) |
| `-o` | — | write collected URLs to a file |
| `-v` | off | also print URLs when `-o` is set |
| `-ce` | off | report URLs with sensitive extensions |
| `-cp` | off | report URLs grouped by vuln param class |
| `-timeout` | `90s` | per-host HTTP timeout |

```bash
srt gau -d example.com -sub -o all_urls.txt
srt gau -d example.com | srt params -class ssrf | httpx -silent
```

---

## dork

Google dorking: generate a curated set of advanced search-operator queries
for a target domain and/or engagement name, and — with a Google Custom
Search API key — actually run them. Scraping google.com's own result pages
isn't how this works (against Google's terms of service, rate-limited/
CAPTCHA'd within a handful of requests, and not even reachable from this
project's own sandbox); the Google Custom Search JSON API
(`customsearch.googleapis.com`) is the one programmatic, ToS-compliant way
to run these queries. Without a key, `dork` still prints every generated
query as a ready-to-paste `google.com/search?q=...` URL — zero network
traffic, useful on its own.

| Flag | Default | Meaning |
|---|---|---|
| `-d` | — | single target domain |
| `-l` | stdin | file of target domains (or the project db's `domain` records — see `-from`) |
| `-name` | — | engagement/org name, for name-scoped categories (paste sites, cloud buckets, source hosting) |
| `-categories` | every supported category | comma list to restrict to, e.g. `-categories admin,listing` |
| `-list-categories` | — | print every category name/description and exit |
| `-search` | off | actually run each query against the Custom Search API (needs `-api-key`/`-cx` or `$SRT_GOOGLE_API_KEY`/`$SRT_GOOGLE_CSE_ID`) |
| `-api-key`, `-cx` | — | Custom Search API key / Programmable Search Engine ID |
| `-num` | `10` | results per query (API max 10/request) |
| `-delay` | `1s` | with `-search`: delay between queries |
| `-max-daily` | `100` | with `-search`: hard cap on queries sent per API key per UTC day — see below |
| `-o` | stdout | output file |
| `-json` | off | JSON lines instead of plain text/URLs |

`-list-categories` output (domain-scoped categories need `-d`/`-l`;
name-scoped ones need `-name`):

```
files         (domain) office/document files
backup        (domain) backup/config/database file leaks
admin         (domain) admin/login panels
listing       (domain) open directory listings ("index of")
errors        (domain) error messages / stack traces
confidential  (domain) documents marked confidential/internal
cloud         (name)   third-party cloud storage buckets mentioning the org
pastes        (name)   paste-site leaks mentioning the org
code          (name)   exposed secrets in public source hosting
```

```bash
# query list only — paste into a browser, no API key needed
srt dork -d example.com -name "Acme Corp"

# actually run them (needs a Custom Search API key + Programmable Search Engine)
export SRT_GOOGLE_API_KEY=... SRT_GOOGLE_CSE_ID=...
srt dork -d example.com -search -o hits.txt
```

Getting an API key/engine ID: [developers.google.com/custom-search/v1/overview](https://developers.google.com/custom-search/v1/overview),
or run [`config.sh`](../../config.sh) from the repo root for a guided
walkthrough (also covers `SRT_CHAOS_API_KEY` and `uncover`'s per-engine keys).
Free tier: 100 queries/day — one `srt dork -search` over 6 domain categories
(no `-name`) costs 6 of those. Past the free tier, every query is **billed**
(roughly $5 per 1,000 queries).

**`-search` enforces that 100/day cap itself, by default** — `-max-daily`
defaults to 100, not unlimited, and every query decrements a per-API-key
budget tracked in `~/.srt/dork_quota.json` across *every* `srt dork`/`srt
pipeline -dork` run on this machine, not just within one invocation. Once
the budget for the day is spent, `-search` stops sending queries (reporting
how many of the planned queries it actually sent) rather than silently
running past the free tier into billing. The budget resets at UTC midnight
and is per API key, so a different key gets its own 100.

This is a **local safety net, not an authoritative one**: it protects this
machine's invocations of this key, not the key itself from other sources.
The one way to *guarantee* no charge, regardless of what runs this key, is
in the [Google Cloud Console](https://console.cloud.google.com/apis/) —
either don't attach a billing account to the project the key belongs to at
all (requests just start failing once the free 100/day is used, which
`dork` treats as an ordinary per-query error), or set a hard daily quota
override there. Do that first if you want a real guarantee; `-max-daily`
is a second layer, and raising it past 100 is only for a key you've
deliberately enabled billing on.

---

## sensitive

Filter a URL list down to ones ending in a sensitive extension (`.sql`, `.env`,
`.bak`, `.key`, …). Handles multi-part extensions like `.tar.gz`.

| Flag | Default | Meaning |
|---|---|---|
| `-l` | stdin | URL list |
| `-o` | stdout | output file |

```bash
cat all_urls.txt | srt sensitive
```

**Content-based classification (`-content`).** Extension matching only
catches a file by its *name* -- a leaked AWS key sitting in a `.js` bundle or
a plain `config` endpoint never ends in `.env`, so it's invisible to the
default mode. `-content` instead fetches every URL and scans the body
against a small, high-precision set of secret/credential signatures (AWS/
Google/Slack/GitHub/Stripe tokens, private key blocks, JWTs, basic-auth and
database connection strings in a URL, generic `key=`/`secret=`/`password=`
assignments) -- regardless of what the URL looks like:

```bash
cat all_urls.txt | srt sensitive -content -c 30 -json -o secrets.jsonl
# stderr: [!] content scan: fetched 842/900 URL(s) (58 failed), 3 secret(s) found
# [AWS Secret Access Key] https://host/old/config.js
#     match:   AWS_SECRET_ACCESS_KEY=...
#     context: ...AWS_SECRET_ACCESS_KEY=... (truncated) ...
```

| Flag | Default | Meaning |
|---|---|---|
| `-content` | off | scan body content instead of filtering by extension |
| `-c` | `20` | concurrent fetches |
| `-timeout` | `15s` | per-request timeout |
| `-insecure` | `true` | skip TLS verification |
| `-max-size` | `2097152` (2 MiB) | max bytes read per response |
| `-json` | off | emit JSON lines (`url`, `pattern`, `match`, `context`) instead of a table |

A fetch error or non-2xx response is skipped, not fatal -- a dead link from
an old Wayback crawl is routine on a large `gau` dump. Since this sends a
request per URL rather than just inspecting a string, it's opt-in and
traffic-shaped by `-c`/`-timeout` the same way `fuzz`'s traffic controls are.

---

## params

Group URLs by the vuln class their parameters hint at (`sqli`, `xss`, `lfi`,
`rce`, `ssrf`, `open-redirect`), using the wordlists baked in from `gau_recon.py`.

| Flag | Default | Meaning |
|---|---|---|
| `-l` | stdin | URL list |
| `-class` | — | print only one class (pipe-friendly) |

```bash
srt params -l all_urls.txt                      # grouped report
srt params -l all_urls.txt -class sqli | nuclei  # one class, piped
```

---

## paramdiscover

Guess hidden GET parameters an endpoint reads but never exposes in any URL
or form -- `params` above only ever classifies parameter names already
sitting in a URL; this finds the ones that aren't. Arjun-style: fetch a
baseline response, try candidate names in batches (`-bs`, default 25), and
only bisect a batch that changed something (a different status, the probe
value reflected in the body, or a body size/word-count delta beyond
`-tol`) down to the specific name(s) responsible -- far fewer requests
than one per candidate whenever (as is typical) almost none of a batch's
names apply. Skips binary responses (by `Content-Type`) after the
baseline alone. Defaults to the embedded SecLists `burp-parameter-names.txt`
(~6.4k names) when no `-w` is given.

| Flag | Default | Meaning |
|---|---|---|
| `-l` | stdin/args | endpoint URL list |
| `-w` | embedded list | candidate parameter name wordlist (repeatable) |
| `-top` | `0` (all) | try at most the first N candidate names |
| `-X` | `GET` | `GET` adds candidates to the query string; anything else form-encodes them in the body |
| `-bs` | `25` | candidate names tried per request before bisecting |
| `-tol` | `5` | body size/word-count tolerance around the baseline, % |
| `-timeout` | `10s` | per-request timeout |
| `-insecure` | `true` | skip TLS verification |
| `-c` | `10` | endpoints probed concurrently |
| `-delay` | `0` | fixed delay before each request |
| `-o` | stdout | output file |
| `-json` | off | JSON line per endpoint (`url`, `found`, `reflected`, `requests`) |
| `-silent` | off | print only endpoints with at least one discovered parameter |
| `-color` | `auto` | `auto` \| `always` \| `never` |

```bash
srt paramdiscover -l endpoints.txt -json -o hidden-params.json
echo "https://target/search" | srt paramdiscover -top 1000
```

A name followed by `*` in the default table output means its value came
back in the response body (a strong, separate signal worth noting even
when nothing else about the response changed -- e.g. a reflected,
unsanitized parameter).

---

## dirlist

Recursively harvest file URLs from open directory listings (Apache/nginx
autoindex). Stays on the same scheme+host, skips image/css noise.
(Port of `legacy/dir_listing.py`.)

| Flag | Default | Meaning |
|---|---|---|
| `-l` | stdin | seed directory URLs |
| `-o` | stdout | output file |
| `-timeout` | `15s` | per-request timeout |
| `-insecure` | `true` | skip TLS verification |
| `-depth` | `0` | max recursion depth (0 = unlimited) |

```bash
echo "https://target/uploads/" | srt dirlist -o loot.txt
```

---

## robots

Fetch `robots.txt` and probe every `Allow`/`Disallow` path, printing
`url [status] [length]` (green for 200). Wildcard (`*`) entries are skipped.
It also reads the sitemap(s) robots.txt declares via `Sitemap:` (or
`/sitemap.xml` when none are declared), follows sitemap indexes two levels
deep and gzipped sitemaps, and probes the URLs listed under a `[Sitemap]`
section. Only URLs on the base URL's own host are kept.
Accepts many base URLs via args, `-l`, or stdin. (Port of `legacy/robots-checker.py`.)

| Flag | Default | Meaning |
|---|---|---|
| `-l` | — | file of base URLs (args/stdin also work) |
| `-color` | `auto` | `auto` \| `always` \| `never` |
| `-timeout` | `15s` | per-request timeout |
| `-insecure` | `true` | skip TLS verification |
| `-c` | `20` | concurrent probes per host |
| `-no-sitemap` | off | don't fetch or probe sitemaps |
| `-sitemap-max` | `100` | max sitemap URLs probed per base URL (`0` = none) |

```bash
srt robots https://target
cat live_hosts.txt | srt robots -color never
```

---

## validate

Re-probe candidate URLs and keep only the real ones. Many sites answer 200
(or a redirect to `/login`, or a WAF 403) for any path, so a status code
alone proves nothing: `validate` fetches random not-found paths per host
(per first directory and extension — `/api/*` and `*.php` often differ from
the root) to fingerprint what "not found" looks like there (status, size
normalized for echoed paths, word count; the `Location` for redirects) and
drops every URL that matches. It does not follow redirects, treats
2xx/3xx/401/403 as candidates, and finally rejects groups of `-learn`
(default 10) near-identical "valid" responses on one host that the
calibration missed.

| Flag | Default | Meaning |
|---|---|---|
| `-l` | stdin/args | URL list |
| `-probes` | `3` | random not-found paths per host/directory/extension class |
| `-tol` | `5` | size tolerance around a not-found response, % |
| `-learn` | `10` | reject groups of this many near-identical valid responses (0 = off) |
| `-timeout` | `10s` | per-request timeout |
| `-insecure` | `true` | skip TLS verification |
| `-c` | `40` | concurrent requests |
| `-max` | `0` | check at most this many URLs (0 = all) |
| `-o` | stdout | write valid URLs here |
| `-silent` | off | print only valid URLs |
| `-json` | off | JSON line per URL, valid and rejected |
| `-rejected` | — | write `reason<TAB>URL` for rejected URLs here |

```bash
srt validate -l candidates.txt -silent -o valid.txt -rejected why-not.txt
cat gau.txt | srt validate -silent
```

---

## snyk

Test a version against a Snyk package advisory page's affected ranges. Needs
outbound internet to `security.snyk.io`. Comparison is numeric (`2.10 > 2.9`).
(Port of `legacy/synk_parser.py`.)

| Flag | Default | Meaning |
|---|---|---|
| `-url` | — (required) | Snyk package advisory URL |
| `-version` | — (required) | installed version (e.g. `3.7` or `3.7.2`) |
| `-timeout` | `30s` | HTTP timeout |
| `-insecure` | `true` | skip TLS verification |

```bash
srt snyk -url "https://security.snyk.io/package/composer/moodle%2Fmoodle" -version 3.7
```

A row is reported when the version satisfies every comparator in its affected
range. If the page layout changes and no table is found, it errors clearly.

---

## relpaths

Walk a directory and print every file as a path relative to the root — turn an
unpacked CMS/plugin source tree into a target-specific ffuf wordlist.
(Port of `legacy/relative_paths.py`.)

| Flag | Default | Meaning |
|---|---|---|
| `-o` | stdout | output file |

```bash
srt relpaths ./wp-plugin-src > plugin-paths.txt
```

---

## fuzz

Scope-aware concurrent directory/file bruteforcer with precise traffic control.
See [fuzz.md](fuzz.md) for the full guide. Flag summary:

**Targets / wordlists**

| Flag | Default | Meaning |
|---|---|---|
| `-u` | — | target URL with `FUZZ` — **repeatable for multi-host** (also honored in `-H`/`-d`) |
| `-tl` | — | file of target URLs, one per line (each may contain `FUZZ`) |
| `-w` | stdin | wordlist file (repeatable) |
| `-e` | — | extra extension per word, e.g. `-e .php` (repeatable) |
| `-ext-auto` | | discover which extensions each host serves (see below); combines with `-e` |
| `-words-auto` | off | add curated extra words per host from its detected tech stack (`wp-admin` for WordPress, ...) and page title — capped at 40 words/host, shares `-ext-auto`'s probe request when both are set |
| `-mutate-case` | off | also try lower/UPPER/Title-case variants of every word |
| `-scope` | — | Burp scope JSON: gate requests + seed targets when no `-u`/`-tl` |

A wordlist line can also carry a literal `%ext%` token (e.g. `backup.%ext%`)
that expands against the resolved extensions directly, instead of only ever
having one appended as a suffix — see [fuzz.md](fuzz.md)'s wordlist
mutations section.

**Traffic control** (see [multi-host](#multi-host-sharing-one-wordlist-across-hosts))

| Flag | Default | Meaning |
|---|---|---|
| `-X` | `GET` | HTTP method |
| `-H` | — | extra header `"Name: Value"` (repeatable) |
| `-d` | — | request body |
| `-ua` | srt UA | User-Agent |
| `-random-agent` | off | rotate a random browser UA per request |
| `-proxy` | — | proxy URL, e.g. `http://127.0.0.1:8080` (Burp) |
| `-c` | `40` | total concurrent workers (global) |
| `-rate` | `0` | max requests/sec **per host** (0 = unlimited) |
| `-rate-global` | `0` | max requests/sec across **all** hosts (0 = unlimited) |
| `-hc` | `0` | max concurrent requests **per host** (0 = unlimited; still a ceiling with `-adaptive-conc`) |
| `-adaptive-conc` | off | let each host's concurrency float with observed latency/errors instead of a fixed `-hc` |
| `-delay` | `0` | fixed delay before each request |
| `-jitter` | `0` | random extra delay up to this |
| `-timeout` | `10s` | per-request timeout |
| `-retries` | `1` | retries on transport error |
| `-maxtime` | `0` | overall deadline (0 = none) |
| `-maxerrors` | `0` | abandon a target after N consecutive errors |
| `-auto-throttle` | off | back off a host's rate automatically on 429/503 |
| `-insecure` | `true` | skip TLS verification |

### Multi-host: sharing one wordlist across hosts

Give several targets (repeat `-u`, use `-tl`, or let `-scope` seed them) and
srt bruteforces them **concurrently and interleaved** — web1/web2/web3 all make
progress at once instead of web1 being drained first. A fair round-robin
scheduler enforces the limits so nothing gets flooded:

- `-rate` caps requests/sec **per host** — the knob that keeps any single target gentle;
- `-hc` caps concurrent requests **per host**;
- `-rate-global` caps the combined rate — protects your own uplink/network;
- `-c` is the total worker pool shared across all hosts.

Recursion stays on the host it was discovered on, inheriting that host's limits.

```bash
# three hosts, each limited to 10 req/s, 200 req/s total ceiling
srt fuzz -u https://web1.com/FUZZ -u https://web2.com/FUZZ -u https://web3.com/FUZZ \
  -w big.txt -rate 10 -rate-global 200 -hc 20 -c 60 -ac

# same, from a file of hosts
srt fuzz -tl hosts.txt -w big.txt -rate 10 -rate-global 200 -ac
```

**Matchers / filters** (lists + ranges, e.g. `200-299,403`)

| Match | Filter | On |
|---|---|---|
| `-mc` | `-fc` | status code |
| `-ms` | `-fs` | response size (bytes) |
| `-mw` | `-fw` | word count |
| `-ml` | `-fl` | line count |
| `-mr` | `-fr` | body regex |
| `-ac` | | auto-calibrate: fingerprint and filter soft-404s **per directory** |
| `-ac-tol` | | with `-ac`: size/word tolerance in percent (default `1`; `0` = exact sizes) |
| `-ac-learn` | | with `-ac`: filter a cluster after N near-identical hits (default `12`; `0` = off) |

Default `-mc`: `200-299,301,302,307,308,401,403,405,500`. Use `-mc all` to match
everything. `-ac` recalibrates for each directory it recurses into, so a
soft-404 size under `/admin` never hides a real finding under `/api`; a child
directory seeds its calibration from its parent's instead of starting cold.

**Preflight (always runs, `-ac` or not).** Before any real fuzzing starts,
srt fires two guaranteed-nonexistent paths at each host's root to see what a
miss actually looks like there. A host whose "miss" would pass the
configured matchers (i.e. look like a hit) gets soft-404 filtering
auto-enabled for it even without `-ac` — logged as `preflight <host>: a
non-existent path doesn't 404 (...) -- auto-enabling soft-404 filtering`.
Either way, the fingerprint seeds that host's top-level `-ac` calibration.

**Automatic extensions (`-ext-auto`).** Instead of guessing `-e .php -e .bak`,
the fuzzer works out what each host serves, once per host:

1. **Tech hints** — the root page is fingerprinted with `probe`'s tech-detect
   and the matching extensions are added directly: PHP/WordPress/Drupal/Joomla/
   Laravel → `.php` (+ `.phtml`/`.inc`), ASP.NET/IIS → `.aspx .ashx .asmx .asp`,
   Express → `.js .json`, Django → `.json`.
2. **Live verification** — every other common extension (`.php .asp .aspx .jsp
   .html .htm .js .json .txt .xml .bak .old .zip`) is tested by requesting
   `index`/`default`/`login` with it, and kept only if the response differs from
   what random non-existent names with that extension return. That baseline uses
   the soft-404 band logic, so an app that answers every miss with a jittery
   `200` doesn't make every extension look valid.

It logs `ext-auto <host>: tech=… hinted=… discovered=…`. Your own `-e` values
are always kept. Cost: roughly 8 requests per verified extension per host, sent
before the real run (and subject to `-rate`).

**Soft-404s that vary in length.** Some apps answer every missing path with a
`200` whose size wobbles (`3302`, `3305`, `3310`, `3312` — a CSRF token, a
timestamp, or the requested path echoed back). `-ac` handles this three ways:

- **Reflection-normalized size** — echoes of the tried word are subtracted, so
  `/a` and `/a-very-long-word` look the same.
- **Tolerance band** (`-ac-tol`, default 1%, floor a few bytes) around the
  calibration probes, which are varied in length and extension. The *word
  count* must also fall in its band, so a genuinely different page of similar
  byte length is still reported.
- **Runtime learning** (`-ac-learn`) — if N hits in one directory share a
  status and near-identical shape, they are filtered from then on and a
  `learned soft-404` line is logged. The first N are already printed by then.

Raise `-ac-tol` for noisier apps; `-ac-tol 0 -ac-learn 0` restores exact-size
matching.

**Highlighting / recursion / output**

| Flag | Default | Meaning |
|---|---|---|
| `-hl` | — | highlight response bodies matching this regex (prints snippets) |
| `-recursion` | off | recurse into discovered directories |
| `-depth` | `0` | max recursion depth (0 = unlimited) |
| `-resume` | — | state file: skip done work and persist progress for restart |
| `-o` | — | write matched results to a file |
| `-json` | off | emit JSON lines (adds `highlights` when `-hl` is set) |
| `-silent` | off | print only matched URLs |
| `-color` | `auto` | `auto` \| `always` \| `never` |
| `-ndjson` | — | also stream every matched hit as an ndjson line to this file, independent of `-json`/`-o`/`-silent` |
| `-summary` | off | print a per-status-code count table at the end, over every response seen — independent of `-mc`/`-fc` |

`-recursion` follows the classic redirect-to-trailing-slash signal, plus a
direct `2xx` on an extensionless word once its `<word>/` form is confirmed to
also resolve to a real page (for apps that list a directory inline, no
redirect) — never probed for a word that has a dot in it.

With `-hl`, each hit is followed by indented `↳` snippets showing the matched
text in context (handy for spotting API keys, secrets, version strings, stack
traces in discovered files). `-resume <file>` records every completed request
and discovered directory, so re-running the same command continues where it
left off instead of repeating work. `-ndjson` lets you keep the colored table
on screen while another tool tails structured output from a file; `-summary`
shows every status code seen regardless of `-mc`/`-fc`, for deciding what to
filter next time instead of guessing.

---

## Protocol clients: ftp · telnet · smb · ldap · ssh · mssql · vnc · rdp

Phases 1-2 of the internal-pentest protocol-client roadmap (see
[ROADMAP.md](ROADMAP.md)), plus four more protocols beyond that roadmap's
original four: native Go clients wrapping a mature library per protocol
(`internal/protocols/<name>`) behind SRT's own scope/results/metering
conventions, rather than reimplementing a wire format by hand -- `vnc` and
`rdp`'s security-layer negotiation are the two exceptions, hand-rolled
because no good library exists (see their own sections below). Every one of
these eight shares the same credential flag shape, netexec-style, except
`vnc` (no username concept) and `rdp` (no login attempted at all):

| Flag | Default | Meaning |
|---|---|---|
| `-l` | stdin | target list: `host` or `host:port` (falls back to the project db's `port` records, like `probe`/`portscan`) |
| `-u` | — | username (repeatable; default: anonymous/unauthenticated only) |
| `-p` | — | password (repeatable, paired with `-u` in listed order; `vnc` reads this directly, no `-u` needed) |
| `-H` | — | NTLM/NT hash, for pass-the-hash (repeatable, paired with `-u`; `smb` and `ldap` use it directly, including over Kerberos for `smb`; `ftp`/`telnet`/`ssh`/`mssql`/`vnc` don't take hash auth) |
| `-d` | — | AD domain (also the Kerberos realm for `-k`) |
| `-local-auth` | off | authenticate against the target's local SAM, not the domain |
| `-k` | off | Kerberos auth instead of NTLM/simple bind, where supported (`smb` and `ldap` do) |
| `-key` | — | (`ssh` only) private key file for public-key auth, tried alongside `-p` for every `-u` |
| `-port` | the protocol's default | override the port |
| `-timeout` | 8-10s | per-connection timeout |
| `-c` | 10-20 | concurrent connections |
| `-o` / `-json` / `-color` | stdout / off / `auto` | same as every other command |

Every target is tried anonymous-first (so a bare `srt smb -l hosts.txt` needs
no flags at all), then with each credential attempt in turn until one is
accepted. A result is saved as its own kind (`ftp`, `telnet`, `smb`, `ldap`,
`ssh`, `mssql`, `vnc`, `rdp`) with a `severity` (`info`/`low`/`medium`/`high`)
in its data, the same way `probe`'s `title`/`server`/`tech` are — `srt
results -kind smb` lists them. None of the eight ever writes, deletes,
executes or opens a shell on the target, even when a login grants that
access — `smb`'s spider (below) only lists directory names, never opens a
file, and `ssh`'s login check never runs a command.

**Default output** is one line per result, netexec's own style, not a table:

```
PROTO     ip                port    hostname          [symbol] message
SMB       10.0.0.5          445     DC01              [+] CORP\administrator:Password1 (Pwn3d!)
```

`[symbol]` is `[*]` (info: a banner, an enumeration finding, anything with no
success/failure outcome of its own), `[+]` (an accepted login or session) or
`[-]` (a connection error or a rejected login); `hostname` falls back to the
bare IP when the protocol doesn't hand one over for free (only `smb`, from the
NTLM challenge, and `ldap`, from RootDSE's `dnsHostName`, do — empty on a
Kerberos login either way). `(Pwn3d!)` marks a result that is a genuine
access-level compromise, not just an accepted credential, decided per
protocol: `telnet`/`ssh` for any shell-granting login (no-auth or a real
credential — a session is a shell either way); `vnc` the same, for full
desktop control; `smb` for a non-anonymous login where the share report also
shows `C$` or `ADMIN$` readable (local Administrator); `mssql` for a login
confirmed a member of the `sysadmin` fixed server role (`SELECT
IS_SRVROLEMEMBER('sysadmin')`, read-only). `ftp`, `ldap` and `rdp` never mark
a line `(Pwn3d!)` — read/write file access, directory read access, and a
security-layer fingerprint (`rdp` never even attempts a login) aren't the same
claim. This is unaffected by `-json`, which keeps its own one-line-per-result
machine-readable shape.

```bash
srt ftp -l hosts.txt -list                          # anonymous-login check + root listing
srt smb -l hosts.txt -u administrator -H <nthash>   # pass-the-hash: fingerprint, share enum, local SAM
srt smb -l dc01.corp.local -u alice -p pw -d CORP.LOCAL -k    # Kerberos bind (needs the DC's hostname, not its IP)
srt ldap -l hosts.txt -u svc-acct -p '' -d CORP      # simple bind as svc-acct@CORP + RootDSE + AD enum
srt telnet -l hosts.txt -u root -p toor             # banner/no-auth-shell check, then try a login
srt ssh -l hosts.txt -u deploy -key ~/.ssh/id_ed25519   # key auth check, no shell opened
srt mssql -l hosts.txt -u sa -p '' -json -enum      # SQL-auth login check + version/database list
srt mssql -l hosts.txt -u administrator -p pw -d CORP   # NTLM/Windows auth (any "DOMAIN\user" triggers it)
srt vnc -l hosts.txt -p mypassword                  # no-auth check, then the given password
srt rdp -l hosts.txt                                # security-layer fingerprint only, never logs in
```

**`ldap`'s authenticated enumeration** (`-enum`, off by default — opt in) runs after
any successful bind: a bulk user search reduced to AS-REP roastable
accounts (`userAccountControl`'s `DONT_REQ_PREAUTH` bit), membership in a
well-known high-value group (Domain/Enterprise/Schema Admins,
Administrators), and the domain password policy (flagged weak under an
8-character minimum, no complexity requirement, or no lockout). `ldap -k`
needs the realm (`-d`) and either a password or `$KRB5CCNAME` pointing at an
existing ticket cache (pass-the-ticket — the `srt shell`'s `krb5` built-in
sets it for you; pass-the-key isn't supported); the target must be the DC's
actual hostname, not its IP, since that's what its LDAP service principal
name is keyed to — `srt` writes a disposable `krb5.conf` per attempt,
treating the target as its own realm's KDC.

**`smb`** wraps `jfjallid/go-smb`, which exposes what `go-smb2` (the
original Phase 1 pick) didn't: a real netexec-style fingerprint line
(negotiated dialect, whether signing is required, and — from the NTLM
challenge, so empty on a Kerberos login — hostname/domain/OS build), a
real share list over MS-SRVS (each share with the server's own remark, not
a guessed one), and `-k` itself (`go-smb2`'s auth interface was unexported,
with no way to plug Kerberos in). `-k` here also takes `-H` for
pass-the-hash over Kerberos — `ldap`'s Kerberos support still can't do
that. With neither `-p` nor `-H`, `-k` here also authenticates straight from
`$KRB5CCNAME` (pass-the-ticket) with no extra code needed — `go-smb`'s own
Kerberos client checks that variable itself before ever asking for a
password; the `srt shell`'s `krb5` built-in sets it for you. A successful
session is always two lines, netexec-style: `[*]` the fingerprint (OS/name/
domain/dialect/signing, with `(null session)` folded in when that's what got
in) then a bare `[+] user:pass` (or `[+] (anonymous)`) line — no share or
enumeration text crammed into either. **`-shares`** (off by default — opt
in) prints the per-share listing, both the one-line summary and the
expanded per-share table, for a target where a session actually got in.
**`-local-enum`** (off by default — opt in) additionally lists the target's
*local* (non-domain) SAM users and local Administrators-alias membership
over MS-SAMR — the same DCE/RPC machinery as the share list, just a
different pipe; tried regardless of which credential got the session in,
since a misconfigured target has let this succeed over a null session
before. **`-spider`** (off by default — it's a real recursive crawl) walks
every share the read-access check found readable (bounded depth and entry
budget) flagging filenames that commonly carry credentials —
`.kdbx`/`.pem`/`.key`/`.pfx`/`.ppk`/`.ovpn`,
`password`/`unattend`/`id_rsa`/`web.config`/`.git-credentials` — reported
as a separate `interesting-file` finding.

`telnet` has no formal protocol marker for "this is a login prompt" or "this
is a shell" — it classifies by the conventional wording (`login:`,
`username:`) versus a trailing shell-style prompt character (`$ # > %`), so an
unusual banner can show up as a plain `banner` finding rather than
`no-auth`/`login-ok`; read `-json`'s `detail` field when in doubt.

**`ssh`** wraps `golang.org/x/crypto/ssh`. Every target is tried with no
credentials at all first (`"none"`, RFC 4252 — the client always sends
this first regardless of what's configured; a server that accepts it
outright needs no password at all, flagged `no-auth`), then `-u`/`-p` and
`-key` (paired with `-p` as the key's own passphrase, if it's encrypted).
It never opens a shell or runs a command.

**`mssql`** wraps `microsoft/go-mssqldb`, the official driver. A plain `-u`
is SQL Server authentication; `-u` combined with `-d` becomes
`"DOMAIN\user"`, which activates the driver's own NTLM provider
automatically (no extra flag). `-H` isn't supported — the NTLM provider
takes a password only. A successful login is always followed by a `[*]`
`SELECT @@VERSION` banner line, then a bare `[+] user:pass` (`(Pwn3d!)` if
`IS_SRVROLEMEMBER('sysadmin')` confirms it); **`-enum`** (off by default —
opt in) adds a third `[*]` line with a bounded `sys.databases` list — all
read-only; `xp_cmdshell` and every other execution-capable stored
procedure are never called.

**`vnc`** is a small hand-rolled RFB (RFC 6143) client — no maintained Go
VNC library exists. It understands exactly the two security types every
real deployment uses: `None` (no password at all, `no-auth`) and `VNC
Authentication` (the classic DES challenge-response, `-p`). A server
offering only the Tight/VeNCrypt/TLS extensions is reported as a `banner`
Finding naming what it offered, not a failure. It never requests a
framebuffer update or sends an input event. Real-world note: a VNC server
that throttles a client after enough recent failed attempts (most do) can
make a *later* password in a long `-p` list fail for that reason, not
because it was wrong.

**`rdp`** is deliberately scoped down from a full login check: no
maintained, verified-against-real-servers Go library exists for RDP's NLA
(every option is either abandoned or explicitly unfinished), so this
reports only the X.224 Connection Request/Confirm security-protocol
negotiation (MS-RDPBCGR 2.2.1.1/2.2.1.2) — which security layer the server
offers (plain RDP Standard Security, TLS, or CredSSP/NLA) and whether
legacy, unencrypted RDP Standard Security still works as a fallback — and
never attempts a login. No `-u`/`-p`/credential flags apply here at all.

---

## pipeline

Runs the HOST and/or WEB methodology ([methodology.md](methodology.md)).
Full guide in [pipeline.md](pipeline.md).

| Flag | Default | Meaning |
|---|---|---|
| `-c` | — | pipeline JSON config file (optional if `-host-file`/`-web-scope` are given) |
| `-host-file` | — | plain file of IPs/CIDRs, one per line — merged into `host` |
| `-web-scope` | — | Burp scope JSON export — concrete hosts (via `burphosts`) merged into `web`, each gated by this scope file |
| `-name` | config's `"name"` | engagement name for the manifest |
| `-kind` | auto | `host`, `web`, or `host,web` |
| `-o` | `options.outputDir` | output directory |
| `-dry-run` | off | print planned steps, send no traffic |
| `-no-web-handoff` | off | don't auto-run the WEB stage against web services the HOST stage discovers |
| `-no-easy-wins` | off | HOST stage: skip the conservative nuclei default-login/misconfig/exposure pass on non-web ports (on by default; it sends real probes). `-easy-wins` is a deprecated no-op. |
| `-no-active-subdomains` | off | WEB stage: skip the default active DNS brute force of subdomains (embedded SecLists top-20000 list; or `options.subdomainsWordlist`) |
| `-no-crawl` | off | WEB stage: skip the katana crawl (default on; skipped if katana isn't installed) |
| `-no-validate` | off | WEB stage: skip the soft-404-aware re-probe of merged endpoints (default on) |
| `-no-fuzz` | off | WEB stage: skip directory/file brute force entirely (default on) |
| `-no-manual-fuzz` | off | WEB stage: skip the interactive cherrypick fuzz flow, brute-force every target automatically instead (cherrypick is on by default, needs a terminal, and already falls back to this for `-dry-run`/CI/the `srt shell`) |
| `-fuzz-dirs-wordlist` / `-fuzz-files-wordlist` | SecLists `raft-medium-directories.txt` / `raft-medium-files.txt` | the manual-fuzz cherrypick prompts' two default wordlists |
| `-no-subfinder` | off | WEB stage: don't add subfinder's passive sources to subdomain discovery (on by default) |
| `-permutations` | off | WEB stage: alterx permutations of discovered names, resolved with dnsx (opt-in) |
| `-content-scan` | off | WEB stage: fetch every merged URL and scan its body for secrets instead of just classifying by extension (opt-in) |
| `-no-cdn-check` | off | HOST stage: don't flag IPs behind a known CDN/WAF/cloud provider via cdncheck (on by default — local dataset lookup, no traffic to the target) |
| `-no-tlsx` | off | WEB stage: don't widen the discovered-domain pool with cert SAN/CN entries via tlsx (on by default — one TLS handshake per target) |
| `-color` | `auto` | `auto` \| `always` \| `never` |

At least one of `-c`, `-host-file`, `-web-scope` is required; combining them
merges everything together.

```bash
srt pipeline -c engagement.json -kind host,web -o ./out

# no JSON config needed at all -- straight from a plain IP file and a Burp scope export
srt pipeline -host-file scope-ips.txt -web-scope target_scope.json -o ./out
```

---

## Saving results: results · runs · export · db

Scan results can persist to a local SQLite database instead of living only in
flat files. It is per project — `<cwd>/.srt/srt.db`, so `cd` between engagements
and each keeps its own — or wherever `SRT_DB` / `-db <path>` points. Nothing
is overwritten: every command or pipeline execution is a **run**, and old runs
stay queryable.

**What gets saved.** `pipeline` always saves (opt out with `-no-db`). The
`shell` saves everything by default (`save off` / `save on`). For a single
command from the plain CLI, put the global flag **before** the command name:

```bash
srt -save portscan -l scope.txt -p common,uncommon
srt -save fuzz -u https://target/FUZZ -w words.txt -ac
srt -save -db ~/acme.db probe -l hosts.txt
```

`portscan`, `fuzz`, `probe`, `pipeline` and the eight protocol clients (`ftp`,
`telnet`, `smb`, `ldap`, `ssh`, `mssql`, `vnc`, `rdp`) record structured results
(ports with banners; URLs with status/length/words/lines; probe title/server/
tech; a protocol finding's detail/severity/credential/hostname). Any other
command is saved by capturing its stdout line by line (kind = the command
name) — so use stdout, not `-o`, with `-save`. Results from older runs or other
tools load with `srt db import`.

### results

Query what's saved. Without `-run`, you get the **newest observation of every
result across all runs** (a merged "current picture"); `-run N` is exactly one
run, `-history` is every observation.

| Flag | Meaning |
|---|---|
| `-kind` | comma list: `port`, `url`, `probe`, `subdomain`, `domain`, `ip`, `resolve`, `gau`, `params`, `sensitive`, `robots`, … |
| `-host` | host substring |
| `-port` | exact port |
| `-status` | HTTP statuses/ranges, e.g. `200,301,400-499` |
| `-q` | substring in the key or data (banner, title, tech) |
| `-run` / `-history` | one run / all observations |
| `-limit` | max rows |
| `-json` / `-keys` / `-count` | JSON lines / bare keys (pipe-friendly) / just the number |
| `-color` | color the default table: `auto`\|`always`\|`never` (ignored with `-json`/`-keys`/`-count`); each `-kind` value gets its own color (consistent run to run) so a mixed-kind result set reads as visually grouped, `STATUS` is colored the same way `probe`'s own table is, and the extra-data `INFO` column is dimmed — except for a saved protocol-client finding, where `INFO` (its credential, hostname and detail) is colored by severity (gray/cyan/yellow/red for info/low/medium/high) instead |

```bash
srt results -kind port -host 10.0.0.5
srt results -kind url -status 200,403 -keys | httpx -title
srt results -kind probe -q wordpress
srt results -run 3 -count
```

### creds

A focused "what got in" view over the same database: exactly the findings a
protocol client (`ftp`/`telnet`/`smb`/`ldap`/`ssh`/`mssql`/`vnc`/`rdp`) marked
as an accepted login or session (`internal/protocols.Finding.Accepted`, stored
as `Data["ok"]` — a dedicated marker, not a guess from severity or wording, so
it can't be confused with "every attempt was rejected"), pulled out of
`results`' own everything-including-banners-and-rejections view. Shares
`results`' `-host`/`-run`/`-history`/`-limit` filters and `-json`/`-count`
output modes; `-kind` narrows within the eight protocol kinds instead of
accepting any kind.

| Flag | Meaning |
|---|---|
| `-kind` | comma list, narrowing within `ftp,telnet,smb,ldap,ssh,mssql,vnc,rdp` (default: all eight) |
| `-host` | host substring |
| `-run` / `-history` | one run / all observations |
| `-limit` | max rows |
| `-json` / `-keys` / `-count` | JSON lines / `"host:port"` one per line, pipe-friendly into another command's `-l` / just the number |
| `-color` | color the table: `auto`\|`always`\|`never` (ignored with `-json`/`-keys`/`-count`); `PROTO` gets a per-kind color the same way `results`' `KIND` column does, `CRED`/`DETAIL` are colored by severity |

The `CRED` column is `Credential.String()`'s own rendering — a username (and
domain, if any), never the password or hash itself (see its doc comment):
the point of `-save` was never to build a password list by reading the
database back, since whoever ran the original command already had the
secret. `HOSTNAME` falls back to the bare host for every protocol except
`smb`/`ldap`, the two that capture one for free (NTLM's challenge, RootDSE).

```bash
srt creds                                   # every accepted login/session, across all runs
srt creds -kind smb,ldap -host 10.0.0.0/24  # note: -host is a substring, not CIDR-aware
srt creds -keys | srt rdp                   # re-probe every host a credential already worked on (reads stdin)
```

### runs

`srt runs` lists saved runs (id, start time, record count, the command line);
`-n` limits how many, `-json` for machine output, `-color` (`auto`\|`always`\|`never`)
highlights an unfinished run's `(unfinished)` marker in yellow.

### export

Write results out as files. The default **tree** gives each host a directory:

```
out/
  summary.json            counts per kind, host count, which run
  hosts.txt               every host seen
  by-kind/<kind>.txt      all keys of a kind, across hosts
  10.0.0.5/ports.txt      "22  SSH-2.0-OpenSSH_8.9"
  a.example/probe.txt     "200  https://a.example  Home | PHP"
  a.example/urls.txt      "status  length  url"
  a.example/urls-200.txt  bare URLs per status (also urls-403.txt, …)
  dev.a.example/subdomain.txt
```

```bash
srt export -o ./acme-out                    # tree of everything
srt export -o ./acme-out -run 3 -kind url   # one run, one kind
srt export -format csv  -o results.csv      # or json; "-" for stdout
```

It takes the same filters as `results`.

### db

`srt db path` (where the database is), `srt db stats` (runs, records, size,
per-kind counts), `srt db import [-kind K] [-name N] <file>` (portscan/fuzz/
probe JSON is recognized automatically; plain lines need `-kind`), and
`srt db rm <run-id>`.

---

## shell

Interactive REPL: run commands by name with history and Tab-completion,
without retyping `srt` each time. Each line dispatches as a real subprocess
of `srt` itself (never in-process), so a bad flag just prints its own error
and returns you to the prompt — it never kills the shell session.

Dynamic help: while you type a flag (`fuzz -u`), a hint above the input box
shows that flag's type and description (taken from the command's own `-h`);
after a flag that takes a value it reminds you what the value is. `help
<command>` prints the full flag reference into the output area above the
prompt, so you can read it while you keep typing the command; PgUp/PgDn,
Ctrl+Up/Down or the mouse wheel scroll it. `help` alone lists every command.

```bash
srt shell
srt> fuzz -u https://target/FUZZ -w words.txt -ac
srt> help portscan
srt> exit
```

Needs an interactive terminal (stdin must be a TTY).

**`krb5`** and **`timesync`** are two more built-ins (`help krb5`/`help
timesync` for their own reference), for Kerberos work with `smb -k`/`ldap -k`:

- **`krb5 [<ccache-path>|clear]`** sets, shows, or clears this session's
  `$KRB5CCNAME` — inherited by every command launched from here (`childEnv`),
  so `smb -k`/`ldap -k` can authenticate from a ticket obtained elsewhere
  (`kinit`, Rubeus, impacket's `getTGT.py`) with no `-p`/`-H` at all
  ("pass-the-ticket"): `smb`'s own Kerberos client already checks
  `$KRB5CCNAME` itself before ever asking for a password; `ldap`'s reads it
  explicitly for the same effect. A path that doesn't exist yet is accepted,
  not rejected — the ticket may still be on its way.
- **`timesync <host>`** queries `host`'s clock over NTP (UDP/123 — the port
  Active Directory's own `w32time` service answers on by default, so a DC
  needs no extra setup) and reports the offset from local time, since
  Kerberos typically rejects anything past ~5 minutes of skew. Read-only: it
  never touches the system clock, only reports what it measured.

```bash
srt> krb5 /tmp/alice.ccache     # every command launched from here now sees it
srt> timesync dc01.corp.local   # check clock skew before trying -k
srt> ldap -l dc01.corp.local -d CORP.LOCAL -k   # authenticates from the ccache, no -p needed
```

---

## version

Print the srt version, embedded VCS revision, and Go/OS/arch.

```bash
srt version
```
