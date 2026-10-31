# srt command reference

Every command reads a list from `-l <file>` **or stdin**, and writes to stdout
**or `-o <file>`**. Status/progress goes to **stderr**, so stdout stays clean to
pipe into the next tool. Run `srt <command> -h` for the live flag list.

If a command is still working 5 seconds after it starts, it logs a
`still running (Ns elapsed)...` line to stderr every 5 seconds until it's
done — so a long run on a big input never looks hung. `fuzz` and `portscan`
show their own richer live counters instead of this generic line.

Jump to: [ipexpand](#ipexpand) · [ipports](#ipports) · [resolve](#resolve) ·
[portscan](#portscan) · [traceroute](#traceroute) · [domains](#domains) · [scopecheck](#scopecheck) ·
[subdomains](#subdomains) · [probe](#probe) · [burphosts](#burphosts) ·
[burpscope](#burpscope) · [gau](#gau) · [sensitive](#sensitive) ·
[params](#params) · [dirlist](#dirlist) · [robots](#robots) · [snyk](#snyk) ·
[relpaths](#relpaths) · [fuzz](#fuzz) · [pipeline](#pipeline) ·
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
| `-c` | `40` | concurrent lookups |
| `-timeout` | `5s` | per-lookup timeout |
| `-o` | stdout | output file |
| `-json` | off | JSON lines (one per query, including failures) |

```bash
srt resolve -l hosts.txt                    # host -> ip1,ip2
srt ipexpand -l scope.txt | srt resolve -reverse   # ip -> ptr-name
```

Failed lookups are reported to stderr and left out of plain-text output; with
`-json`, every query gets a line, successes and failures alike.

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
Accepts many base URLs via args, `-l`, or stdin. (Port of `legacy/robots-checker.py`.)

| Flag | Default | Meaning |
|---|---|---|
| `-l` | — | file of base URLs (args/stdin also work) |
| `-color` | `auto` | `auto` \| `always` \| `never` |
| `-timeout` | `15s` | per-request timeout |
| `-insecure` | `true` | skip TLS verification |
| `-c` | `20` | concurrent probes per host |

```bash
srt robots https://target
cat live_hosts.txt | srt robots -color never
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
| `-scope` | — | Burp scope JSON: gate requests + seed targets when no `-u`/`-tl` |

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
| `-hc` | `0` | max concurrent requests **per host** (0 = unlimited) |
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
soft-404 size under `/admin` never hides a real finding under `/api`.

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

With `-hl`, each hit is followed by indented `↳` snippets showing the matched
text in context (handy for spotting API keys, secrets, version strings, stack
traces in discovered files). `-resume <file>` records every completed request
and discovered directory, so re-running the same command continues where it
left off instead of repeating work.

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

`portscan`, `fuzz`, `probe` and `pipeline` record structured results (ports with
banners; URLs with status/length/words/lines; probe title/server/tech). Any
other command is saved by capturing its stdout line by line (kind = the command
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

```bash
srt results -kind port -host 10.0.0.5
srt results -kind url -status 200,403 -keys | httpx -title
srt results -kind probe -q wordpress
srt results -run 3 -count
```

### runs

`srt runs` lists saved runs (id, start time, record count, the command line);
`-n` limits how many, `-json` for machine output.

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

Dynamic help: while you type a flag (`fuzz -u`), a hint under the input box
shows that flag's type and description (taken from the command's own `-h`);
after a flag that takes a value it reminds you what the value is. `help
<command>` opens the full flag reference in a scrollable pane on the right
while you keep typing on the left — PgUp/PgDn, Ctrl+Up/Down or the mouse wheel
scroll it, Esc closes it. `help` alone lists every command in the same pane.

```bash
srt shell
srt> fuzz -u https://target/FUZZ -w words.txt -ac
srt> help portscan
srt> exit
```

Needs an interactive terminal (stdin must be a TTY).

---

## version

Print the srt version, embedded VCS revision, and Go/OS/arch.

```bash
srt version
```
