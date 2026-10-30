# srt command reference

Every command reads a list from `-l <file>` **or stdin**, and writes to stdout
**or `-o <file>`**. Status/progress goes to **stderr**, so stdout stays clean to
pipe into the next tool. Run `srt <command> -h` for the live flag list.

Jump to: [ipexpand](#ipexpand) · [ipports](#ipports) · [domains](#domains) ·
[scopecheck](#scopecheck) · [burphosts](#burphosts) · [burpscope](#burpscope) ·
[gau](#gau) · [sensitive](#sensitive) · [params](#params) · [dirlist](#dirlist) ·
[robots](#robots) · [snyk](#snyk) · [relpaths](#relpaths) · [fuzz](#fuzz) ·
[version](#version)

---

## ipexpand

Expand a scope file of IPs and CIDRs into a unique, numerically sorted list of
individual IPs. (Port of `HOST/ipparser.py`.)

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
(Port of `HOST/format-ips.py`.)

| Flag | Default | Meaning |
|---|---|---|
| `-l` | stdin | input IP file |
| `-o` | stdout | output file |
| `-ports` | `8080,8443` | comma-separated ports |

```bash
srt ipexpand -l scope.txt | srt ipports -ports 8080,8443,9090 | httpx -silent
```

---

## domains

Extract unique hostnames from `httpx` output (or any text). IPs are ignored —
a trailing alphabetic TLD is required. (Port of `HOST/domain-extracter.py`.)

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
Concurrent DNS. (Port of `HOST/domain_enum.py`.)

| Flag | Default | Meaning |
|---|---|---|
| `-l` | stdin | hosts/subdomains file |
| `-scope` | — (required) | scope file of IPs/CIDRs |
| `-o` | stdout | output file |
| `-c` | `40` | concurrent DNS resolutions |
| `-timeout` | `5s` | per-host DNS timeout |

```bash
subfinder -dL domains -silent | srt scopecheck -scope scopeips -c 80 > subs
```

---

## burphosts

Parse a Burp Suite scope JSON export and emit `host[/dir]` entries (no scheme)
for `httpx`/`katana`. Wildcard hosts (`*.example.com`) are collapsed to the apex
so they resolve. (Port of `WEB/domains-to-httpx.py`.)

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
(Port of `WEB/domains-parser.py`.)

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
outbound internet to `web.archive.org`. (Port of `WEB/gau_recon.py`.)

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
(Port of `dir_listing.py`.)

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
Accepts many base URLs via args, `-l`, or stdin. (Port of `robots-checker.py`.)

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
(Port of `synk_parser.py`.)

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
(Port of `relative_paths.py`.)

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

Default `-mc`: `200-299,301,302,307,308,401,403,405,500`. Use `-mc all` to match
everything. `-ac` recalibrates for each directory it recurses into, so a
soft-404 size under `/admin` never hides a real finding under `/api`.

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

## version

Print the srt version, embedded VCS revision, and Go/OS/arch.

```bash
srt version
```
