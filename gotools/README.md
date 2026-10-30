# srt — bug-bounty recon helpers (Go)

A single, dependency-free Go binary that ports the Python glue scripts in
[`legacy/`](../legacy/) into fast, pipe-friendly subcommands, and is growing
into a full HOST/WEB assessment automation — see
[`docs/methodology.md`](docs/methodology.md) for the target design and
[`docs/pipeline.md`](docs/pipeline.md) for the orchestrator driving it.

Some of the commands below predate that and are still glue — they *prepare
input for* and *post-process output from* `katana`/`nuclei`/`dalfox`/`ffuf`,
for chaining by hand per [`docs/playbook.md`](docs/playbook.md). But
`naabu`, `subfinder`, and `httpx` are no longer part of that list: `portscan`,
`subdomains`, and `probe` replace them natively. `methodology.md`'s policy is
to keep closing that gap rather than add more external-tool chaining — vulnx
is the one sanctioned exception (CVE lookups), already wired into `pipeline`.

## Why

The originals hardcoded filenames, mixed status output into stdout, and were slow
on big lists. `srt` fixes that:

- **One static binary.** `go build` with the standard library only — scp it to a
  VPS and run it. No `pip install`, no venv, no runtime deps.
- **Pipe-first.** Every command reads from `-l <file>` **or stdin**, and writes to
  stdout **or `-o <file>`**. Status/progress goes to **stderr**, so stdout stays
  clean for the next tool in the pipe.
- **Concurrent** where it matters (`scopecheck` DNS, `robots` probes).
- **Faithful logic.** Parsing, regexes, param/extension lists and Snyk range
  checks match the Python, with a few clearly-marked bug-bounty tweaks.

## Install / Build

Fastest path — installs the latest GitHub Release binary, no Go toolchain
needed (Linux/macOS):

```bash
curl -fsSL https://raw.githubusercontent.com/trike33/SRT-Cheatsheet/main/install.sh | sudo bash
```

Update the same way later: swap `install.sh` for `update.sh` in that command.
Windows: grab `srt-windows-amd64.exe` from
[Releases](https://github.com/trike33/SRT-Cheatsheet/releases/latest) directly.

Or build from source:

```bash
cd gotools
make build        # produces ./srt  (uses the local Go toolchain, no download)
# or:
GOTOOLCHAIN=local go build -o srt ./cmd/srt
```

Requires Go 1.24+. Install system-wide with `sudo make install` (-> `/usr/local/bin/srt`).

### CI

[`.github/workflows/build.yml`](../.github/workflows/build.yml) vets, tests,
and cross-compiles for linux/darwin/windows (amd64 + arm64) on every push;
pushing a `vX.Y.Z` tag publishes those binaries as a GitHub Release, which
`install.sh`/`update.sh` fetch from.

## Docs

- [`docs/methodology.md`](docs/methodology.md) — the HOST/WEB assessment
  methodology this tool is built to automate, and what's still backlog
- [`docs/pipeline.md`](docs/pipeline.md) — `srt pipeline`, the JSON-driven
  orchestrator that runs an assessment end to end
- [`docs/commands.md`](docs/commands.md) — every command, every flag, with examples
- [`docs/fuzz.md`](docs/fuzz.md) — the scope-aware fuzzer, in depth
- [`docs/playbook.md`](docs/playbook.md) — manual engagement workflow chained
  with external tools, for the methodology gaps `pipeline` doesn't cover yet
- [`docs/ROADMAP.md`](docs/ROADMAP.md) — changelog + backlog

## Commands

Run `srt <command> -h` for flags. Each maps to a script in this repo:

| Command | Replaces | Does |
|---|---|---|
| `ipexpand` | `legacy/HOST/ipparser.py` | Expand CIDRs/IPs -> unique sorted IP list |
| `ipports` | `legacy/HOST/format-ips.py` | Append ports (default 8080,8443) as `host:port` |
| `resolve` | **new** | Forward (A/AAAA) or reverse (PTR) DNS lookup, concurrent |
| `portscan` | **new** | Native concurrent TCP connect port scanner (replaces naabu) |
| `domains` | `legacy/HOST/domain-extracter.py` | Pull unique domains out of httpx output / any text |
| `scopecheck` | `legacy/HOST/domain_enum.py` | Keep hosts whose resolved IP is in a scope file (concurrent DNS) |
| `subdomains` | **new** | Find subdomains: passive (crt.sh) + optional active DNS brute force (replaces subfinder) |
| `probe` | **new** | Native httpx-lite: title/status/length/server + basic tech-detect |
| `burphosts` | `legacy/WEB/domains-to-httpx.py` | Burp scope JSON -> `host/dir` list for httpx/katana |
| `burpscope` | `legacy/WEB/domains-parser.py` | Burp scope JSON -> colored include/exclude paths |
| `gau` | `legacy/WEB/gau_recon.py` | Collect archived URLs from the Wayback CDX API |
| `sensitive` | `legacy/WEB/gau_recon.py` | Filter a URL list to sensitive file extensions |
| `params` | `legacy/WEB/gau_recon.py` | Group URLs by likely vuln class (sqli/xss/ssrf/…) |
| `dirlist` | `legacy/dir_listing.py` | Recursively harvest files from open directory listings |
| `robots` | `legacy/robots-checker.py` | Fetch robots.txt and probe each Allow/Disallow path |
| `snyk` | `legacy/synk_parser.py` | Test a version against a Snyk package's advisory ranges |
| `relpaths` | `legacy/relative_paths.py` | List files under a dir as relative paths (ffuf wordlist) |
| `fuzz` | **new** | Scope-aware concurrent directory/file bruteforcer with precise traffic control |
| `version` | **new** | Print version + build info |

## Workflow examples

These mirror `legacy/HOST/AUTOMATED.md` and `legacy/WEB/README.md`, but with pipes.

### HOST recon

```bash
# scope -> unique IPs -> recon-on-root (title/tech-detect/status/length)
srt ipexpand -l scope | tee scopeips | srt probe -o probe_out

# extract main domains from that, keep only in-scope ones, resolve concurrently
srt domains -l probe_out | srt scopecheck -scope scopeips -c 60 > domains

# subdomains (passive + active), then keep in-scope ones, then probe
srt subdomains -l domains -w subdomain-wordlist.txt | srt scopecheck -scope scopeips > subdomains
srt probe -l subdomains -o probe_out_subdomains

# discover open ports everywhere (replaces a blind httpx probe of 8080/8443)
srt ipexpand -l scope | srt portscan -p common,uncommon -o scan_out
```

### WEB recon (Burp scope export)

```bash
# host list for httpx / katana
srt burphosts -l target_assets.json | httpx -title -tech-detect -sc -cl -fr -o httpx_out
srt burphosts -l target_assets.json | katana -jc -o katana_out

# human-readable scope (green = in, red = out)
srt burpscope -l target_assets.json
```

### URL mining & triage

```bash
# collect archived URLs (needs outbound internet to web.archive.org)
srt gau -d example.com -sub -o all_urls.txt

# triage an existing URL list without re-fetching
srt sensitive -l all_urls.txt                 # backups, .env, .sql, keys, ...
srt params    -l all_urls.txt                 # grouped by vuln class
srt params    -l all_urls.txt -class ssrf | httpx -silent   # feed one class onward
```

### Directory listings, robots, Snyk

```bash
# recurse open directory indexes, drop image/css noise
echo "https://target/uploads/" | srt dirlist -o loot.txt

# probe every robots.txt Allow/Disallow path (mass mode: feed many base URLs)
srt robots https://target
cat live_hosts.txt | srt robots -color never

# is Moodle 3.7 affected? (needs outbound internet to security.snyk.io)
srt snyk -url "https://security.snyk.io/package/composer/moodle%2Fmoodle" -version 3.7
```

## `fuzz` — scope-aware bruteforcer

A concurrent directory/file bruteforcer built for **precise control over the
traffic you send**, with a hard rule: it never requests anything outside your
Burp scope.

### Precision controls

- **Scope gating** (`-scope scope.json`): the `host` and `file` fields of a Burp
  scope export are regexes, and the fuzzer compiles and evaluates them exactly as
  Burp does — a request is sent only if it matches an **include** rule and no
  **exclude** rule (protocol-aware: an `https`-only exclude won't block `http`).
  Out-of-scope candidates are counted and dropped *before* a packet goes out.
- **Multi-host fair scheduling**: give several targets (repeat `-u`, use `-tl`,
  or let `-scope` seed them) and srt bruteforces them **interleaved** — all hosts
  progress at once, not one drained first — with **per-host** rate (`-rate`) and
  concurrency (`-hc`) caps so no single target is flooded, plus a `-rate-global`
  ceiling for your own uplink.
- **Rate limiting** (`-rate N`): per-host requests/second; `-rate-global` caps the
  combined rate across all hosts.
- **Pacing** (`-delay`, `-jitter`): fixed + random delay before each request.
- **Concurrency** (`-c` total, `-hc` per host), **timeout**, **retries**.
- **Safety/evasion**: `-random-agent` rotates browser UAs, `-maxtime` hard-stops
  the whole run, `-maxerrors` abandons a dead/unreachable target.
- **Exact request shaping**: `-X` method, repeatable `-H "Name: Value"`, `-d`
  body, `-ua`, and `-proxy http://127.0.0.1:8080` to send everything through
  Burp. `FUZZ` can appear in the URL, any header, or the body.
- **Matchers / filters**: `-mc -fc` (status), `-ms -fs` (size), `-mw -fw`
  (words), `-ml -fl` (lines), `-mr -fr` (body regex). Each accepts lists and
  ranges, e.g. `-mc 200-299,403`.
- **Auto-calibration** (`-ac`): probes a few random paths first, fingerprints the
  soft-404 response, and auto-filters anything that matches — **per directory**,
  so recursion recalibrates and a soft-404 in `/admin` can't hide a finding in `/api`.
- **Body highlighting** (`-hl <regex>`): prints context snippets of matching
  response bodies (keys, secrets, versions); also added to `-json`.
- **Auto-throttle** (`-auto-throttle`): per-host backoff on 429/503, so a slow
  target throttles itself and the others keep going.
- **Resume** (`-resume <file>`): skip completed work and re-seed discovered
  directories after an interruption.
- **Recursion** (`-recursion`, `-depth N`): descends into discovered directories
  (detected via redirect-to-slash), still gated by scope.

### Examples

```bash
# Point it at the scope file and go: it seeds https://<include-host>/FUZZ for
# every concrete in-scope host, and refuses anything out of scope.
srt fuzz -scope loandepot.json -w raft-medium-directories.txt -ac -recursion

# Classic single target, with extensions, through Burp, rate-limited:
srt fuzz -u https://apply.myloandepot.com/FUZZ \
  -w directory-list-2.3-medium.txt -e .php -e .bak \
  -scope loandepot.json -proxy http://127.0.0.1:8080 \
  -rate 20 -c 40 -ac -recursion -depth 2

# Only 200s and 403s, hide the 1337-byte boilerplate page, pipe hits onward:
srt fuzz -u https://host/FUZZ -w words.txt -mc 200,403 -fs 1337 -silent | httpx -silent

# FUZZ a header value (e.g. subdomain/vhost brute):
srt fuzz -u https://target/ -H "Host: FUZZ.target" -w subs.txt -mc all -fs 0

# Many hosts at once, interleaved, each capped at 10 req/s (never floods one):
srt fuzz -u https://web1.com/FUZZ -u https://web2.com/FUZZ -u https://web3.com/FUZZ \
  -w big.txt -rate 10 -rate-global 200 -ac
```

`-silent` prints only matched URLs (clean for pipes); `-json` emits JSON lines;
`-o file` saves hits. Progress and the final summary go to stderr.

## Notes

- **Network egress:** `gau` and `snyk` call out to `web.archive.org` and
  `security.snyk.io`. In a locked-down environment those hosts may be blocked;
  the commands report the error per-target and keep going. On a normal VPS they
  just work.
- **TLS:** `dirlist`, `robots`, `gau` and `snyk` default to `-insecure` (skip
  cert verification) because target certificates are routinely broken — same as
  the Python `verify=False`.
- **Color:** `robots` and `burpscope` auto-detect a TTY; use `-color never` when
  redirecting, or `-color always` to force.
- **Proxies:** all HTTP commands honor `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY`.
