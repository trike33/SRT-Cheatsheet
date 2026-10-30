# srt — bug-bounty recon helpers (Go)

A single, dependency-free Go binary that ports the Python glue scripts in this
repo into fast, pipe-friendly subcommands. It does **not** reimplement `httpx`,
`katana`, `nuclei`, `naabu`, `subfinder` or `ffuf` — it replaces the hand-rolled
Python that *prepares input for* and *post-processes output from* those tools, so
everything chains together cleanly on an engagement.

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

## Build

```bash
cd gotools
make build        # produces ./srt  (uses the local Go toolchain, no download)
# or:
GOTOOLCHAIN=local go build -o srt ./cmd/srt
```

Requires Go 1.24+. Install system-wide with `sudo make install` (-> `/usr/local/bin/srt`).

## Commands

Run `srt <command> -h` for flags. Each maps to a script in this repo:

| Command | Replaces | Does |
|---|---|---|
| `ipexpand` | `HOST/ipparser.py` | Expand CIDRs/IPs -> unique sorted IP list |
| `ipports` | `HOST/format-ips.py` | Append ports (default 8080,8443) as `host:port` |
| `domains` | `HOST/domain-extracter.py` | Pull unique domains out of httpx output / any text |
| `scopecheck` | `HOST/domain_enum.py` | Keep hosts whose resolved IP is in a scope file (concurrent DNS) |
| `burphosts` | `WEB/domains-to-httpx.py` | Burp scope JSON -> `host/dir` list for httpx/katana |
| `burpscope` | `WEB/domains-parser.py` | Burp scope JSON -> colored include/exclude paths |
| `gau` | `WEB/gau_recon.py` | Collect archived URLs from the Wayback CDX API |
| `sensitive` | `WEB/gau_recon.py` | Filter a URL list to sensitive file extensions |
| `params` | `WEB/gau_recon.py` | Group URLs by likely vuln class (sqli/xss/ssrf/…) |
| `dirlist` | `dir_listing.py` | Recursively harvest files from open directory listings |
| `robots` | `robots-checker.py` | Fetch robots.txt and probe each Allow/Disallow path |
| `snyk` | `synk_parser.py` | Test a version against a Snyk package's advisory ranges |
| `relpaths` | `relative_paths.py` | List files under a dir as relative paths (ffuf wordlist) |

## Workflow examples

These mirror `HOST/AUTOMATED.md` and `WEB/README.md`, but with pipes.

### HOST recon

```bash
# scope -> unique IPs -> httpx on 80/443
srt ipexpand -l scope | tee scopeips | httpx -title -tech-detect -sc -cl -fr -o httpx_out

# extract main domains from httpx output, keep only in-scope ones, resolve concurrently
srt domains -l httpx_out | srt scopecheck -scope scopeips -c 60 > domains

# subfinder, then keep in-scope subs, then httpx
subfinder -dL domains -silent | srt scopecheck -scope scopeips > subdomains
httpx -l subdomains -title -tech-detect -sc -cl -fr -o httpx_out_subdomains

# probe 8080/8443 everywhere
srt ipports -l scopeips | httpx -title -sc -cl -fr -o httpx_out_80808443
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
