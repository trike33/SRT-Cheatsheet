# pipeline

Run the HOST and/or WEB methodology ([methodology.md](methodology.md))
instead of hand-chaining commands per [playbook.md](playbook.md).
`pipeline` orchestrates `srt`'s own subcommands end to end and writes
everything — including a `manifest.json` summary — to one output directory.
Targets come from a JSON config file (`-c`), a plain IP/CIDR list
(`-host-file`), a Burp scope export (`-web-scope`), or any combination —
see [No JSON config needed](#no-json-config-needed) if you only have a
plain host list and/or a Burp scope file.

It's still a subset of the full methodology — a few steps (active crawling,
Google dorking, context-aware wordlist generation, parameter
fuzzing/guessing, DNS brute force for HOST, ...) aren't implemented yet.
The "easy wins" pass (a direct, rate-limited `nuclei` call, on by default) and content-based
secret scanning (`-content-scan`) are both wired in. See [The methodology
this is meant to drive](#the-methodology-this-is-meant-to-drive) below.

## Quick start

```bash
srt pipeline -c engagement.json -kind host,web -o ./out
```

| Flag | Default | Meaning |
|---|---|---|
| `-c` | — | pipeline JSON config file (optional if `-host-file`/`-web-scope` are given) |
| `-host-file` | — | plain file of IPs/CIDRs, one per line — merged into the config's `host` list |
| `-web-scope` | — | Burp scope JSON export — concrete web hosts (via `burphosts`) merged into `web`, each gated by this file (also becomes the default `options.scope`) |
| `-name` | config's `"name"` | engagement name for the manifest |
| `-kind` | auto | `host`, `web`, or `host,web` — which section(s) of the config to run. Auto runs whichever of `host`/`web` the config actually has. |
| `-o` | `options.outputDir`, else `srt-pipeline-out` | output directory |
| `-dry-run` | off | print the planned targets/steps and exit — sends no traffic |
| `-no-web-handoff` | off | don't auto-run the WEB stage against web services the HOST stage discovers |
| `-no-easy-wins` | off | HOST stage: don't run the conservative nuclei default-login/misconfig/exposure pass on non-web open ports (on by default; same as `options.easyWins:false`). `-easy-wins` is accepted as a deprecated no-op. |
| `-no-active-subdomains` | off | WEB stage: skip the active DNS brute force of subdomains (on by default, embedded SecLists top-20000 list; same as `options.subdomainsActive:false`) |
| `-no-crawl` | off | WEB stage: skip the katana crawl (on by default; skipped if katana isn't installed) |
| `-no-validate` | off | WEB stage: skip the soft-404-aware re-probe of the merged endpoints (on by default) |
| `-no-fuzz` | off | WEB stage: skip directory/file brute force (on by default; embedded SecLists common.txt unless a wordlist is set) |
| `-no-subfinder` | off | WEB stage: don't add subfinder's passive sources to subdomain discovery (same as `options.subfinder:false`) |
| `-permutations` | off | WEB stage: alterx permutations of the discovered names, resolved with dnsx (same as `options.permutations`) |
| `-content-scan` | off | WEB stage: fetch every merged URL and scan its body for secrets instead of just classifying by extension (same as `options.contentScan`) |
| `-no-cdn-check` | off | HOST stage: don't flag IPs behind a known CDN/WAF/cloud provider via cdncheck (same as `options.cdnCheck:false`) |
| `-no-tlsx` | off | WEB stage: don't widen the discovered-domain pool with each target's cert SAN/CN entries via tlsx (same as `options.tlsx:false`) |
| `-param-discover` | off | WEB stage: guess hidden GET parameters on the validated endpoints (batch+bisect against a baseline) (same as `options.paramDiscover`) |
| `-param-discover-max` | `20` | with `-param-discover`: probe at most this many endpoints, first ones first (same as `options.paramDiscoverMax`) |
| `-param-discover-top` | `500` | with `-param-discover`: try at most this many candidate names per endpoint (same as `options.paramDiscoverTop`) |
| `-active-on-subdomains` | off | WEB stage: also run robots/fuzz/katana against probe-confirmed-live discovered subdomains, not just the explicit web targets (same as `options.activeOnSubdomains`) |
| `-active-on-subdomains-max` | `20` | with `-active-on-subdomains`: cap to this many live discovered subdomains, first-confirmed first (same as `options.activeOnSubdomainsMax`) |
| `-color` | `auto` | `auto` \| `always` \| `never` |

At least one of `-c`, `-host-file`, `-web-scope` must be given; all three
combine (so a JSON config can still add per-target overrides a plain host
file can't express, while `-host-file`/`-web-scope` quickly add more
targets to it).

## Skipping a step while it runs

If stdin is a terminal, press **`s`** at any time during a run to abandon
the step currently in progress and move straight to the next one — useful
when a slow step (a big `fuzz`, `nuclei` easy-wins pass, `katana` crawl,
...) isn't worth waiting on for this engagement. The step is recorded in
`manifest.json` as `"status": "skipped"`, same as a step skipped for
missing input, and — only for a keyboard skip, so it's distinguishable from
that — also saved to the results database as a `pipeline_skip` record
(unless `-no-db`), with the stage, step name, target and timestamp in its
`data` column: `srt results -kind pipeline_skip` lists every step a run
was told to abandon.

This abandons the step, it doesn't kill it: whatever request(s) it already
started keep running in the background until they finish on their own —
there's no per-step cancellation in `srt`, only process-wide. In practice
that means a little extra traffic you didn't wait for, and occasionally one
of that step's own log lines landing in the next step's warning count
instead of its own. `Ctrl+C` is unaffected and still halts the entire
pipeline immediately, same as always.

Piped/non-interactive runs (CI, `-dry-run`, stdin redirected from a file)
never touch stdin for this, so there's nothing to configure to disable it.

## No JSON config needed

If all you have is a plain IP/CIDR list and/or a Burp scope export — no
need to hand-write any JSON:

```bash
srt pipeline -host-file scope-ips.txt -web-scope target_scope.json -o ./out
```

This expands to the same thing a hand-written config would: every line of
`scope-ips.txt` becomes a `host` entry, and every concrete host `burphosts`
extracts from `target_scope.json` becomes a `web` entry with its `scope`
field set to that same file — so `fuzz`'s requests are still gated by your
exact Burp include/exclude rules, not just a flattened host list.

## Config file

```json
{
  "name": "example-engagement",
  "host": [
    "10.0.0.0/24",
    "192.168.1.5",
    { "target": "192.168.1.10", "ports": "22,80,443,8000-8100" }
  ],
  "web": [
    "example.com",
    "https://app.example.com/",
    "1.2.3.4",
    {
      "target": "https://admin.example.com",
      "wordlist": "custom.txt",
      "scope": "burp-scope.json",
      "extensions": [".php", ".bak"]
    }
  ],
  "options": {
    "outputDir": "./srt-pipeline-out",
    "concurrency": 40,
    "rate": 0,
    "rateGlobal": 0,
    "timeout": "10s",
    "insecure": true,
    "wordlist": "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "scope": "burp-scope.json",
    "ports": "common,uncommon",
    "proxy": "",
    "subdomainsWordlist": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "fuzz": true,
    "crawl": true,
    "crawlDepth": 3,
    "validate": true,
    "validateMax": 10000,
    "easyWins": true,
    "subfinder": true,
    "permutations": false,
    "contentScan": false,
    "cdnCheck": true,
    "tlsx": true,
    "paramDiscover": false,
    "paramDiscoverMax": 20,
    "paramDiscoverTop": 500
  }
}
```

- **`host`** and **`web`** are each a list of target entries. An entry is
  either a bare string (`"1.2.3.4"`, `"example.com"`) or an object with a
  required `target` field plus optional overrides — mix both freely in the
  same list.
- **`options`** sets pipeline-wide defaults. A per-target field of the same
  name always wins over `options`.
- A `web` entry can be a raw IP too (e.g. `"1.2.3.4"`) — it just won't have a
  domain to run `domains`/`subdomains`/`gau`/`sensitive`/`params` against, so
  those steps are skipped for it (see [Steps](#steps) below); `robots` and
  `fuzz` still run against it directly.
- Active DNS brute-force subdomain enumeration is **on by default**
  (alongside the passive sources, which always run), using the SecLists
  `subdomains-top1million-20000.txt` list embedded in the binary — nothing
  to install. `options.subdomainsWordlist` (options-only, no per-target
  override) swaps in your own label wordlist; `options.subdomainsActive:false`
  / `-no-active-subdomains` makes the run passive-only. It's ~20,000 DNS
  queries per domain, against the target's own nameservers via your
  resolver — turn it off for engagements that forbid active DNS probing.
- `options.easyWins` (also `-no-easy-wins` to disable; options-only, no
  per-target override) controls the HOST stage's nuclei default-login/
  misconfig/exposure pass over non-web open ports. **On by default.**
  Unlike most steps here it sends real probes at the service, not just
  passive recon, so its traffic is deliberately bounded (see
  [Steps](#steps) below for exactly what it runs) — set it to `false`
  (or pass `-no-easy-wins`) for an engagement whose rules forbid probing
  beyond recon.
- `options.crawl` (also `-no-crawl`; options-only) controls the katana
  crawl; `options.crawlDepth` sets its depth (default 3). **On by default**,
  it sends real requests to the target (bounded: ~50 req/s, 5 concurrent,
  3 minutes, same host).
- `options.validate` (also `-no-validate`; options-only) controls the
  soft-404-aware re-probe of the merged endpoint list. **On by default** —
  one request per endpoint (up to `options.validateMax`, default 10000) plus
  a few calibration requests per host/directory/extension class.
- `options.fuzz` (also `-no-fuzz` to disable; options-only) controls the
  directory/file brute force. **On by default**, with the embedded SecLists
  `common.txt` unless a `wordlist` is configured. It sends one request per
  word (times the auto-detected extensions) to each explicit web target;
  `options.rate`/`concurrency` bound it.
- `options.subfinder` (also `-no-subfinder`; options-only) adds
  [subfinder](https://github.com/projectdiscovery/subfinder)'s passive
  sources to subdomain discovery. **On by default** — third-party lookups
  only, no traffic to the target, same category as crt.sh.
- `options.permutations` (also `-permutations`; options-only) feeds the
  names found so far to [alterx](https://github.com/projectdiscovery/alterx)
  (capped at 2000 permutations per domain), resolves them with
  [dnsx](https://github.com/projectdiscovery/dnsx) and drops wildcard
  answers. **Off by default** — every permutation is a DNS query.
  When dnsx is installed it also performs the default brute force (with
  wildcard filtering) and the native brute force steps aside, so the same
  queries aren't sent twice; without dnsx the native one runs.
- `options.contentScan` (also `-content-scan`; options-only, no per-target
  override) switches the WEB stage's `sensitive` step from extension-based
  filtering to fetching every URL in the merged `gau` list and scanning its
  body for secrets (`sensitive -content`). **Off by default** — a large
  `gau` dump can be thousands of URLs, and this turns a string
  classification into a request per URL; `options.concurrency`, if set,
  caps how many run at once, the same way it already does for `fuzz`.
- `options.cdnCheck` (also `-no-cdn-check` to disable; options-only, no
  per-target override) flags which HOST-stage IPs sit behind a known
  CDN/WAF/cloud provider, via [cdncheck](https://github.com/
  projectdiscovery/cdncheck). **On by default** — unlike every other
  external-tool step here, it's a local dataset lookup with no traffic to
  the target at all, so there's nothing to opt into. Informational only:
  it doesn't change what gets scanned.
- `options.tlsx` (also `-no-tlsx` to disable; options-only, no per-target
  override) widens the WEB stage's discovered-domain pool with each
  explicit target's certificate SAN/CN entries, via [tlsx](https://github.
  com/projectdiscovery/tlsx) — another source alongside crt.sh/active
  brute force. **On by default** — one TLS handshake per target is the
  same order of traffic as `probe`'s own one request per target, not the
  "real exploitation-adjacent probes" category `easyWins`/`contentScan`
  are opt-in for.
- `options.paramDiscover` (also `-param-discover`; options-only, no
  per-target override) runs [`paramdiscover`](commands.md#paramdiscover)'s
  batch+bisect guessing pass against the validated endpoint list, finding
  hidden GET parameters neither a form (`05c_forms.txt`) nor `params`'
  URL-based classification can see. **Off by default** — a batch of extra
  requests per endpoint on top of everything else here, native to `srt`
  rather than another external tool. `options.paramDiscoverMax` (also
  `-param-discover-max`, default 20) caps how many validated endpoints get
  probed, first ones first (the same convention `validateMax` uses);
  `options.paramDiscoverTop` (also `-param-discover-top`, default 500)
  caps how many candidate names are tried per endpoint. Both exist so
  turning this on can't silently balloon into thousands of extra requests
  across a large endpoint list.

Install `vulnx`/`nuclei`/`cdncheck`/`tlsx`/`subfinder`/`dnsx`/`alterx`/`katana` with [pdtm](https://github.com/
projectdiscovery/pdtm), ProjectDiscovery's tool manager: `go install -v
github.com/projectdiscovery/pdtm/cmd/pdtm@latest`, then `pdtm -i
vulnx,nuclei,cdncheck,tlsx,subfinder,dnsx,alterx,katana` (installs to `$HOME/.pdtm/go/bin`, added to
`PATH` by default). `install.sh --with-pd` does this for you,
`update.sh --with-pd` runs `pdtm -u`, and `uninstall.sh --purge-pd` runs
`pdtm -r` (pdtm itself is kept). Each step **skips cleanly** with a `"skipped"` status
if its tool isn't on `PATH` — nothing here is required for the rest of the
pipeline to run.

### Per-target fields (object form)

| Field | Applies to | Meaning |
|---|---|---|
| `target` | host, web | the IP/CIDR/domain/URL (required) |
| `ports` | host | ports to scan (`portscan -p`), overrides `options.ports` (default `common,uncommon`) |
| `wordlist` | web | wordlist for `fuzz -w`, overrides `options.wordlist`. No wordlist resolved → the embedded `common.txt` is used. |
| `scope` | web | Burp scope JSON for `fuzz -scope`, overrides `options.scope` |
| `extensions` | web | extra extensions for `fuzz -e` (repeatable). When omitted, `fuzz -ext-auto` discovers them per host from tech-detect + live checks (disable with `options.autoExtensions: false`) |
| `snykUrl` + `snykVersion` | web | both set → also runs `snyk -url -version` for that target |
| `excluded` | host | `true` → excluded-but-tracked: never portscanned or handed off to WEB, only `resolve -reverse` + `traceroute` |

## Steps

### `host` stage → `<outputDir>/host/`

Targets are grouped by their effective `ports` value so each distinct port
spec only runs once:

1. `ipexpand` — expand CIDRs/IPs into a unique IP list.
2. `resolve -reverse` — reverse DNS lookup per IP, informational (the
   methodology's "DNS check" for included hosts).
3. `portscan` — scan that group's port spec (see [`portscan`'s
   docs](commands.md#portscan) for what `-p` accepts).
3b. `cdncheck` (github.com/projectdiscovery/cdncheck), **on by default** —
   `options.cdnCheck`/`-no-cdn-check` to disable: flags which of the
   group's IPs sit behind a known CDN/WAF/cloud provider. A local dataset
   lookup, no traffic to the target at all; purely informational, doesn't
   change what gets scanned. **Skipped** if `cdncheck` isn't installed.
4. Classify each open port:
   - **Web service** (a recognized HTTP(S) port) → added to the targets the
     `web` stage below runs against, automatically — this is the "hand off
     to WEB" step in methodology.md. Disable with `-no-web-handoff`.
   - **Uncommon/specialty port** (e.g. rsync, Java RMI) → recorded as a
     `flag-uncommon-service` step for manual follow-up.
   - **BeanShell** (any port, since it has no fixed one — its grabbed
     banner is matched instead) → recorded as a `flag-beanshell` step: an
     exposed one with no auth is an unauthenticated remote code execution
     risk, so this is flagged as its own distinct step rather than lumped
     into `flag-uncommon-service`.
   - Any open port with a grabbed banner, that isn't a web service → a
     `vulnx search` step (github.com/projectdiscovery/vulnx): `-p <product>`
     when the banner matches a recognized service (e.g. `-p openssh` for an
     `SSH-2.0-OpenSSH_...` banner — far more precise than free-texting the
     whole banner, version numbers and all), else a free-text search over
     the banner itself. **Skipped** if `vulnx` isn't installed, never fails
     the run. Runs alongside `flag-uncommon-service`/`flag-beanshell` above,
     not instead of them.
   - Every non-web open port, **unless disabled with `options.easyWins:false`/
     `-no-easy-wins`** (on by default) → a `nuclei` step (github.com/projectdiscovery/nuclei):
     `-tags default-login,exposure,misconfig -etags dos,fuzz,intrusive`,
     deliberately rate-limited (`-rl 10 -c 3 -bs 1 -timeout 5 -mt 3m`) so an
     automated, unattended pipeline step can't turn into an unbounded scan
     of one target. This is methodology.md's "easy wins" pass (default
     creds, common misconfigs) — unlike `vulnx`, it sends real probes at
     the service rather than querying a third-party database, which is
     exactly why its traffic is capped and it can be turned off. **Skipped** if `nuclei` isn't
     installed; also needs its templates fetched once (`nuclei -ut`) —
     `-duc` only disables nuclei's own update-check network call on every
     run, it doesn't bootstrap templates from nothing.

A `host` entry with `"excluded": true` is excluded-but-tracked instead:
steps 3-4 above don't run for it at all. In their place:

5. `ipexpand` (its own group, separate from the included hosts above).
6. `resolve -reverse` — same as included hosts, informational only.
7. `traceroute` — a native ICMP route trace (see
   [`traceroute`'s docs](commands.md#traceroute)). Needs a raw socket
   (`CAP_NET_RAW` or root); **skipped** cleanly without one, same shape as
   the `vulnx` step above.

An excluded host never reaches portscan, so it can never be classified as a
web service and never gets handed off to WEB — exactly what "never actively
probed" means.

### `web` stage → `<outputDir>/web/`

Runs over all explicit `web` entries, **plus** any web services the `host`
stage discovered and handed off (written to a `web/` subfolder of that
`host`-stage run rather than a separate top-level one):

1. `domains` — extract domains from any URL-shaped targets.
2. `scopecheck` (**host↔web cross-link**) — when this invocation's config
   has `host` targets too, the extracted domains are filtered through
   `scopecheck` against the **host stage's own IP scope** (its `host` list,
   included *and* excluded-but-tracked entries — an excluded host is still
   part of the engagement's IP range), the same way `playbook.md`'s manual
   flow keeps "only the ones that resolve back into scope." A domain that
   resolves outside that range (a third-party CDN, a stale DNS record) is
   dropped before it reaches `subdomains`/`gau`/`probe`. **Skipped** with no
   `host` targets in the config — a web-only config/run behaves exactly as
   before this existed, the two stages stay independent. A `scopecheck`
   failure (e.g. a malformed scope entry) fails open: nothing is dropped.
3. `subdomains` — per domain: passive (crt.sh) always, active DNS brute
   force too unless disabled (`-no-active-subdomains`; embedded top-20000
   wordlist unless `options.subdomainsWordlist` is set; skipped here in
   favour of dnsx when that's installed). **Skipped** if no
   domain was extracted (or none survived step 2). Discovered subdomains
   widen the domain list step 4 (`probe`) and step 5 (`gau`) run against —
   `robots`/`fuzz`/`katana` stay scoped to the explicit `web` targets by
   default, so this never silently multiplies active traffic, unless
   `options.activeOnSubdomains`/`-active-on-subdomains` is set (see step 4).
3b. `tlsx` (github.com/projectdiscovery/tlsx), **on by default** —
   `options.tlsx`/`-no-tlsx` to disable: per explicit `web` target, a
   certificate SAN/CN extraction widening the same discovered-names pool
   subdomains does -- `-san -cn -resp-only`. One TLS handshake per target,
   the same order of traffic as step 4 (`probe`)'s own one request per
   target. Runs regardless of whether step 1 extracted a domain (a bare-IP
   target still has a host:port to connect to). **Skipped** if `tlsx`
   isn't installed.
3b2. `subfinder` / `dnsx` / `alterx` (ProjectDiscovery), per domain, each
   skipped cleanly if not installed: **subfinder** (on by default,
   `-no-subfinder`) adds passive sources; **dnsx** (unless active brute
   force is disabled) brute-forces `<word>.<domain>` and a second `dnsx -wd` pass
   drops wildcard answers (the native brute force can't tell those from real
   hosts); with `options.permutations`/`-permutations` (off by default),
   **alterx** permutes the names found so far and dnsx resolves and
   wildcard-filters them. Results join the same discovered-names pool.
3c. `scopecheck` again — the newly discovered subdomains (step 3) and
   tlsx names (step 3b) together go through the same host-scope filter
   before being merged into the domain list, matching `playbook.md`'s
   "subdomains ... kept in scope, then probed." Same skip/fail-open
   behavior as step 2.
4. `probe` — recon-on-root (title/status/content-length/`Server`/tech-detect)
   for every domain and discovered subdomain. **Skipped** if none exist.
   With `options.activeOnSubdomains`/`-active-on-subdomains` (**off by
   default**, gap 8) its results also decide which discovered subdomains
   get a full active pass below: every one `probe` reached successfully
   (not just resolved) is added to steps 6a/6/7 (`katana`/`robots`/`fuzz`)
   as its own target, capped at `options.activeOnSubdomainsMax` (default
   20, first-confirmed-live first, since each one gets a full fuzz
   wordlist pass, not just one request). An `active-on-subdomains` step is
   recorded either way, saying how many of the discovered subdomains were
   added (and whether the cap applied).
5. `gau` — per domain **and** discovered subdomain, archived URLs from the
   Wayback Machine (merged into one deduped list). **Skipped** if there was
   nothing to query.
6a. `katana` (github.com/projectdiscovery/katana), **on by default**
   (`options.crawl:false`/`-no-crawl`; `options.crawlDepth`, default 3) —
   crawls each explicit target: links, JavaScript endpoints, robots/sitemap,
   and form extraction. Same host only, 3-minute cap, static assets
   filtered, `options.rate`/`concurrency`/`proxy` honoured, results
   filtered through the target's Burp scope when one is set. Its endpoints
   join the merged list; its forms are written to `05c_forms.txt`
   (`METHOD action  param,param`) — parameter names the site declares
   itself. **Skipped** if `katana` isn't installed.
6. `robots` — per target, fetch `robots.txt` and probe its paths, plus the
   same-host URLs of the sitemap(s) it declares (or `/sitemap.xml`), capped
   at 100 per target.
7. `fuzz` — directory/file brute force per target, **on by default**
   (`options.fuzz:false`/`-no-fuzz` to disable). Wordlist: the target's
   `wordlist`, else `options.wordlist`, else the SecLists `common.txt`
   (~4.7k names) embedded in the binary.
8. `merge-endpoints` — one deduplicated list (`06b_endpoints.txt`) of every
   `robots`/sitemap URL that answered 2xx/3xx/401/403, every `fuzz` hit,
   the crawler's endpoints and gau's archived URLs (active hits first).
8b. `validate` (**on by default**, `options.validate:false`/`-no-validate`)
   — re-probes every endpoint (native, no redirects followed) and keeps only
   real ones: dead URLs, errors and **soft-404s** are dropped. Each host's
   not-found behaviour is fingerprinted with random-path requests, per
   first directory and extension (`/api/*` and `*.php` are often handled
   differently from the root), and anything matching it — a catch-all 200
   whose size wobbles with the echoed path, a redirect to `/login`, a WAF's
   403 for everything — is rejected. A second pass rejects groups of 10+
   near-identical "valid" responses on one host that calibration missed.
   Writes `06c_valid_endpoints.txt` and `06c_rejected.txt` (reason + URL);
   checks at most `options.validateMax` (default 10000) endpoints, archived
   URLs last. Also available standalone as `srt validate`
   ([commands.md](commands.md#validate)).
9. `sensitive` + `params` — classify the **validated** endpoint list
   (the merged one with `-no-validate`). **Skipped** if it's empty. `sensitive` filters by extension by default;
   with `options.contentScan`/`-content-scan` (off by default) it instead
   fetches every URL and scans the body for secrets (`sensitive -content`),
   writing `03_sensitive.json` instead of `03_sensitive.txt`.
9b. `paramdiscover`, **only with `options.paramDiscover`/`-param-discover`**
   (off by default) — guesses hidden GET parameters on the validated
   endpoint list (native, batch+bisect against a baseline; see
   [commands.md](commands.md#paramdiscover)), capped to
   `options.paramDiscoverMax` endpoints (default 20, first ones first) and
   `options.paramDiscoverTop` candidate names each (default 500). Writes
   `06d_paramdiscover.json` (`url`, `found`, `reflected`, `requests` per
   endpoint). This is the "fuzzing/guessing" half of what `params`'
   URL-based classification leaves undone; step 6a's form extraction
   (`05c_forms.txt`) is the "what the site declares itself" half.
10. `snyk` — per target that sets both `snykUrl` and `snykVersion`.
   **Skipped** otherwise.

A skipped step is recorded in the manifest with a `detail` explaining why —
it never aborts the run.

## Output layout

```
<outputDir>/
  manifest.json
  host/
    00_raw_<n>.txt          # raw CIDR/IP entries for that ports group
    01_ipexpand_<n>.txt
    02_resolve_<n>.txt       # reverse DNS
    03_portscan_<n>.json
    03b_cdncheck_<n>.json    # one per ports group, only without -no-cdn-check
    vulnx_<host:port>.json   # one per flagged non-web port with a banner
    easywins_<host:port>.json  # one per non-web open port, unless options.easyWins is false
    web/                      # web services the host stage discovered,
      ...                     #   same layout as the top-level web/ below
  web/
    00_targets.txt
    01_domains.txt
    scopecheck_domains_in.txt     # host<->web cross-link; only when "host" targets exist
    scopecheck_domains_out.txt    #   (in = pre-filter, out = kept-in-scope)
    01b_subdomains_<domain>.txt  # one per domain
    01e_*_<domain>.txt           # subfinder / dnsx / alterx steps, when installed
    01d_tlsx_<target>.txt    # one per explicit web target, only without -no-tlsx
    scopecheck_subdomains_in.txt  # same cross-link, over subdomains + tlsx names
    scopecheck_subdomains_out.txt
    01c_probe_targets.txt
    01c_probe.json
    02_gau_<domain>.txt      # one per domain + discovered subdomain
    02_all_urls.txt          # merged, deduped
    05b_katana_<target>.jsonl   # katana's JSON lines (endpoints + forms)
    05c_forms.txt            # form actions and their field names
    06b_endpoints.txt        # merged gau + robots/sitemap + fuzz
    06c_valid_endpoints.txt  # the same, after validate (soft-404s dropped)
    06c_rejected.txt         # reason<TAB>URL for everything validate dropped
    03_sensitive.txt         # 03_sensitive.json instead, with options.contentScan
    04_params.txt
    05_robots_<target>.txt
    06_fuzz_<target>.json
    06d_paramdiscover_targets.txt  # only with options.paramDiscover
    06d_paramdiscover.json         # url/found/reflected/requests per endpoint
    07_snyk_<target>.txt
```

## manifest.json

Written once, at the end of the run, even if some steps failed or were
skipped:

```json
{
  "name": "example-engagement",
  "startedAt": "2026-10-30T12:00:00Z",
  "endedAt": "2026-10-30T12:00:06Z",
  "kinds": ["host", "web"],
  "steps": [
    {
      "kind": "web",
      "name": "fuzz",
      "target": "https://app.example.com",
      "status": "ok",
      "output": "out/web/06_fuzz_https___app.example.com.json",
      "duration": "4.2s"
    },
    {
      "kind": "web",
      "name": "fuzz",
      "target": "1.2.3.4",
      "status": "skipped",
      "detail": "no wordlist configured (set this target's \"wordlist\" or options.wordlist)"
    }
  ]
}
```

`status` is one of `"ok"`, `"error"`, or `"skipped"`.

## The methodology this is meant to drive

Today's `host`/`web` stages implement most of the flow described in
[methodology.md](methodology.md) — port scanning, reverse DNS, service
classification, the web hand-off, subdomain enumeration (passive and
active), recon-on-root, the host↔web IP-scope cross-link, vulnx CVE
lookups, the nuclei "easy wins" pass, cdncheck/tlsx enrichment, the katana
crawl, sitemap-aware `robots`, directory brute force, soft-404-aware
endpoint validation and content-based secret scanning are all there. A few
pieces aren't implemented yet: Google dorking, context-aware wordlist
generation, parameter fuzzing/guessing, and chaos/uncover. As each lands it
gets added to `internal/pipeline/host.go`/`internal/pipeline/web.go` in
the order `methodology.md` lays out. See [ROADMAP.md](ROADMAP.md) for what's
queued.

`srt` implements recon natively where it's worth it, and shells out to a
short, named list of ProjectDiscovery tools where it isn't: vulnx, nuclei,
cdncheck, tlsx, subfinder, dnsx, alterx and katana
(`gotools/internal/pipeline/external.go` ships the plumbing: `runExternal`
looks up a binary on `PATH`, runs it under a hard timeout, captures its
output, and reports a clean `"skipped"` step instead of failing the run when
it isn't installed). A future external-tool step follows the same shape.
