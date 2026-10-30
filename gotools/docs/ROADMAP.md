# srt roadmap & changelog

Running log of what's shipped and what's queued, newest first.

## Shipped

### Fuzzer precision & scale
- **Per-directory soft-404 calibration** (`-ac`) — recalibrates on every
  directory recursion descends into, so a soft-404 size under one directory
  never hides a finding under another.
- **Response-body highlighting** (`-hl <regex>`) — prints context snippets of
  matching bodies (secrets, keys, versions); added to `-json` as `highlights`.
- **Per-host live progress line** — stderr shows total counters plus each
  host's `matches/reqs(req/s)`.
- **Auto-throttle** (`-auto-throttle`) — per-host exponential backoff on
  429/503, decaying back on success; one slow host doesn't stall the rest.
- **Resumable runs** (`-resume <file>`) — logs completed targets and discovered
  directories; a re-run skips done work and re-seeds discovered dirs.
- **Multi-host fair scheduling** — one wordlist across many hosts (repeat `-u`,
  `-tl` file, or `-scope` seeding), interleaved round-robin, with per-host
  `-rate`/`-hc`, a global `-rate-global`, and a shared `-c` worker pool.
- **Streaming engine** — one feeder goroutine per host instead of one per
  candidate; recursion stays race-free (verified with `-race`).
- **Safety/evasion** — `-random-agent`, `-maxtime`, `-maxerrors`.
- **Scope gating** — compiles a Burp scope export's host/file regexes
  (protocol-aware include/exclude); only in-scope requests are sent, and the
  scope file can seed targets directly.

### Toolkit
- Ported every Python helper to Go subcommands (`ipexpand`, `ipports`,
  `domains`, `scopecheck`, `burphosts`, `burpscope`, `gau`, `sensitive`,
  `params`, `dirlist`, `robots`, `snyk`, `relpaths`), all pipe-friendly.
- `version` command; GitHub Actions build/release workflow; usage docs.
- **`pipeline` command** — JSON-driven orchestrator that runs the right
  subcommands against `host`/`web` targets automatically. See
  [pipeline.md](pipeline.md).
- **"Still running" heartbeat** — any command still working 5 seconds in
  logs `<command>: still running (Ns elapsed)...` to stderr every 5 seconds
  until it finishes, so a long run on a big input never looks hung. `fuzz`
  and `portscan` keep their own richer live counters instead.

### HOST methodology (see [methodology.md](methodology.md))
- **`resolve`** — forward (A/AAAA) and reverse (PTR) DNS lookup, concurrent.
  Covers the methodology's "DNS check" step.
- **`portscan`** — native concurrent TCP connect scanner: `common`/
  `uncommon`/`all`/explicit port specs (comma-combinable), a best-effort
  banner grab, JSON or plain output. `srt`'s replacement for naabu.
- **Service classification + WEB hand-off in `pipeline`** — the HOST stage
  now scans, classifies each open port as a web service or not, and
  automatically runs the WEB stage against the web ones (`-no-web-handoff`
  opts out). Non-web uncommon/specialty ports (rsync, Java RMI, and the rest
  of `portscan`'s `uncommon` list) get flagged in the manifest for manual
  follow-up.
- **vulnx integration** — `pipeline`'s HOST stage runs `vulnx search
  "<banner>"` (github.com/projectdiscovery/vulnx) for every non-web open
  port with a grabbed banner, via the `runExternal` helper in
  `pipeline_external.go` (skips cleanly if `vulnx` isn't installed). Works
  unauthenticated, just rate-limited without `vulnx auth` configured.

### WEB methodology (see [methodology.md](methodology.md))
- **`subdomains`** — passive enumeration via crt.sh certificate transparency
  logs (always runs) plus optional active DNS brute force with a label
  wordlist. `srt`'s replacement for subfinder.
- **`probe`** — native httpx-lite: title/status/content-length/`Server` +
  a best-effort tech-detect (WordPress, Drupal, Joomla, Laravel, Django,
  Express, PHP, ASP.NET, nginx, Apache, IIS, Cloudflare — a small,
  conservative signature set, not a wappalyzer-equivalent). Covers
  "recon on root."
- **Wired into `pipeline`'s WEB stage** — `subdomains` (passive always,
  active if `options.subdomainsWordlist` is set) and `probe` run right
  after `domains`, widening the domain list `gau` also runs against.
  `robots`/`fuzz` stay scoped to the explicit `web` targets, so discovering
  N subdomains doesn't silently multiply active traffic — that stays opt-in.

## Ideas / backlog

### Methodology gaps (see [methodology.md](methodology.md))

Native implementations, not external-tool integrations — `srt`'s policy is
to reimplement what naabu/httpx/subfinder/katana/nuclei/dalfox would give
us rather than shell out to them (vulnx is the one exception, now wired up
— see Shipped above).

- **HOST**: excluded-but-tracked hosts (reverse DNS + route trace, never
  actively probed) — the `pipeline` schema has no way to mark a `host` entry
  excluded today, and there's no traceroute helper yet either; a native
  "easy wins" pass (default creds/common misconfigs); BeanShell detection
  (no fixed port to match on, needs banner-based detection).
- **WEB**: Google dorking; context-aware wordlist generation for `fuzz`
  (candidates derived from the detected tech stack/app context — `probe`'s
  tech-detect output is the natural input for this now, not just static
  wordlists); a re-validation step for URLs pulled from `gau`/dorking;
  parameter fuzzing/guessing beyond `params`' URL-based classification,
  plus reading parameters from a webset/API spec when one exists;
  content-based sensitive-info classification (creds/keys found inside a
  file, not just by extension); optionally also running `robots`/`fuzz`
  against `pipeline`-discovered subdomains, opt-in given the traffic-volume
  implications (today only `gau`/`probe` auto-widen to them).
- **`pipeline` integration** — as each of the above lands, extend
  `pipeline_host.go`/`pipeline_web.go` to call it in the order
  `methodology.md` lays out.
- **Host↔web scope cross-link in `pipeline`** — `playbook.md` filters
  domains discovered on the web side through `scopecheck` against the host
  stage's IP scope; the pipeline's two stages are independent today.

### Fuzzer / pipeline

- **Recursion content-length auto-filter inheritance** — optionally seed a
  child directory's calibration from its parent to save probe requests.
- **Smarter directory detection** — treat a `200` on a trailing-slash request
  as a directory even without a redirect.
- **Per-host adaptive concurrency** — raise/lower `-hc` based on latency.
- **Resume compaction** — periodically rewrite the state file to dedupe.
- **Output formats** — ndjson streaming to a file, and a `-mc`-less "show all"
  summary table grouped by status.
- **Wordlist mutations** — case/extension permutations, `%ext%` style tokens.
- **Release automation** once workflow scope is available (tag → binaries).

Suggestions welcome — open an issue.
