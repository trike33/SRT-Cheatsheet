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

## Ideas / backlog

### Methodology gaps (see [methodology.md](methodology.md))

Native implementations, not external-tool integrations — `srt`'s policy is
to reimplement what naabu/httpx/subfinder/katana/nuclei/dalfox would give
us rather than shell out to them. The one exception is **vulnx**, via the
`runExternal` helper already in `pipeline_external.go` (looks the binary up
on `PATH`, skips cleanly if it's missing) — **not wired up yet: its exact
CLI interface needs confirming first** (a web search during development
didn't turn up a tool by that name with a CVE-lookup CLI — the closest
public match, `anouarbensaad/vulnx`, is a CMS auto-exploitation tool, which
doesn't sound like what "check CVEs with vulnx" meant; this needs a
straight answer before wiring anything in, since the wrong assumption here
means either a broken integration or — worse — something that auto-exploits
instead of just checking a version against known CVEs).

- **HOST**: excluded-but-tracked hosts (reverse DNS + route trace, never
  actively probed) — the `pipeline` schema has no way to mark a `host` entry
  excluded today, and there's no traceroute helper yet either; vulnx
  integration for version→CVE lookups (blocked on the question above); a
  native "easy wins" pass (default creds/common misconfigs); BeanShell
  detection (no fixed port to match on, needs banner-based detection).
- **WEB**: a native subdomain enumerator (active + passive); a local
  "recon on root" prober — tech-detect/title/status/content-length/
  follow-redirects, an httpx-lite; Google dorking; context-aware wordlist
  generation for `fuzz` (candidates derived from the detected tech
  stack/app context, not just static wordlists); a re-validation step for
  URLs pulled from `gau`/dorking; parameter fuzzing/guessing beyond
  `params`' URL-based classification, plus reading parameters from a
  webset/API spec when one exists; content-based sensitive-info
  classification (creds/keys found inside a file, not just by extension).
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
