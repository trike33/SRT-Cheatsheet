# srt roadmap & changelog

Running log of what's shipped and what's queued, newest first.

## Shipped

### `config.sh`: guided setup for the optional API keys
- **New repo-root script** alongside `install.sh`/`update.sh`/`uninstall.sh`
  — a guided wizard for the API keys `dork -search` and `pipeline`'s
  `options.uncover`/chaos source can use (`SRT_GOOGLE_API_KEY`/
  `SRT_GOOGLE_CSE_ID`, `SRT_CHAOS_API_KEY`, and uncover's `SHODAN_API_KEY`/
  `CENSYS_API_TOKEN`+`CENSYS_ORGANIZATION_ID`/`FOFA_EMAIL`+`FOFA_KEY`).
  Every one of these is already off by default and skips cleanly without a
  key (see gap 11 and gap 12 below); `config.sh` is only for turning them
  on, never required to use `srt` at all.
- For each credential: prints what it unlocks, a short signup/setup
  walkthrough with the real URLs, shows what's already configured
  (masked), and prompts to set it. Values are written to `~/.config/srt/env`
  (mode 600) and that file is hooked into `~/.bashrc`/`~/.zshrc`/
  `~/.profile` (whichever exist) so new shells pick them up automatically.
  `./config.sh --status` shows current state without prompting;
  `./config.sh --set NAME=VALUE` / `--unset NAME` / `--unset-all` work
  non-interactively for scripting. Refuses to run under `sudo` by a real
  user (would write into root's `$HOME` instead of theirs) but allows
  running as root directly (a container has no other user to redirect to).
- Prompts read from `/dev/tty` directly rather than stdin, the same
  `curl | bash`-safe pattern `install.sh`/`update.sh`/`uninstall.sh` rely
  on for their own confirmations. **A real finding while verifying, not
  assumed**: `[ -r /dev/tty ]` is not a reliable way to detect "no
  controlling terminal" — its permission-bit check can report true even
  when an actual `read` from `/dev/tty` would fail with `ENXIO` (confirmed
  live in this project's own dev sandbox, which has no controlling
  terminal at all); an actual open attempt (`: < /dev/tty`) is what
  reliably catches it, which is what the script uses instead, falling
  back to a clean non-interactive error rather than hanging or spamming
  `/dev/tty: No such device or address`.
- Verified live end to end, not just a syntax check: `--set`/`--status`/
  `--unset`/`--unset-all` round-tripped correctly against an isolated test
  `$HOME`; the interactive wizard was driven under a real pty (Python's
  `pty.fork`, not a canned input redirect, which doesn't reach `/dev/tty`
  the way a real terminal does) and correctly prompted, hid secret input
  (`read -s`), saved the answered credential, skipped the declined ones,
  and hooked the shell profile.

### chaos / uncover wired in (gap 11)
- **chaos**: subfinder already has a `chaos` passive subdomain source —
  verified against a real `subfinder` v2.17.0 binary (`subfinder -ls`
  lists `chaos *`, and its `pkg/runner/config.go` loads a plain
  `sourceName: [keys...]` YAML provider config). `options.chaosAPIKey`/
  `-chaos-key` (falls back to `$SRT_CHAOS_API_KEY`) writes a dedicated
  `chaos_provider_config.yaml` for the run's `subfinder -pc` calls
  (`internal/pipeline/chaos.go`) rather than touching the operator's own
  `~/.config/subfinder/provider-config.yaml` — meaning any *other* source
  keys in that file (securitytrails, etc.) don't apply to this
  invocation specifically; documented rather than attempting a merge,
  since subfinder's config format has no stable Go library here to parse
  against. No key: unchanged behavior, exactly as before this shipped.
- **uncover** (github.com/projectdiscovery/uncover), HOST stage, gap 11's
  "scope-building" half: `options.uncover`/`-uncover` (off by default)
  seeds additional host targets from a Shodan/Censys/etc. search
  (`options.uncoverQuery`/`-uncover-query`, e.g. `org:"Acme Corp"`) before
  `ipexpand`, so discovered hosts flow through the rest of the HOST stage
  exactly like an explicit target — even with `cfg.Host`/`cfg.Web`
  otherwise completely empty (a config that's just `options.uncover` +
  `options.uncoverQuery` is legitimate; `-kind host` must still be passed
  explicitly, since `pipeline`'s own auto-`-kind` detection keys off the
  config's `host`/`web` lists, not its options). `-f ip` (verified
  against the real CLI) gives bare IPs, the exact shape a "host" config
  entry already is.
  - **Per-engine keys need no srt-side key management at all**: verified
    against uncover v1.2.1's own `sources/provider.go` that it already
    reads standard per-engine env vars itself (`SHODAN_API_KEY`,
    `FOFA_EMAIL`+`FOFA_KEY`, `CENSYS_API_TOKEN`+
    `CENSYS_ORGANIZATION_ID`, ... — 18 engines, full list in
    `internal/pipeline/external.go`'s `uncoverEngineEnvVars`), so a key an
    operator already has set up for using `uncover` by hand just works
    here. srt checks those same env vars itself before invoking (rather
    than parsing uncover's own fatal-error text, which a real
    no-credentials run was confirmed to print: `could not run
    enumeration: ... requires keys but no keys were found`, exit 1) —
    **cleanly skipped**, naming the missing engine(s), when none of the
    requested engines has a key, or `options.uncoverQuery` is empty.
  - **`shodan-idb`** (Shodan's free InternetDB lookup, keyed by IP/CIDR
    rather than a free-text search) needs no key at all — confirmed
    against uncover's source (`sources/agent/shodanidb/shodan.go`:
    `https://internetdb.shodan.io/%s`, no auth) — but doesn't fit
    `options.uncoverQuery`'s "seed hosts from a search" shape, so it's
    not a default engine; still usable via `options.uncoverEngines`.
  - **A real sandbox-network finding, not assumed**: every host this
    feature's live queries would hit (`internetdb.shodan.io`,
    `chaos.projectdiscovery.io`, `dns.projectdiscovery.io`) is blocked in
    this project's own dev sandbox, same as most external hosts here —
    but invoking subfinder's `chaos` source specifically (with a dummy
    key, to see what happens) **hung** rather than failing fast the way
    every other subfinder source already shipped does through this
    sandbox's proxy (confirmed: the default subfinder call with no
    `-s chaos` completes in seconds, same command with `-s chaos` didn't
    finish in 20s+ and had to be killed). Not a defect in this feature —
    outside this sandbox, `chaos.projectdiscovery.io` is a normal public
    HTTPS API — but genuinely not independently live-verified beyond
    that, flagged here rather than presented as checked, per this
    project's "verify, don't just trust docs" norm. `runExternal`'s
    existing hard 5-minute wall-clock timeout (added after the earlier
    katana-hang finding) still bounds the worst case either way.
- Verified live end to end, not just unit tests: a bare `srt pipeline
  -kind host -uncover -uncover-query 'org:"test"'` with no API key
  configured produced exactly the expected clean-skip step and manifest
  entry; the same command with `SHODAN_API_KEY` set and a fake `uncover`
  binary on `PATH` correctly seeded a host, which then flowed all the way
  through real `ipexpand`/`resolve`/`portscan` (and on into the WEB
  stage's own web-handoff) with `cfg.Host` completely empty the whole
  time.
- See [pipeline.md's host stage, step
  0](pipeline.md#host-stage--outputdirhost) and
  [methodology.md](methodology.md)'s HOST "Scope" entry.

### `resolve -type`: CNAME/MX/NS/TXT record collection
- **`srt resolve` can now collect `cname`/`mx`/`ns`/`txt` records**
  alongside its existing forward (A/AAAA) and reverse (PTR, `-reverse`)
  lookups (`-type cname,mx,ns,txt`, comma list, any subset). Native --
  Go's `net.Resolver` already has `LookupCNAME`/`LookupMX`/`LookupNS`/
  `LookupTXT`, no new dependency. **`soa` is not supported**: `net` has no
  `LookupSOA` at all, and this project is native-by-policy (see
  methodology.md's External-tool policy), so pulling in a DNS library for
  one record type wasn't judged worth it. `-type` only applies to forward
  lookups; combined with `-reverse` it's a clear error rather than a silent
  no-op, since record types like MX/TXT describe a name, not a raw IP.
- Output: one extra line per type found (`example.com MX -> 10
  mail.example.com`), or an `extra` field in `-json` output keyed by
  uppercase type (`{"CNAME":[...],"MX":[...],...}`) alongside the existing
  fields -- purely additive, so existing `-json` consumers (and
  `pipeline`, which only ever calls `resolve -reverse` without `-type`)
  see no change. A type with no records for a query is simply missing
  from the output, not an error.
- **Found and worked around a real stdlib surprise, not assumed**:
  `net.Resolver.LookupCNAME` does **not** send a dedicated CNAME-type DNS
  query -- confirmed via `go doc net.Resolver.LookupCNAME` ("Callers...
  both [LookupHost/LookupIP] take care of resolving the canonical name as
  part of the lookup"). It performs an ordinary A/AAAA-style lookup and
  reads off whatever CNAME chain the server returned along the way,
  falling back to the queried name itself if no CNAME appeared. A test
  fake DNS server built for this (see below) initially answered CNAME
  queries on a dedicated `case 5:` branch only, which `LookupCNAME` never
  actually reaches -- the test caught this immediately (got the queried
  name back instead of the target), and the fake server's `A`-query
  handling now chases the CNAME chain itself, same as a real nameserver
  would, which is exactly the behavior this feature depends on in
  production.
- Verified with a real, from-scratch, test-only DNS server
  (`internal/recon/resolve/dnsfake_test.go`) speaking actual DNS wire
  format over UDP -- not a mock of `net.Resolver`'s Go-level API, a real
  parsed-and-built DNS message round trip through `net.Resolver` itself
  (via its `Dial` override) -- rather than trusting the stdlib's
  documented behavior on faith. `go test ./internal/recon/resolve/...`
  covers CNAME-chain resolution, MX preference+host formatting, multi-NS/
  multi-TXT records, "no records for this type" being silently omitted,
  `-type`+`-reverse` rejection, and an unknown `-type` value erroring
  clearly instead of being silently ignored.
- See [commands.md](commands.md#resolve).

### Google dorking (gap 12)
- **New native command `srt dork`**, and a WEB-stage pipeline step (`02b`,
  off by default: `options.dork`/`-dork`) — generates a curated set of
  advanced search-operator queries per explicit target's domain plus the
  engagement name, in 9 bounded categories (`-list-categories`): exposed
  office/document files, backup/config/database file leaks, admin/login
  panels, open directory listings, error messages/stack traces,
  confidential-marked documents (all domain-scoped), plus — when a `name`
  is given — third-party cloud storage buckets, paste-site leaks, and
  exposed secrets in public source hosting mentioning the org (name-scoped).
- **Deliberately does not scrape google.com's own result pages** — against
  Google's terms of service, rate-limited/CAPTCHA'd within a handful of
  requests, and (verified live) not even reachable from this project's own
  sandbox network policy, unlike `www.googleapis.com` which is. The **Google
  Custom Search JSON API** (`customsearch.googleapis.com`) is the one
  programmatic, ToS-compliant way to run these queries, gated behind
  `-search` plus an API key + Programmable Search Engine ID (`-api-key`/
  `-cx`, or `$SRT_GOOGLE_API_KEY`/`$SRT_GOOGLE_CSE_ID` — same "env var or
  flag, clean skip when absent" friction pattern as chaos/uncover below).
  **Without credentials it sends no traffic at all**: every query is still
  printed as a ready-to-paste `google.com/search?q=...` URL, which is
  useful standalone and is exactly what `pipeline`'s `dork` step does by
  default too.
- Verified live, not just against docs: `www.googleapis.com` is reachable
  from this sandbox while `www.google.com` itself is not (confirming the
  API-not-scraping design was the only viable approach here, not just the
  more cautious one); a real unauthenticated request against the Custom
  Search endpoint returned the exact documented error JSON shape
  (`{"error":{"code":400,"message":"API key not valid...","status":
  "INVALID_ARGUMENT"}}`), which the error-path parsing and its test are
  built against verbatim. **Not independently verified**: an authenticated
  success response — no API key/Search Engine ID was available in this
  environment to test one, so that parsing follows the API's long-stable
  documented `items[].{title,link,snippet}` schema rather than a
  live-checked example; flagged here per this project's "verify, don't
  just trust docs" norm rather than silently presenting it as checked.
- `pipeline` wiring: runs per explicit target's own domain only (not every
  discovered subdomain — a handful of categories per domain already adds
  up against the free tier's 100 queries/day), writes
  `02b_dork_<domain>.txt`. Without `-search` that file holds search URLs
  and is **not** merged into the endpoint list (they're google.com links,
  not target URLs); with `-search`, the real hit URLs it finds do join the
  merged list before `validate`, same as `gau`'s. Credentials resolve from
  `options.dorkAPIKey`/`dorkCX` (JSON config) or the same env vars the
  standalone command uses, so a config file committed to a repo never has
  to carry a secret key in plain text.
- **`-search` enforces the free tier's 100-queries/day cap itself, by
  default** — `-max-daily`/`options.dorkMaxDaily` (and `pipeline`'s
  `-dork-max-daily`) default to 100, not unlimited. Every query decrements
  a per-API-key budget persisted to `~/.srt/dork_quota.json`
  (`internal/recon/dork/quota.go`), shared across *every* `srt dork`/`srt
  pipeline -dork` invocation on the machine that day, not just within one
  process — a second `dork` run an hour later sees the same spent budget
  and refuses to send anything once it's gone, rather than each
  invocation getting its own fresh 100. Keyed by a SHA-256 fingerprint of
  the API key (never the raw key) so different keys get independent
  budgets, reset on UTC day rollover, and guarded by a lock file so
  concurrent runs can't race the counter into under-counting (verified
  with 30 concurrent goroutines never exceeding the cap). This is a local
  safety net, not authoritative — it can't stop a different machine, or
  this one with its state file deleted, from spending the same key past
  the real quota; the one actual guarantee is a hard quota override or no
  billing account at all, set in the Google Cloud Console itself, which
  commands.md says explicitly rather than implying this flag alone is
  enough.
- See [commands.md](commands.md#dork), [pipeline.md's step
  5b](pipeline.md#web-stage--outputdirweb), and
  [methodology.md](methodology.md)'s WEB "gather endpoints/files" passive
  entry.

### Context-aware wordlist words: tech stack, page title, engagement name (gap 7)
- **`fuzz -words-auto`** (new flag, off by default standalone) — adds a
  small curated set of extra candidate words per host, the same way
  `-ext-auto` adds extensions: a per-tech directory/file-name map
  (`WordPress` → `wp-admin`/`wp-content`/`wp-login`/`wp-json`/`xmlrpc`/...;
  similar small sets for Drupal, Joomla, Laravel, Django, Express, ASP.NET,
  IIS, PHP) plus the root page's `<title>`, tokenized (lowercase, 3+
  chars, generic English stopwords dropped). Resolved once per host origin
  and capped at 40 extra words total, tech words first. Reuses
  `-ext-auto`'s own `probe.One` root-page request when both flags are set
  (one request serves both, via a new per-origin `siteProbeCache`), rather
  than probing twice.
- **`srt pipeline`**: `options.contextWords`/`-no-context-words` (**on by
  default** — WEB stage `fuzz` calls gain `-words-auto`; costs nothing
  extra in the common case since step 6's `-ext-auto` is also on by
  default and the two share one probe). Adds a third word source
  `-words-auto` can't see on its own: the engagement's `name` from the
  config, tokenized (split on spaces/camelCase, short tokens and
  corporate-suffix noise like `inc`/`llc`/`corp` dropped) and written once
  to `00_name_words.txt`, merged into every target's fuzz wordlist via an
  extra `-w` (already repeatable) — a client's short name or product/
  codename is often also a path on their own site.
- **Still open** (see Ideas/backlog, gap 7's note): JS-declared identifiers
  (variable/function/route names parsed out of crawled JS) as a fourth word
  source — katana's existing crawl only extracts links/forms, not generic
  JS identifiers, and that parsing is a meaningfully larger piece of work
  than the curated-map approach used here.
- See [fuzz.md's Context-aware words
  section](fuzz.md#context-aware-words-words-auto) and
  [pipeline.md's step 7](pipeline.md#web-stage--outputdirweb) for the
  user-facing version.

### Active steps (`robots`/`fuzz`/`katana`) can reach probe-confirmed-live discovered subdomains (gap 8)
- **`options.activeOnSubdomains`/`-active-on-subdomains`** (off by default)
  — `robots`/`fuzz`/`katana` previously only ever ran against the explicit
  `web` targets; every domain `subdomains`/`tlsx`/`dnsx`/`alterx`
  discovered only ever reached `gau` (passive) and one `probe` request
  (recon-on-root), so "recon on every subdomain" never got to endpoint
  discovery (gau alone finds nothing for a subdomain with no Wayback
  history). With this on, step 4 (`probe`)'s own results decide which
  discovered subdomains get the same full active pass as an explicit
  target: every one `probe` actually reached (not just resolved — a
  wildcard-DNS or dead subdomain never gets a wordlist thrown at it for
  nothing) is added to `robots`/`fuzz`/`katana` as its own target, capped
  at `options.activeOnSubdomainsMax` (default 20, first-confirmed-live
  first) since each one gets a full fuzz wordlist pass and crawl, not just
  one request like `probe`/`gau`. An `active-on-subdomains` step is always
  recorded, saying how many were added (and whether the cap applied), even
  when it's off (0 of N). See [pipeline.md's step
  4](pipeline.md#web-stage--outputdirweb) for the user-facing version.
- Implementation: `internal/pipeline/web.go`'s `liveProbedBaseURLs` parses
  step 4's own `-json` probe output (`internal/recon/probe.Result`) and
  returns the base URL of every result whose `Target` is a discovered
  subdomain and whose `Err` is empty — no new probing, it's free given
  probe already ran. `crawlTargets` (`internal/pipeline/crawl.go`) now
  takes an `extraBases []string` alongside `cfg.Web`, scoped only by
  `options.scope` since a discovered subdomain has no per-target override
  of its own; the `robots`/`fuzz` call sites append the same list
  (`fuzz`'s target loop now ranges over `cfg.Web` plus a synthetic
  `targetEntry` per extra base, so wordlist/extensions/scope resolution is
  identical to a bare `web` entry).

### Commands default their input to the project database when nothing else is given
- **`probe`, `portscan`, `resolve`, `traceroute`, `subdomains`, `gau`,
  `sensitive`, `params`, `robots` and `validate` now fall back to
  `.srt/srt.db`** (see `srt results`) when none of `-l`, a positional arg,
  or piped/redirected stdin is given *and* stdin is an interactive
  terminal. A bare `srt probe` (nothing else) after an earlier run/pipeline
  already saved `domain`/`subdomain` records uses those instead of hanging
  waiting on the terminal; `srt portscan` falls back to `ip` records,
  `robots`/`validate`/`sensitive`/`params` to `url`/`probe`/`gau`/`robots`
  records, `resolve` to `domain`/`subdomain` (or `ip` with `-reverse`),
  `traceroute` to `ip`, `subdomains` to `domain`, `gau` to `domain`/
  `subdomain`. An explicit `-l`/positional arg/piped stdin always wins, same
  as before this existed; a real pipe (even an empty one) is never affected
  — only a genuinely interactive, nothing-given invocation changes
  behavior, so no existing script or `cmd1 | cmd2` chain is. `-from <kinds>`
  (comma list) picks a different kind than the command's own default, and
  `-where "status=<list/ranges>"` narrows it by HTTP status. One stderr
  line says what was read ("probe: using 143 domain/subdomain record(s)
  from .srt/srt.db ..."). See [commands.md's intro note](commands.md) for
  the user-facing version.
- Implementation: `internal/store.BindInputFallback`/`InputFallback.Resolve`
  (`internal/store/input.go`) is a drop-in replacement for the
  `ioutil.InputLines(ioutil.ResolveInput(*in, fs.Args()))` pattern every one
  of these commands already used; `ioutil.StdinIsTerminal` (new) is the
  terminal-vs-pipe check that makes "an interactive terminal doesn't hang"
  possible (a non-terminal stdin — a real pipe, or a redirected file, even
  an empty one — is read exactly as `InputLines` always has). The status
  filter reuses `ioutil.RangeSet`/`ParseRangeSet` (already used by `fuzz`/
  `portscan`) rather than a new parser. `resolve`'s default kind switches
  between hostnames and `ip` depending on `-reverse`, decided only after
  `fs.Parse` (`InputFallback.SetDefaultKinds`). `dirlist` and `ipexpand`
  were deliberately left out: neither has a matching db kind that's a clean
  fit (dirlist's input is a narrow "open directory listing" URL subset;
  ipexpand's input is the IP/CIDR range of the engagement itself, not a
  prior command's output).
- Verified live under a real pty (not just unit tests): a bare `srt
  resolve` with a seeded `domain` record and no `-l`/args, on an
  interactive terminal, correctly fell back to the db instead of hanging;
  piped stdin (even empty) behaved exactly as before, including the
  existing "no input" error when it really is empty.

### Skip the current pipeline step with a keyboard shortcut
- **`pipeline` now listens for `s` on stdin and abandons the step currently
  running**, moving straight to the next one, when stdin is a terminal.
  Recorded in `manifest.json` as `"status": "skipped"`, and (unless
  `-no-db`) as its own `pipeline_skip` record in the results database --
  `stage`/`step`/`target`/`reason`/`at` in `data`, queryable with `srt
  results -kind pipeline_skip` -- so a run's keyboard skips survive past
  that one manifest.json, same as every other pipeline result. See
  [pipeline.md's "Skipping a step while it runs"](pipeline.md#skipping-a-step-while-it-runs).
- Took the lighter of the two designs this bullet originally described
  (below), by explicit choice over the per-step-cancellation-context
  version: **abandon, not kill**. `runStep` now runs `fn` in a goroutine and
  races it against the skip request; on skip it returns `"skipped"`
  immediately without waiting, but the goroutine itself keeps running (and
  sending whatever traffic it already started) until it finishes on its
  own — there's still no cancellation context threaded through `fuzz`/
  `portscan`/`validate`/`runExternal`, so a kept-running step's own log
  lines can land in the *next* step's captured-warnings count instead of
  its own (cosmetic only). Trade-off: far smaller change (one new
  `internal/pipeline/skip.go`, no native command touched), at the cost of
  a skip not stopping that step's traffic right away. A true per-step kill
  (the heavier option this bullet also offered) is still open if the
  background traffic/log-misattribution turns out to matter in practice.
- Mechanism: `golang.org/x/term.MakeRaw` puts stdin in raw mode for the
  run's duration (same dependency `shell` already uses, just not its
  bubbletea-pane approach — a linear pipeline run has no screen to manage),
  read byte-by-byte in a goroutine. Raw mode disables the terminal's own
  Ctrl+C→SIGINT translation, so Ctrl+C is caught as a raw byte (0x03) and
  handled by replicating `halt.InstallHandler`'s own SIGINT behavior
  (`halt.Run()` then `os.Exit(130)`) — verified Ctrl+C still halts the
  whole run exactly as before raw mode was introduced. Verified live under
  a real pty (not just unit tests): a background process in raw mode
  receiving a keypress correctly wakes a blocked `select`. A
  non-interactive run (piped stdin, CI) never enters raw mode, so nothing
  changes for it — `activeSkip` stays `nil` and `runStep` behaves exactly
  as before this.

### `paramdiscover`: hidden GET parameter guessing (gap 9)
- New native command **`srt paramdiscover`**, and a WEB-stage pipeline step
  (`06d`, off by default: `options.paramDiscover`/`-param-discover`).
  Arjun-style batch+bisect: fetch a baseline response for an endpoint, try
  candidate parameter names in batches (default 25) against it, and only
  bisect a batch that changed something (different status, the probe
  value reflected in the body, or a body size/word-count delta beyond
  tolerance) down to the specific name(s) responsible -- cuts a ~6.4k-name
  default wordlist to a couple hundred requests per endpoint instead of
  one request per candidate. Skips binary responses after the baseline
  alone (by `Content-Type`), and excludes any candidate already present
  in the endpoint's own query string (already visible, not hidden --
  `params`' job). Defaults to the embedded SecLists
  `burp-parameter-names.txt` (~6.4k names, MIT, see
  `internal/wordlists/NOTICE.md`) when no `-w` is given.
- The pipeline step is capped on both axes so turning it on can't silently
  balloon into thousands of extra requests: `options.paramDiscoverMax`
  (default 20) limits how many validated endpoints get probed, first
  ones first (the same convention `validateMax` uses);
  `options.paramDiscoverTop` (default 500) limits candidate names tried
  per endpoint. Runs over the same validated endpoint list `sensitive`/
  `params` do.
- This is the "fuzzing/guessing" half of gap 9; katana's form extraction
  (`05c_forms.txt`, shipped with the crawler) is the "what the site
  declares itself via HTML forms" half. JS-declared parameters and
  OpenAPI/Swagger/GraphQL introspection are still open -- see
  Ideas/backlog.
- Verified end to end: a local test server with a hidden `debug` query
  parameter was found correctly (and flagged as reflected) both via the
  standalone command and through the real `pipeline` CLI with
  `-param-discover` end to end.

### katana crawler wired into the WEB stage (gap 5)
- `pipeline`'s WEB stage now crawls every explicit target with katana (on by
  default, `-no-crawl`/`options.crawl:false`, `options.crawlDepth`): links,
  JavaScript endpoints (`-jc`), robots/sitemap (`-kf all`), form extraction
  (`-fx`), `-fs fqdn` same-host scope, depth 3, 3-minute `-ct` cap, ~50 req/s,
  static assets filtered, output filtered through the target's Burp scope.
  Endpoints join `06b_endpoints.txt` (and so go through `validate`); forms
  land in `05c_forms.txt` — the first piece of gap 9 (parameters a site
  declares itself).
- The earlier hang finding was re-tested: the same command finished in ~12s
  (katana v1.8.0), so it was treated as a one-off; the step keeps katana's own
  `-ct` cap and `runExternal`'s 5-minute kill as a backstop. Known limits:
  out-of-Burp-scope paths on the same host are still *requested* (the scope
  filter only drops them from the results); JS-derived endpoints vary
  between runs; headless mode (`-hl`), `-aff` form filling and `-jsl` are
  deliberately not used.
- `install.sh`/`update.sh`/`uninstall.sh --with-pd` now manage eight tools.

### `validate`: soft-404-aware endpoint validation (gaps 3, 4, 10)
- New native command `srt validate` and a pipeline step (`06c`, on by
  default, `-no-validate`): re-probes the merged endpoint list and keeps only
  real resources. Fingerprints each host's not-found response with random
  paths per (host, first directory, extension) — status, echo-normalized
  size band, word count, and `Location` for redirects — and drops matches;
  a second pass learns groups of 10+ near-identical hits calibration
  missed. `sensitive`/`params` now run on the validated list, so extension
  matches and `-content-scan` no longer waste requests on dead or soft-404
  URLs. Endpoints are capped (`options.validateMax`, default 10000) with
  archived URLs checked last.
- Known limits: calibration is per first directory, not per every
  directory; and the fingerprint is size/words based, so a soft-404 page
  that embeds large random content could slip through to the learn pass.

### WEB pipeline: endpoint merge, reordered sensitive/params, default directory wordlist
- `robots`/sitemap hits and `fuzz` hits now merge with gau's URLs into
  `06b_endpoints.txt`, and `sensitive`/`params` run over that list *after*
  `robots`/`fuzz` instead of before them (they used to see only gau's URLs).
- `fuzz` is on by default with SecLists' `common.txt` embedded in the
  binary when no wordlist is configured (`options.fuzz:false`/`-no-fuzz` to
  disable). Gaps 1, 2 and 6 below.

### Active subdomain brute force on by default, with an embedded wordlist
- The WEB stage now brute-forces subdomains by default using SecLists'
  `subdomains-top1million-20000.txt`, **embedded in the binary**
  (`internal/wordlists`, MIT, see its NOTICE.md) so there's no path to
  configure or install. `options.subdomainsWordlist` overrides it;
  `options.subdomainsActive:false`/`-no-active-subdomains` makes the run
  passive-only. When dnsx is installed it performs the brute force (plus
  wildcard filtering) and the native one steps aside, so queries aren't
  duplicated.

### Easy wins on by default; subfinder/dnsx/alterx DNS discovery
- **The nuclei "easy wins" pass is now on by default** (`options.easyWins:false`
  or `-no-easy-wins` to disable; `-easy-wins` stays as a deprecated no-op).
  Its flags are unchanged: rate-limited, `-etags dos,fuzz,intrusive`, no
  OAST, 3-minute cap per target.
- **WEB-stage subdomain discovery now chains ProjectDiscovery's DNS tools**,
  each skipped cleanly if not installed: **subfinder** (passive, on by
  default, `-no-subfinder`); **dnsx** brute force when
  `options.subdomainsWordlist` is set (now the default, see above), followed by a `-wd` wildcard-filter
  pass; **alterx** permutations resolved by dnsx (opt-in,
  `-permutations`, capped at 2000 per domain). This is the methodology's
  HOST "DNS brute force" gap, delivered through the host↔web cross-link:
  names found are scope-checked against the host IP scope before use.
  `install.sh`/`update.sh`/`uninstall.sh --with-pd` manage all seven tools.

### `robots`: sitemap handling
- `srt robots` (and the pipeline's WEB `robots` step) now also reads
  `Sitemap:` directives from robots.txt, falling back to `/sitemap.xml`,
  follows sitemap indexes (2 levels, 25 files max) and gzipped sitemaps, and
  probes the listed URLs under a `[Sitemap]` section. Same-host only (a
  sitemap can list anything; it must not widen what gets probed), capped at
  `-sitemap-max` (default 100) per base, `-no-sitemap` to disable.

### Chaining more ProjectDiscovery tools: `cdncheck`, `tlsx`; `katana` investigated, not shipped
- **`cdncheck`** (on by default, `options.cdnCheck`/`-no-cdn-check`) — the
  HOST stage now flags which of a ports group's IPs sit behind a known
  CDN/WAF/cloud provider, informational only. A local dataset lookup with
  no traffic to the target at all, unlike every other external-tool step
  here, so there's nothing to opt into.
- **`tlsx`** (on by default, `options.tlsx`/`-no-tlsx`) — the WEB stage
  now extracts each explicit target's certificate SAN/CN entries and
  merges them into the same discovered-domain pool `subdomains` widens,
  through the same host↔web scopecheck cross-link. One TLS handshake per
  target, the same order of traffic as `probe`'s own one request per
  target.
- **`katana` (active crawling) was first investigated and NOT shipped — superseded, see the entry above.** It would have been the highest-value addition on this list —
  `gau`'s passive Wayback lookups miss everything that was never archived
  — but in the sandbox this was built in, a trivial local crawl hung
  indefinitely: it opened several parallel HTTPS connections through the
  egress proxy to something unrelated to the crawl target before ever
  reaching it, and no flag (including `-duc`) was found to prevent it.
  Shipping an automated, unattended pipeline step on a tool observed
  hanging, with no way to know whether a given deployment's own network
  hits the same thing, wasn't worth the risk. **Still a real, open gap —
  see Ideas/backlog below** for what adding it properly would need.
- **`runExternal` now enforces a hard 5-minute wall-clock timeout on every
  external-tool call** (`vulnx`, `nuclei`, `cdncheck`, `tlsx`, and any
  future addition) — directly because of the `katana` finding above. Set
  comfortably above `nucleiEasyWinsArgs`' own `-mt 3m` cap so a tool
  winding down cleanly on its own schedule is never cut off first; only
  matters for a tool that's hung or unexpectedly slow, which previously
  had no backstop at all.
- All four tools' exact flags (`vulnx`, `nuclei` from before, plus
  `cdncheck`/`tlsx` here, and `katana`'s investigation) were verified
  against binaries built with `go install .../cmd/<tool>@latest` and run
  directly (`-h`, and live against local test listeners/a self-signed TLS
  cert with SAN entries for `tlsx`), not just READMEs —
  `docs.projectdiscovery.io` itself is blocked in this session's network
  policy, so each tool's own GitHub README (via
  `raw.githubusercontent.com`, which is reachable) was the source instead.
  Install any of them with [pdtm](https://github.com/projectdiscovery/pdtm):
  `pdtm -i vulnx,nuclei,cdncheck,tlsx`.

### WEB stage wiring for `sensitive -content` (`-content-scan`)
- **`pipeline`'s WEB stage can now run `sensitive -content` over the
  merged `gau` URL list** instead of only ever filtering by extension —
  closes the "pipeline integration" gap that was still open after
  `sensitive -content` itself shipped. `options.contentScan` in a JSON
  config, or `-content-scan` on the CLI, switches the `sensitive` step
  from `03_sensitive.txt` (plain extension-filtered URLs, the unchanged
  default) to `03_sensitive.json` (structured secret hits: `url`,
  `pattern`, `match`, `context`). **Off by default** — a large `gau` dump
  can be thousands of URLs, and this turns a string classification into a
  real fetch per URL; `options.concurrency`, if set, caps it the same way
  it already does for `fuzz`, instead of adding a second concurrency knob
  just for this step. The argv-building logic
  (`sensitiveArgsFor` in `internal/pipeline/web.go`) was pulled out as its
  own function so it's unit-testable without live HTTP calls, the same
  shape `vulnxSearchArgs`/`nucleiEasyWinsArgs` already use.

### HOST "easy wins" pass: a conservative `nuclei` call (`-easy-wins`)
- **`pipeline`'s HOST stage can now run nuclei's default-login/misconfig/
  exposure templates against every non-web open port** — the last entry
  in methodology.md's HOST "scan" step. By explicit decision this is a
  direct `nuclei` call rather than a native reimplementation (the usual
  policy): reimplementing nuclei's own default-credential/misconfiguration
  template library wasn't worth it for one step, so `nuclei` joins `vulnx`
  as a second named exception in methodology.md's External-tool policy.
  **Off by default** (`options.easyWins` in a JSON config, or `-easy-wins`
  on the CLI) — unlike `vulnx`'s lookup against a third-party database,
  this sends real probes at the service, so it needs an explicit opt-in.
  Traffic is bounded regardless of that opt-in: `-tags
  default-login,exposure,misconfig` (never `cve` — `vulnx` already covers
  that from the banner right above this step in the same loop), `-etags
  dos,fuzz,intrusive` to drop anything actively harmful, and `-rl 10 -c 3
  -bs 1 -timeout 5 -retries 1 -mt 3m` to keep one target's worst case to a
  low-rate, short burst well under nuclei's own (much higher) defaults.
  `-ni` skips OAST/interactsh templates so this never depends on a
  third-party interactsh server; `-duc` skips nuclei's own per-run
  update-check call but does **not** fetch nuclei-templates from nothing
  — that's still a one-time `nuclei -ut` the operator runs themselves.
  Skips cleanly (same `runExternal` shape as `vulnx`) if `nuclei` isn't
  installed. The exact flags were verified against a built `nuclei`
  v3.11.1 binary (`-h`/`-help`), not just its docs, same rigor as `vulnx`'s
  `-p/--product` fix.

### BeanShell detection by banner (`portscan.IsBeanShellBanner`)
- **`pipeline`'s HOST stage now flags an exposed BeanShell interactive
  server** regardless of what port it's listening on. BeanShell has no
  fixed/assigned port, so it was the one entry in methodology.md's "flag
  uncommon services for manual follow-up" step that `uncommonPorts`'
  port-number list could never catch; `IsBeanShellBanner` instead matches
  its real startup line ("BeanShell &lt;version&gt; - by Pat Niemeyer
  (pat@pat.net)", the same signature nmap's service-probes database
  fingerprints it by) against any open port's grabbed banner. A match is
  recorded as its own `flag-beanshell` step — a distinct, more specific
  label than the generic `flag-uncommon-service`, since an exposed
  BeanShell with no auth is an immediate unauthenticated remote code
  execution risk (anything sent to it runs as arbitrary Java/BeanShell), not
  just "worth a manual look." `vulnx` still also runs against it, same as
  any other bannered non-web port.

### Fuzzer output formats: `-ndjson`, `-summary`
- **`-ndjson <file>`** — streams every matched hit as a JSON line to that
  file continuously, independent of the console display mode (table/
  `-silent`/`-json`) and of `-o`. Before this, getting structured output
  meant giving up the colored table (`-json` replaces it); now you can keep
  the table on screen and have another tool `tail -f` structured data from
  the file at the same time.
- **`-summary`** — counts every response this run saw (matched or not) and
  prints a per-status-code table at the end, independent of `-mc`/`-fc` --
  the "-mc-less show-all" view: a quick look at what's actually out there
  (how many 403s, how many soft-404 200s slipped past calibration, ...)
  before deciding what to filter, instead of re-running with `-mc all` and
  wading through every line.

### Host↔web scope cross-link in `pipeline`
- **`pipeline`'s WEB stage filters discovered domains/subdomains through
  the HOST stage's IP scope** — closes the gap `playbook.md`'s manual flow
  always had and `pipeline` didn't: a domain/subdomain that resolves
  outside the engagement's IP range (a third-party CDN, a stale DNS record)
  is dropped before it reaches `subdomains`/`gau`/`probe`, the same way
  `srt domains -l ... | srt scopecheck -scope scopeips` does by hand.
  The cross-link runs twice, matching the playbook's order: once on the
  domains `domains` extracts from `web` targets (before `subdomains` runs),
  and once on the subdomains that step discovers (before they're merged
  into the list `gau`/`probe` operate on). `robots`/`fuzz` are unaffected —
  they already only ever touch the explicit `web` targets, never the
  discovered list.
  The "host IP scope" is built from the same invocation's config `host`
  list (both included and excluded-but-tracked entries — excluded just
  means never actively probed, not out of scope), written once to
  `<outputDir>/host_scope.txt`. With no `host` targets in the config (a
  web-only run), the cross-link is skipped entirely and both stages stay as
  independent as before this existed. A `scopecheck` failure (e.g. a
  malformed host entry) fails open rather than silently dropping every
  domain over a broken check.

### Content-based sensitive-info classification (`sensitive -content`)
- **`sensitive -content`** — fetches every input URL and scans the response
  body against a small, high-precision set of secret/credential signatures
  (AWS/Google/Slack/GitHub/Stripe tokens, private key blocks, JWTs,
  basic-auth and database connection strings in a URL, generic
  `key=`/`secret=`/`password=` assignments — `internal/payloads.SecretPatterns`)
  instead of filtering by extension. Closes the "not just by extension" half
  of the WEB methodology gap: a leaked key in a `.js` bundle or a plain
  `config` endpoint is invisible to extension matching but not to this.
  `-c`/`-timeout`/`-insecure`/`-max-size` control the fetch; a fetch error or
  non-2xx is skipped, not fatal, since a dead link from an old Wayback crawl
  is routine on a large `gau` dump. `-json` emits structured hits
  (`url`, `pattern`, `match`, `context`); the default mode (no `-content`)
  is unchanged.

### Fuzzer: preflight baseline, parent-seeded calibration, smarter recursion, adaptive concurrency, mutations
- **Preflight baseline probe** — every `fuzz` run, with or without `-ac`,
  fires two guaranteed-nonexistent paths at each target host's root before
  any real fuzzing starts (the "what does a 404 look like here" check a
  human runs by hand). A host whose miss comes back looking like a *hit*
  under the configured matchers gets soft-404 filtering auto-enabled for it
  on its own, with a stderr line saying so; a host that 404s cleanly is left
  alone. Either way the fingerprint is recorded as that host's baseline.
- **Parent-to-child (and baseline-to-directory) calibration inheritance** —
  `-ac`'s per-directory calibration now seeds from the nearest already-known
  fingerprint — the preflight baseline at the top level, or the parent
  directory's own calibration once `-recursion` descends — before running
  its own probes on top. Saves probe requests on deep trees without masking
  a directory with a genuinely different soft-404 of its own.
- **Smarter directory detection for `-recursion`** — besides the classic
  redirect-to-trailing-slash signal, a direct `2xx` on an extensionless word
  is now also recursed into once its `<word>/` form is confirmed to resolve
  to a real (non-soft-404) page too — for apps that serve a directory
  listing inline with no redirect. Narrowed to words with no dot, so a flat
  file is never probed this way.
- **Adaptive per-host concurrency (`-adaptive-conc`)** — an AIMD controller
  per host: starts conservative, climbs one slot at a time after a run of
  clean, on-pace responses, and backs off immediately on a transport error,
  `429`/`503`, or a response much slower than that host's own recent
  average. `-hc`, if also set, still caps how high it can climb.
- **Wordlist mutations** — `-mutate-case` also tries lower/UPPER/Title-case
  variants of every word; a literal `%ext%` token in a wordlist line (e.g.
  `backup.%ext%`) expands against the resolved extensions instead of only
  ever having one appended as a suffix.
- **Resume-log compaction** — a `-resume` state file is now rewritten down
  to one line per completed target and one per discovered directory every
  20k appended lines, instead of growing by one line per request for the
  life of a long run; a failed compaction (e.g. a read-only output dir)
  leaves the original file and writer untouched.

### Excluded-but-tracked hosts + native traceroute
- **`host` entries can be marked `"excluded": true`** in a `pipeline`
  config: never portscanned, never handed off to WEB — only `ipexpand` ->
  `resolve -reverse` -> `srt traceroute`, matching the methodology's
  excluded-but-tracked hosts exactly.
- **`srt traceroute`** — a native ICMPv4 route tracer (one echo per TTL,
  matched to its reply by id/sequence so unrelated ICMP traffic on the host
  can't be mistaken for it). Needs a raw socket (`CAP_NET_RAW` on Linux, or
  root); checked once up front and **skipped cleanly** without one — in
  `traceroute` itself and in `pipeline`'s excluded-host step — the same
  shape already used for `vulnx` when it's not installed. Not implemented
  on Windows yet (needs a different raw-socket API — WSASocket/IP_HDRINCL —
  that nobody's wired up); the binary still cross-compiles there, the
  command just reports it can't run. IPv4 only for now; `golang.org/x/sys`
  (already pulled in transitively) is now a direct dependency for the raw
  socket calls, no new dependency tree.

### Fuzzer precision & scale
- **Automatic extension discovery** — `fuzz -ext-auto` combines tech-detect
  with the soft-404 logic: the root page's detected stack (PHP, ASP.NET,
  Express…) trusts its extensions outright, and the generic candidates
  (`.html .txt .bak .zip`…) are verified live against a per-extension
  baseline, so jittery-200 apps don't yield false extensions. Per host, shared
  across recursion. `pipeline` enables it for web targets with no explicit
  `extensions` (`options.autoExtensions: false` opts out).
- **Jitter-tolerant soft-404 filtering** — `-ac` fingerprints are bands:
  reflection-normalized size, `-ac-tol` percent tolerance, a word-count band
  (so a different page with a similar byte length still shows), and
  `-ac-learn` runtime learning of clusters calibration missed. Handles apps
  whose "not found" 200 varies in length (3302/3305/3310/3312).
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
- **`install.sh`/`update.sh`** — one-liner install/update: fetches the
  right platform binary from this repo's latest GitHub Release and `sudo
  install`s it to `/usr/local/bin` (`$PREFIX/bin` if set), no Go toolchain
  needed. Linux/macOS; Windows grabs the `.exe` release asset directly.
- **`pipeline -host-file`/`-web-scope`** — build a config straight from a
  plain IP/CIDR list and/or a Burp scope export, no hand-written JSON
  required; combines with `-c` when one is also given.
- **`shell`** — interactive REPL with command history and Tab-completion on
  command names (`golang.org/x/term`, pinned to v0.40.0 for Go 1.24
  compatibility — `srt`'s first Go module dependency; everything else stays
  stdlib-only). Every line dispatches as a real subprocess of `srt` itself
  rather than in-process, since every command's `flag.FlagSet` uses
  `flag.ExitOnError` — in-process, a typo'd flag would `os.Exit` the whole
  shell session instead of just that command. The subprocess design also
  makes `help <command>` free: it's literally `<command> -h`, so there's no
  separate help text to maintain or drift out of sync.
- **Scope-file auto-detection** — `pipeline` with no `-c`/`-host-file`/
  `-web-scope` scans the current directory for `*-in-scope*` (host list) and
  `target_assets*.json` (Burp export; tolerates `(1)`-style download
  suffixes), newest match wins, and says what it picked on stderr.
  `-no-detect` opts out.
- **Project switching in `shell`** — `cd <dir>` / `project <dir>` changes the
  shell's CWD (every spawned command inherits it); the project name is the
  directory's base name and sits in the status bar. `cd -` returns to the
  previous project, bare `cd` goes home, bare `project` shows where you are.
  Tab completes directories (unique match, or longest common prefix), and a
  switch reports any scope files auto-detected in the new project.
- **Go-binary install, run from anywhere** — `go install
  github.com/trike33/srt-cheatsheet/gotools/cmd/srt@latest` (or `make
  go-install`) gives a self-contained `srt` on `PATH`; nothing is read from
  the source tree and relative paths resolve against the CWD. `srt version`
  reports the module version for `go install` builds (ldflags still win),
  and the shell re-execs itself via `os.Executable`, so it works from any
  directory.
- **Live traffic counter + halt** — every network touch (HTTP requests and
  wire bytes, TCP connect attempts, DNS lookups) is metered at three
  chokepoints (`netx`'s client, `portscan.probePort`, the resolvers).
  Commands run from the `shell` log a `[traffic] ...` line every 2s, the
  shell keeps a session total in its own permanent traffic box (see below),
  and Ctrl+C halts a command instantly with its totals. `limit bytes <size>`
  sets a per-command byte ceiling; a breach kills the command immediately
  (exit 3, "HALTED"). Plain CLI runs aren't metered. Counts are per process,
  so a `pipeline` run is metered as a whole; external tools it shells out to
  (`vulnx`) aren't counted.
- **Self-overwriting live counters, width-safe** — the heartbeat
  (`ioutil.StartHeartbeatEvery`), `fuzz`'s per-host progress ticker, and the
  shell's `[traffic] ...` line all update the same terminal row in place
  (`colorout.Overwrite`) instead of scrolling a new line per tick, and the
  line is truncated to the terminal's actual width first
  (`colorout.TermWidth`) — printing something longer than the terminal and
  letting it wrap breaks the whole trick, since `\r` only returns to the
  start of the *last* wrapped row, not back to the top of the previous
  print, so every earlier row is left stuck on screen as new ticks pile up
  below it (this is what a multi-host `fuzz` run on a narrow terminal used
  to look like). Redirected to a file/pipe, each tick still gets its own
  newline-terminated line, so a backgrounded run's log keeps every tick.
- **Permanent traffic box in the shell** — session traffic (and the last
  finished command's own traffic) now live in a dedicated bordered box that
  is always visible and never clears on the next keystroke, instead of a
  few seconds in the transient status-line notice that disappeared the
  moment you started typing the next command.
- **Bash-style Tab completion over paths** — Tab in the shell completes
  files and directories for whichever word the cursor is in, not just a
  2nd-word `cd`/`project` argument: any command's path argument (a
  wordlist, a scope file, an output path) completes the same way a real
  shell's does. `cd`/`project` still restrict matches to directories only,
  since their one argument is always a place to switch into; every other
  command completes both. A unique match completes fully (directories get
  a trailing `/`), several matches extend to their longest common prefix.
- **`clear` redraws the startup banner** — the shell's `clear` command
  still clears the terminal, then reprints the banner (version, build,
  cwd) that was otherwise only ever shown once at startup and lost for
  good the moment the screen was cleared.
- **Global request-rate cap** — `srt -rate 50 <command>` (or `$SRT_RATE`)
  throttles the whole process to N requests/second, whatever the command or
  its concurrency: every HTTP request, TCP connect and DNS lookup takes a
  strictly spaced slot (no bursts), and cancelled/timed-out requests leave
  the queue. Works on every subcommand; `fuzz`'s own `-rate`/`-rate-global`
  still apply on top (the lower wins). The shell applies **50 req/s by
  default** to every command; `limit rate <n>` changes it, `limit rate off`
  lifts it, and `srt -rate N` starts a shell with a different default. Under
  a tight cap, high `-c` concurrency queues behind the gate, so waiting time
  counts toward a request's timeout — lower `-c` or raise `-timeout` if you
  see spurious timeouts.
- **Results database** — `pipeline`, the `shell`, and `-save` on any command
  persist results to a per-project SQLite file (`.srt/srt.db`; pure-Go driver
  `modernc.org/sqlite`, so `srt` stays one static binary, ~+8 MB). Generic
  `records` table (kind, key, host, port, url, status, length, JSON data)
  grouped into `runs`; **runs are never overwritten**, so re-running the
  methodology keeps history (that backlog item is done too). `srt results`
  (filters + table/JSON/keys/count; default view = newest observation of each
  result), `srt runs`, `srt export` (per-host directory tree, CSV, JSON) and
  `srt db path|stats|import|rm`. Global flags `-save` and `-db <path>`
  (`$SRT_SAVE`, `$SRT_DB`). Structured for portscan/fuzz/probe; other
  commands are saved from stdout line by line. Flushed on Ctrl+C/halts.
- **Stop & resume** — an interrupted scan continues instead of restarting.
  - `portscan -resume <file>`: progress is one watermark over the fixed
    host-major probe sequence (plus every open port, written the moment it's
    found), checkpointed every 500ms and flushed on Ctrl+C/limit halts. A
    re-run with the same hosts/ports skips finished probes and re-emits the
    recovered results, so the output file always reflects the whole scan; a
    state file from a different scan is refused. `fuzz -resume` already
    existed.
  - `pipeline -resume`: `checkpoint.json` in the output dir records finished
    steps; a resumed run skips them (if their output file still exists) and
    continues the interrupted `portscan`/`fuzz` mid-way via per-step state
    files. Without `-resume` a run starts fresh.
  - Central halt handling (`halt.go`): SIGINT/SIGTERM and limit breaches run
    flush hooks before exiting 130/3 — so state on disk is current.
  - In the `shell`, `portscan`/`fuzz`/`pipeline` are tracked automatically in
    `<project>/.srt/` (so they survive closing the shell and are per
    project). Stop one with Ctrl+C or a `limit bytes` halt, then `sessions`
    lists what's interrupted and `resume [id]` (default: the latest) carries
    on. A clean finish discards the session. Passing your own `-resume` opts
    out of tracking.
- **Shell is the default mode** — bare `srt` on an interactive terminal
  drops straight into the shell; `srt <command> ...` (e.g. `srt pipeline`)
  stays plain CLI. With no TTY on stdin (scripts, pipes) bare `srt` still
  prints usage and exits 2 rather than hanging. Shell test coverage now
  includes line dispatch, key handling, exec-result handling and the TTY
  guard.

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
- **vulnx integration** — `pipeline`'s HOST stage runs `vulnx search` for
  every non-web open port with a grabbed banner, via the `runExternal`
  helper in `internal/pipeline/external.go` (skips cleanly if `vulnx` isn't
  installed). Works unauthenticated, just rate-limited without `vulnx auth`
  configured. `vulnxSearchArgs`/`vulnxProduct` use `-p <product>` (e.g. `-p
  openssh`, `-p arcgis`) when the banner matches a recognized service --
  the precise, structured form of the real CLI (verified against the built
  binary, not just its docs/help text) -- falling back to a free-text
  search over the banner for anything `vulnxProduct` doesn't recognize.

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
  active by default, see Shipped) and `probe` run right
  after `domains`, widening the domain list `gau` also runs against.
  `robots`/`fuzz` stay scoped to the explicit `web` targets, so discovering
  N subdomains doesn't silently multiply active traffic — that stays opt-in.

## Ideas / backlog

### Methodology gaps (see [methodology.md](methodology.md))

Native implementations, not external-tool integrations — `srt`'s policy is
to reimplement what naabu/httpx/subfinder/dalfox would give us rather than
shell out to them. `vulnx`, `nuclei`, `cdncheck`, and `tlsx` are the four
named exceptions, each wired up for its own reason — see Shipped above and
methodology.md's External-tool policy.

- **HOST**: ~~excluded-but-tracked hosts~~ — done, see Shipped.
  ~~BeanShell detection~~ — done, see Shipped (`portscan.IsBeanShellBanner`).
  ~~"Easy wins" pass~~ — done, see Shipped (`-easy-wins`; a direct `nuclei`
  call rather than a native reimplementation, by design — see
  methodology.md's External-tool policy).
- **WEB**: Google dorking; context-aware wordlist generation for `fuzz`
  (extensions now are, via `-ext-auto`; candidate *words* derived from the detected tech stack/app context — `probe`'s
  tech-detect output is the natural input for this now, not just static
  wordlists); ~~a re-validation step for URLs pulled from `gau`/dorking~~ —
  done, see Shipped (`validate`; dorking itself still isn't implemented,
  so nothing from it reaches `validate` yet); ~~parameter
  fuzzing/guessing beyond `params`' URL-based classification~~ — done,
  see Shipped (`paramdiscover`), though reading parameters from a
  webset/API spec when one exists is still open;
  ~~content-based sensitive-info classification~~ — done, see Shipped
  (`sensitive -content`); optionally also running `robots`/`fuzz`
  against `pipeline`-discovered subdomains, opt-in given the traffic-volume
  implications (today only `gau`/`probe` auto-widen to them).
- **`pipeline` integration** — as each of the above lands, extend
  `internal/pipeline/host.go`/`internal/pipeline/web.go` to call it in the
  order `methodology.md` lays out. ~~`sensitive -content` wiring~~ — done,
  see Shipped (`options.contentScan`/`-content-scan`).
- ~~Host↔web scope cross-link in `pipeline`~~ — done, see Shipped.

### More ProjectDiscovery tool chaining (see Shipped above for `cdncheck`/`tlsx`)

- **`katana`** — shipped (see Shipped). Still open: headless crawling
  (`-hl`, for JS-heavy SPAs), authenticated crawling (cookies/headers via
  `-H`), and crawling discovered subdomains (gap 8).
- **`dnsx` (more record types)** — brute force, resolution and wildcard
  filtering are now wired (see Shipped). ~~TXT/CNAME/NS/MX/SOA record
  collection~~ — TXT/CNAME/NS/MX done natively, see Shipped
  (`srt resolve -type`); **SOA still open** -- Go's `net` package has no
  `LookupSOA` at all (no public primitive for it), and pulling in a DNS
  library just for one record type wasn't judged worth it for a command
  that's native by policy.
- **`shuffledns`** — massDNS-based brute force for very large wordlists;
  needs massdns and a resolver list, so it wasn't chosen over dnsx.
- **`mapcidr`** — CIDR aggregation (merge many ranges into the smallest
  covering set) and filtering. Overlaps with `srt ipexpand`'s existing CIDR
  expansion; aggregation specifically could help build/shrink a host scope
  file, but isn't a gap `ipexpand` leaves open today.
- **`asnmap`** — maps an ASN/org/domain to its CIDR ranges, which could
  seed a HOST scope from just a company name. Requires a ProjectDiscovery
  Cloud Platform API key for the CLI to work at all (not just
  rate-limited-without-one like `vulnx`), which is real adoption friction
  for a default-on or even default-off pipeline step — would need its own
  config field for the key and a clear skip when it's absent. Still open
  (not the same tool as `uncover` below, which is shipped).
- ~~**`uncover`**~~ — done, see Shipped (gap 11): aggregates Shodan/
  Censys/etc. searches for exposed assets matching a query, wired into
  the HOST stage as `options.uncover`/`-uncover`.

### WEB pipeline: target flow and gaps (investigated, not started)

Target flow: **endpoints** (active: robots + sitemap, crawl, dir/file brute
force with generic *and* guessed wordlists; passive: gau, optionally
chaos/uncover) -> one merged endpoint list -> **re-probe with native httpx**
-> **valid endpoints** (careful: soft-404 sites answer 200 for anything) ->
**parameters** (fuzz/guess, or read from what the site declares) and
**sensitive info** (sensitive extensions, creds/API keys).

What the pipeline does today, in order: domains -> subdomains (+subfinder/
dnsx/alterx) -> tlsx -> `probe` (roots only) -> `gau` -> `sensitive` +
`params` (over gau URLs only) -> `robots` -> `fuzz` -> `snyk`. Gaps:

1. ~~**No endpoint merge.**~~ *(done — `06b_endpoints.txt`)* `robots`/sitemap output (`05_robots.txt`) and
   `fuzz` results (`06_fuzz_*.json`) never join `02_all_urls.txt`; there is
   no single "endpoints/directories/files" list to carry forward.
2. ~~**Wrong order.**~~ *(done)* `sensitive`/`params` run *before* `robots`/`fuzz`, so
   they only ever see gau's archived URLs, never what the active steps found.
3. ~~**No re-probe of endpoints.**~~ *(done — `validate`)*  
   *(original note:)* `probe` runs once on domains (recon on
   root). gau/robots/sitemap/fuzz URLs are never validated as a distinct
   step (`probe` already accepts URLs, so the plumbing exists).
4. ~~**No soft-404 handling outside `fuzz`.**~~ *(done — `validate`; `robots`' own green-on-200 output is unchanged)*  
   *(original note:)* `fuzz -ac` calibrates per
   directory, but `probe` has none, and `robots` prints green for any 200
   (so the new sitemap URLs on a soft-404 site all look valid). The
   validation step needs a per-host random-path fingerprint (status, size,
   words, body hash) and to drop matches — `fuzz`'s `calibData` is the
   reusable piece.
5. ~~**No crawler.**~~ *(done — katana, see Shipped)*
6. ~~**Directory brute force is off unless you configure a wordlist.**~~ *(done — embedded `common.txt`, on by default)* `fuzz`
   is skipped per target when no `wordlist`/`options.wordlist` resolves —
   the same problem subdomains had before the embedded list. Needs an
   embedded generic list (raft/common-style) and a `-no-fuzz`-style switch.
7. ~~**No guessed/context wordlists.**~~ *(mostly done — see Shipped:
   `fuzz -words-auto` + `options.contextWords`)* *(original note:)* Only
   extensions are auto-detected (`-ext-auto`); words derived from the
   target's tech stack, titles, JS identifiers or the engagement name are
   not generated. **Still open**: JS-declared identifiers (variable/
   function/route names parsed out of crawled JS, as opposed to katana's
   existing link/form extraction) as a word source.
8. ~~**Active steps only cover explicit targets.**~~ *(done — see Shipped:
   `options.activeOnSubdomains`/`-active-on-subdomains`)* *(original
   note:)* `robots`/`fuzz` never run against discovered live subdomains
   (deliberate, to bound traffic, but then "recon on every subdomain"
   never reaches endpoint discovery). Needs an opt-in that feeds
   `probe`-confirmed live hosts forward.
9. ~~**Parameters are only classified, not discovered.**~~ *(mostly done —
   see Shipped: `paramdiscover`'s batch+bisect guessing, wired in opt-in;
   katana's form extraction covers HTML forms/inputs)* *(original note:)*
   `params` buckets parameters already present in URLs by vuln class.
   Missing: parameter fuzzing/guessing against valid endpoints, and
   automatic extraction of what the site declares itself (HTML
   forms/inputs, JS, OpenAPI/Swagger/GraphQL introspection). **Still
   open**: JS-declared parameters (XHR bodies/query strings katana parses
   but doesn't surface as parameter names today) and OpenAPI/Swagger/
   GraphQL introspection.
10. ~~**Sensitive-info checks the wrong population.**~~ *(done — runs on the validated list)*  
    *(original note:)* The extension list is
    identical to your regex (and matches on the URL *path*, so a query
    string can't hide or fake a hit), but it runs on archived URLs without
    checking the file still exists, and `-content-scan` (off by default)
    fetches every URL including dead ones and soft-404 pages. Both should
    run over the validated list only.
11. ~~**chaos / uncover not wired.**~~ *(done — see Shipped:
    `options.chaosAPIKey`/`options.uncover`)* *(original note:)* Both need
    a ProjectDiscovery/engine API key. chaos is a subdomain source
    (subfinder can use it once a chaos key is in its provider config —
    worth documenting before adding a tool); uncover (Shodan/Censys/...)
    seeds hosts/IPs from a query and belongs at scope-building, with a
    config field for keys and a clean skip when absent.
12. ~~**Google dorking**~~ *(done — see Shipped: `srt dork` +
    `options.dork`)*.

Suggested build order: (1)+(2) merge and reorder, (4) soft-404-aware
validation, (3) re-probe, then (10) rerun sensitive/params on the valid
list, then (6)/(7) default wordlists, (9) parameter discovery, (5) crawler.

### Active testing & UX (from engagement notes, not started)

Noted for later — none of these are scoped or designed yet, just captured
so they aren't lost:

- **Parameters → vulnerability-class correlation** — go beyond `params`'
  current static marker-matching to a richer mapping from a discovered
  parameter to the vulnerability classes worth testing it for.
- **A payload library**, sourced from PayloadsAllTheThings, for active
  testing modules to draw on (ties into auto-detect-and-send below).
- **Detect error-based and time-based behaviors** — blind SQLi/command
  injection style signals during active testing.
- **Screenshot discovered websites** (gowitness/aquatone-style).
- **Auto-detect and send payloads** — close the loop from recon
  (parameters, tech-detect) to actually firing payloads at likely-vulnerable
  targets.
- **Skip the current pipeline step with a *true* kill, not just an
  abandon** — the keyboard-shortcut skip shipped above (see Shipped) stops
  *waiting* on a step but doesn't stop *it*: the abandoned goroutine keeps
  running (and sending traffic) until it finishes on its own, since there's
  no cancellation context threaded through `runStep`/`runExternal`/the
  native steps (`fuzz`, `portscan`, `validate` would each need to honour a
  context and save resumable state the way they do for the global halt,
  see `internal/halt`). Worth doing only if that lingering background
  traffic/log-misattribution turns out to matter in practice; also open:
  the same shortcut inside `shell`'s own output pane (a dedicated key
  binding there, since raw-stdin reading isn't `shell`'s model).
- **A guided flag-builder in `shell`** (the basic REPL itself shipped — see
  Shipped above) — interactively prompting for each flag instead of still
  typing them. Needs either a shared declarative flag schema across every
  command (a real refactor) or per-command duplicate prompt flows that
  would drift from the real flags over time.

### Fuzzer / pipeline

- ~~Recursion content-length auto-filter inheritance~~ — done, see Shipped
  (preflight-to-directory and parent-to-child calibration seeding).
- ~~Smarter directory detection~~ — done, see Shipped.
- ~~Per-host adaptive concurrency~~ — done, see Shipped (`-adaptive-conc`).
- ~~Resume compaction~~ — done, see Shipped.
- ~~Wordlist mutations~~ — done, see Shipped (`-mutate-case`, `%ext%`).
- ~~Output formats~~ — done, see Shipped (`-ndjson`, `-summary`).
- **Release automation** once workflow scope is available (tag → binaries).

Suggestions welcome — open an issue.

# JOAN Suggestions

- ~~Stop and resume sessions~~ — done, see Shipped.
- ~~Project switching in the shell~~ — done, see Shipped.
- ~~Auto-detect known scope files~~ — done, see Shipped.
- ~~Live traffic counter and halt in the shell~~ — done, see Shipped.
- ~~Finish the shell tests and make shell the default mode~~ — done, see Shipped.
- ~~Install as a Go binary, run from anywhere~~ — done, see Shipped.

