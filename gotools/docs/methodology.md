# Assessment methodology

The HOST and WEB methodology `srt pipeline` is built to automate, end to
end. Original planning notes are kept for reference:
[host-notes.jpg](methodology/host-notes.jpg),
[web-notes.jpg](methodology/web-notes.jpg).

Each step below says what's already implemented (and by which `srt`
subcommand) versus what's still backlog — see [ROADMAP.md](ROADMAP.md) for
the tracked list.

## External-tool policy

`srt` does not shell out to third-party recon tools (naabu, httpx,
subfinder, dalfox, ...). Where the methodology below needs what one of
those would normally provide, the plan is to implement it natively in
Go — porting the useful logic from existing open-source discovery projects
where that saves work, but not invoking their binaries or calling out to
their APIs at runtime — so `srt` stays a single static binary for every
other command. (Separately, `srt` itself picked up its first Go module
dependency, `golang.org/x/term`, for the interactive `shell`'s line editor
— unrelated to this policy, which is about not shelling out to *other
recon tools*, not about the build staying stdlib-only forever.)

**Eight named ProjectDiscovery tools are the exceptions**, each kept as an
external call via the `runExternal` hook in `gotools/internal/pipeline/
external.go` (looks the binary up on `PATH`, skips cleanly if it's missing
— never aborts a run over an optional tool). Install any of them with
[pdtm](https://github.com/projectdiscovery/pdtm), ProjectDiscovery's own
tool manager (`go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest`,
then `pdtm -i vulnx,nuclei,cdncheck,tlsx,subfinder,dnsx,alterx,katana`):

- **vulnx** — CVE lookups from a grabbed service/software version.
- **nuclei** — the HOST stage's "easy wins" pass (default creds, common
  misconfigs). Reimplementing nuclei's own default-login/misconfig
  template library natively wasn't worth it for this one step, so it's a
  generic, directly-invoked `nuclei` call instead — but unlike vulnx, it
  sends real probes at the service rather than querying a third-party
  database, so its traffic is kept deliberately bounded (rate-limited,
  intrusive templates excluded) and it can be disabled
  (`options.easyWins:false`/`-no-easy-wins`; **on by default**) (see
  [pipeline.md](pipeline.md)'s classify-services step for the exact flags).
- **cdncheck** — flags a HOST-stage IP as a known CDN/WAF/cloud provider.
  A local dataset lookup with no traffic to the target at all, so it's
  **on by default** (`options.cdnCheck`/`-no-cdn-check` to disable) —
  informational only, it doesn't change what gets scanned, just tells the
  operator when an "open" port is actually a CDN edge rather than the
  origin.
- **tlsx** — widens the WEB stage's discovered-domain pool with each
  target's certificate SAN/CN entries, alongside crt.sh/active brute
  force. One TLS handshake per target is the same order of traffic as
  `probe`'s own one request per target, so it's **on by default**
  (`options.tlsx`/`-no-tlsx` to disable).

- **subfinder** — passive subdomain sources beyond crt.sh. **On by
  default** (`options.subfinder`/`-no-subfinder`); third-party lookups
  only, no traffic to the target.
- **dnsx** — DNS brute force (`-d`/`-w`) with a second `-wd` pass that
  drops wildcard answers, run by default (embedded SecLists top-20000 list, or `options.subdomainsWordlist`);
  also resolves alterx's permutations.
- **alterx** — permutations of the discovered names, **opt-in**
  (`options.permutations`/`-permutations`) since each one is a DNS query.

- **katana** — the WEB stage's crawler: follows links, parses JavaScript
  for endpoints (`-jc`), reads robots.txt/sitemap.xml (`-kf all`) and
  extracts form fields (`-fx`). **On by default** (`options.crawl`/
  `-no-crawl`); depth 3, 3-minute cap, request rate and concurrency bounded,
  same host only (`-fs fqdn`), static assets filtered, results dropped if a
  Burp scope is configured and they fall outside it.

  katana was first left out: in the dev sandbox a trivial local crawl
  produced no output for 60 seconds. On re-testing (v1.8.0) the same command
  and every flag individually finished in ~12s, so that run is treated as a
  one-off — but the step is built to survive a repeat: katana's own `-ct`
  cap, plus `runExternal`'s hard 5-minute wall-clock kill, so a hung crawl
  can cost time but never hang a run. Crawl output is also nondeterministic
  at the edges (JavaScript-derived endpoints appeared in some runs and not
  others), which is one more reason the endpoint list merges several
  sources rather than trusting any one.

## HOST

```
scope (IPs, or a pipeline JSON config's "host" list)
  -> included / excluded
       excluded -> reverse DNS lookup + route trace only (never actively probed)
       included -> DNS check -> port scan (common + uncommon ports) -> services list
                                                                           |
                                        web services -------------------->+--> hand off to WEB (below)
                                        other services -> "scan":
                                          - grab version -> check CVEs with vulnx
                                          - run an "easy wins" pass via nuclei (default creds / common misconfigs)
                                          - flag uncommon services for manual follow-up
                                            (e.g. BeanShell, rsync, Java RMI)
```

1. **Scope**: a list of IPs/CIDRs, or the `host` section of a `pipeline`
   JSON config (see [pipeline.md](pipeline.md)). Splits into **included**
   and **excluded** the way a Burp/program scope does.
2. **Excluded hosts are never actively touched.** The only information
   gathered about them is passive: a reverse DNS lookup and a route trace.
   *(Implemented: a `pipeline` `host` entry with `"excluded": true` skips
   `portscan` and the WEB hand-off entirely, running only `ipexpand` ->
   `resolve -reverse` -> `srt traceroute` (a native ICMP route tracer).
   `traceroute` needs a raw socket (`CAP_NET_RAW` or root) to send/receive
   ICMP; without one it's skipped cleanly, same as `vulnx` when that's not
   on `PATH` — never fails the run. IPv4 only for now. `scopecheck` is a
   different check — which hosts/domains resolve *into* scope — not this.)*
3. **Included hosts**:
   - DNS check. *(Implemented: `srt resolve`, wired into `pipeline`'s HOST
     stage as a reverse lookup per discovered IP.)*
   - Port scan, both common and uncommon ports. *(Implemented: `srt
     portscan` — a native TCP connect scanner with `common`/`uncommon`/`all`/
     explicit port specs and a best-effort banner grab, wired into
     `pipeline`'s HOST stage.)*
4. **Services list**: the port scan's output.
   - Web services (a recognized HTTP(S) port) feed straight into the
     **WEB** methodology below instead of a separate host-side web flow —
     one pipeline, reused. *(Implemented: `pipeline`'s HOST stage classifies
     each open port and automatically runs the WEB stage against the ones
     that are web services; `-no-web-handoff` opts out.)*
   - Everything else goes through **"scan"**:
     1. Grab the service's version, then check it against CVE databases —
        this is where **vulnx** gets called. *(Implemented: `portscan`'s
        banner grab feeds a `vulnx search` call — `-p <product>` (e.g. `-p
        openssh`) when the banner matches a recognized service, the
        structured, precise form of vulnx's real CLI (verified against the
        built binary: `vulnx search -p arcgis`), else a free-text search
        over the banner itself. `pipeline`'s HOST stage runs it for every
        non-web port with a banner, skipped cleanly if `vulnx` isn't
        installed.)*
     2. Run an "easy wins" pass: default credentials, common
        misconfigurations. *(Implemented: a direct `nuclei` call --
        `-tags default-login,exposure,misconfig -etags dos,fuzz,intrusive`,
        rate-limited to `-rl 10 -c 3 -bs 1 -timeout 5 -mt 3m` so one
        unattended pipeline step can't turn into an unbounded scan. On by
        default (`options.easyWins:false`/`-no-easy-wins` to disable);
        unlike every other HOST step it sends real probes at the service
        rather than passive recon or a third-party lookup. Skipped cleanly if
        `nuclei` isn't installed.)*
     3. Flag uncommon services for manual follow-up — e.g. an exposed
        BeanShell, rsync daemon, or Java RMI registry. *(Implemented:
        rsync/Java RMI and the rest of `portscan`'s `uncommon` port list are
        flagged by port number; BeanShell has no fixed port, so
        `portscan.IsBeanShellBanner` instead matches its real startup
        banner ("BeanShell &lt;version&gt; - by Pat Niemeyer (pat@pat.net)",
        the same signature nmap's service-probes database uses) against any
        open port's grabbed banner — `pipeline`'s HOST stage flags a match
        as `flag-beanshell`, an unauthenticated-RCE risk.)*

## WEB

```
scope (domains/URLs, or a pipeline JSON config's "web" list)
  -> included / excluded
       included -> find subdomains if allowed (active + passive)
                 -> recon on root + every subdomain
                    (tech-detect, title, status code, content-length, follow-redirects)
                 -> gather endpoints/files:
                      active:  crawl (robots.txt/sitemap-aware), brute force
                               (random/generic wordlists, AND wordlists guessed
                               from the engagement/app context)
                      passive: archived URLs (gau), Google dorking
                 -> test them -> valid endpoints/files
                                   |
                                   +--> parameters: fuzz, guess, or read automatically
                                   |     from a webset/API definition when one exists
                                   +--> sensitive information: classify documents,
                                         flag creds/API keys/etc.
```

1. **Scope**: domains/URLs, or the `web` section of a `pipeline` JSON
   config. Splits into **included**/**excluded** like HOST.
2. **Included** → find subdomains, if the scope allows it, using both
   active and passive techniques → recon the root domain and every
   subdomain found: tech-detect, title, status code, content-length, follow
   redirects (a native httpx-lite). *(Implemented: `srt subdomains` —
   passive via crt.sh certificate transparency logs, active DNS brute force
   (on by default with an embedded wordlist; `-w` to override) — and `srt probe` for recon-on-root
   (title/status/content-length/`Server`/a small tech-detect signature set).
   `pipeline`'s WEB stage runs both automatically ahead of endpoint
   gathering.)*
3. **Gather endpoints/files**, both:
   - **Active**: crawl, robots.txt/sitemap-aware *(implemented: `srt
     robots` fetches robots.txt and the sitemap(s) it declares or
     `/sitemap.xml` — indexes and `.gz` followed, same-host URLs only —
     and probes every path/URL; `srt dirlist`. A real link-following
     crawling is `katana`'s job — see above)*; brute force using random/generic wordlists
     *(implemented: `srt fuzz`)* **and** wordlists guessed from the
     engagement/app context — the target's own naming conventions,
     detected tech stack, anything source-derived (`srt relpaths` already
     builds one kind of context-derived wordlist from unpacked source).
     *(Context-aware *generation* beyond that — e.g. deriving candidates
     from a detected framework or CMS automatically — is not implemented.)*
   - **Passive**: archived URLs *(implemented: `srt gau`)*; Google dorking
     *(not implemented)*.
4. **Test them** → valid endpoints/files. *(Partially implemented: `fuzz`'s
   matcher validates results as it discovers them, but URLs pulled from
   `gau`/dorking aren't re-validated as a distinct step today.)*
5. From the valid endpoints/files list:
   - **Parameters**: fuzz them, guess common ones, or — when a webset/API
     spec is available — read them automatically from that definition.
     *(Partially implemented: `srt params` classifies parameters already
     present in a URL by likely vuln class; actively fuzzing/guessing new
     parameter names, or reading them from an API spec, is not
     implemented.)*
   - **Sensitive information**: classify discovered documents, flag
     credentials/API keys/etc. *(Implemented: `srt sensitive` matches by
     file extension by default; `sensitive -content` instead fetches each
     URL and scans the body against a set of secret/credential signatures
     (AWS/Google/Slack/GitHub/Stripe tokens, private keys, JWTs, connection
     strings, generic key=/secret=/password= assignments including
     camelCase/snake_case key-name variants) — what's actually a credential
     inside a file, not just a filename that looks like one.
     `pipeline`'s WEB stage runs this mode too, via
     `options.contentScan`/`-content-scan` (off by default — fetching every
     URL in a merged `gau` list is real added traffic, unlike filtering by
     extension).)*
