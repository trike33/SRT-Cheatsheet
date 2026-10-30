# Engagement playbook (manual, external-tool-assisted)

How the `srt` commands chain together on a real bug-bounty engagement. Most
of the HOST methodology, and a good chunk of WEB, now run natively — `srt
pipeline` automates both end to end (see [pipeline.md](pipeline.md),
[methodology.md](methodology.md)). This doc is for chaining things by hand,
and for the parts that still need an external tool: `katana` (JS-aware
crawling), `nuclei` (templated vuln scanning), `dalfox` (XSS), `ffuf` (an
alternative fuzzer) — none of these are replaced natively yet, see
[ROADMAP.md](ROADMAP.md).

(`Automated methodology.md`, `HOST/`, `WEB/` — the original Python-era notes
this was based on — now live in [`legacy/`](../../legacy/) at the repo root.)

## 1. HOST recon (you have an IP/CIDR scope)

Fully native now — this is what `srt pipeline -kind host` automates; chained
by hand it looks like:

```bash
# scope.txt holds IPs and CIDRs
srt ipexpand -l scope.txt > scopeips

# reverse DNS, for context
srt resolve -reverse -l scopeips

# port scan (common + uncommon), with a best-effort banner grab
srt portscan -l scopeips -p common,uncommon -json -o scan.json

# recon-on-root for anything that turned out to be a web port
grep -o '"port":[0-9]*' scan.json  # eyeball which ports came back, or just:
srt probe -l scopeips -o probe_out

# main domains -> keep only the ones that resolve back into scope
srt domains -l probe_out | srt scopecheck -scope scopeips -c 80 > domains

# subdomains (passive + active), kept in scope, then probed
srt subdomains -l domains -w subdomain-wordlist.txt | srt scopecheck -scope scopeips > subs
srt probe -l subs -o probe_subs
```

## 2. WEB recon (you have a Burp scope export)

```bash
# host list for probing/crawling
srt burphosts -l target_scope.json | srt probe -o probe_out
srt burphosts -l target_scope.json | katana -jc -o katana_out   # katana: no native replacement yet

# eyeball the scope (green = in, red = out)
srt burpscope -l target_scope.json
```

## 3. URL mining & triage

```bash
# archived URLs
srt gau -d target.com -sub -o all_urls.txt

# sensitive files worth a look
srt sensitive -l all_urls.txt | srt probe -json -o sensitive_live.json

# parameter triage, one class at a time into the right scanner
srt params -l all_urls.txt -class sqli  | nuclei -tags sqli   # nuclei: no native replacement yet
srt params -l all_urls.txt -class ssrf  | srt probe
srt params -l all_urls.txt -class xss   | dalfox pipe           # dalfox: no native replacement yet
```

## 4. Content discovery (the precise part)

```bash
# open directory indexes -> grab exposed files
echo "https://target/uploads/" | srt dirlist -o listing_loot.txt

# robots.txt paths
srt robots https://target

# scope-aware bruteforce of the whole Burp scope, through Burp, rate-limited
srt fuzz -scope target_scope.json \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -e .php -e .bak \
  -proxy http://127.0.0.1:8080 -rate 20 -recursion -depth 2 -ac \
  -silent -o discovered.txt

# feed discoveries onward (nuclei: no native replacement yet)
cat discovered.txt | srt probe -json -o discovered_probed.json
nuclei -l discovered.txt -silent

# many in-scope hosts at once, interleaved and capped so none is flooded
srt burphosts -l target_scope.json | sed 's#^#https://#; s#$#/FUZZ#' > targets.txt
srt fuzz -tl targets.txt -scope target_scope.json \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -rate 10 -rate-global 150 -hc 15 -c 60 -ac -silent -o discovered.txt
```

See [fuzz.md](fuzz.md) for the full fuzzer guide, and [commands.md](commands.md)
for every flag.

## 5. Version / CVE checks

```bash
# once srt probe's tech-detect (or a portscan banner) tells you a component + version
srt snyk -url "https://security.snyk.io/package/composer/moodle%2Fmoodle" -version 3.7

# vulnx (github.com/projectdiscovery/vulnx) for a broader CVE search
vulnx search "Moodle 3.7" --json

# build a target-specific wordlist from unpacked source, then fuzz with it
srt relpaths ./moodle-src > moodle-paths.txt
srt fuzz -u https://target/FUZZ -w moodle-paths.txt -scope target_scope.json -ac
```

## Notes

- Commands read stdin and write stdout, so insert `tee`, `sort -u`, `grep`,
  `anew`, etc. anywhere in a pipe.
- `gau`, `snyk`, `subdomains` (passive mode), and `probe` reach out to the
  internet (`web.archive.org`, `security.snyk.io`, `crt.sh`, and the targets
  themselves, respectively); `vulnx` talks to ProjectDiscovery's cloud API.
  Everything else only talks to your targets.
- `fuzz -scope` is the safety net: even with aggressive wordlists and recursion,
  it will not send a request your Burp scope excludes.
