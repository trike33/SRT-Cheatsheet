# Engagement playbook

How the `srt` commands chain together on a real bug-bounty engagement, following
the methodology in the repo root (`Automated methodology.md`, `HOST/`, `WEB/`).
`srt` does the glue; `httpx`/`naabu`/`subfinder`/`katana`/`nuclei`/`ffuf` do the
heavy network work.

## 1. HOST recon (you have an IP/CIDR scope)

```bash
# scope.txt holds IPs and CIDRs
srt ipexpand -l scope.txt > scopeips

# web services on 80/443
httpx -l scopeips -title -tech-detect -sc -cl -fr -o httpx_out

# main domains -> keep only the ones that resolve back into scope
srt domains -l httpx_out | srt scopecheck -scope scopeips -c 80 > domains

# subdomains, kept in scope, then probed
subfinder -dL domains -silent | srt scopecheck -scope scopeips > subs
httpx -l subs -title -tech-detect -sc -cl -fr -o httpx_subs

# 8080/8443 everywhere, plus full TCP via naabu
srt ipports -l scopeips | httpx -title -sc -cl -fr -o httpx_alt
naabu -hL scopeips -p - -exclude-ports 80,443,8080,8443 -o naabu_out
```

## 2. WEB recon (you have a Burp scope export)

```bash
# host list for probing/crawling
srt burphosts -l target_scope.json | httpx -title -tech-detect -sc -o httpx_out
srt burphosts -l target_scope.json | katana -jc -o katana_out

# eyeball the scope (green = in, red = out)
srt burpscope -l target_scope.json
```

## 3. URL mining & triage

```bash
# archived URLs
srt gau -d target.com -sub -o all_urls.txt

# sensitive files worth a look
srt sensitive -l all_urls.txt | httpx -silent -mc 200 -o sensitive_live.txt

# parameter triage, one class at a time into the right scanner
srt params -l all_urls.txt -class sqli  | httpx -silent | nuclei -tags sqli
srt params -l all_urls.txt -class ssrf  | httpx -silent
srt params -l all_urls.txt -class xss   | httpx -silent | dalfox pipe
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

# feed discoveries onward
cat discovered.txt | httpx -silent -sc -cl | nuclei -silent

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
# once httpx -tech-detect tells you a component + version
srt snyk -url "https://security.snyk.io/package/composer/moodle%2Fmoodle" -version 3.7

# build a target-specific wordlist from unpacked source, then fuzz with it
srt relpaths ./moodle-src > moodle-paths.txt
srt fuzz -u https://target/FUZZ -w moodle-paths.txt -scope target_scope.json -ac
```

## Notes

- Commands read stdin and write stdout, so insert `tee`, `sort -u`, `grep`,
  `anew`, etc. anywhere in a pipe.
- `gau` and `snyk` reach out to the internet (`web.archive.org`,
  `security.snyk.io`); everything else only talks to your targets.
- `fuzz -scope` is the safety net: even with aggressive wordlists and recursion,
  it will not send a request your Burp scope excludes.
