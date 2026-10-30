**1. RECON**

Port scanning(exclude ports 80,443,8080,8443) -> naabu
Service recon -> nmap
Ports 80,443,8080,8443 -> httpx

**2. ENUMERATION**

Find subdomains -> subfinder & amass

Crawl URLs -> katana

Crawl GET params -> paramspider

CVE check -> nuclei

  Wordpress CVE check -> https://github.com/topscoder/nuclei-wordfence-cve

Info disclosures -> gau & `grep -E "\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|zip|tar\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|tar|xz|7zip|p12|pem|key|crt|csr|sh|pl|py|java|class|jar|war|ear|sqlitedb|sqlite3|dbf|db3|accdb|mdb|sqlcipher|gitignore|env|ini|conf|properties|plist|cfg)$"`

*Unauthenticated testing*

XSS -> Dalfox, a bit slow but effective

SQLI -> find a tool capable of mass scanning

HTML injection -> find a tool

SSTI -> find a tool

*Authenticated testing*

Command injection -> find a tool
