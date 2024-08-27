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

*Unauthenticated testing*

XSS -> find a tool capable of mass scanning

SQLI -> find a tool capable of mass scanning

HTML injection -> find a tool

SSTI -> find a tool

*Authenticated testing*

Command injection -> find a tool
