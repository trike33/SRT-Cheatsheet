Please note that the commands are meant to be thrown in order, first on first

```
python3 ipparser.py --scope_file <file> >> scopeips

httpx -title -tech-detect -sc -cl -fr -o httpx_out -l scopeips

sudo naabu -hL scopeips -ports full -exclude-ports 80,443,8080,8443 -Pn -o naabu_out

python3 domain-extracter.py httpx_out >> domains

subfinder -dL domains -o subfinder_out

python3 domain-enum.py subfinder_out scopeips >> subdomains

httpx -title -tech-detect -sc -cl -fr -o subdomains_enum -l subdomains
```
