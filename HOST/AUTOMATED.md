Please note that the commands are meant to be thrown in order, first on first

```
#Parsing scope
python3 ipparser.py --scope_file <file> >> scopeips

#Testing HTTP and HTTPS on ports 80 and 443
httpx -title -tech-detect -sc -cl -fr -o httpx_out -l scopeips

#Full TCP scan
sudo naabu -hL scopeips -ports full -exclude-ports 80,443,8080,8443 -Pn -o naabu_out

#Extracting main domains
python3 domain-extracter.py httpx_out >> httpx_out_domains

#Checking that the main domains are in scope
python3 domain-enum.py httpx_out_domains scopeips >> domains

#Finding new subdomains
subfinder -dL domains -o subfinder_out

#Reverse DNS lookup
while read -r ip; do nslookup "$ip" | awk '/name =/ {print $4}' >> reverse_dns_out; done < scopeips

#Checking that the subdomains found are in scope
python3 domain-enum.py subfinder_out scopeips >> subdomains
python3 domain-enum.py reverse_dns_out scopeips >> subdomains

#Enumerating subdomains in scope
httpx -title -tech-detect -sc -cl -fr -o httpx_out_subdomains -l subdomains

#Enumerating HTTP and HTTPS on ports 8080 and 8443
python3 format-ips.py scopeips | httpx -title -tech-detect -sc -cl -fr -o httpx_out_80808443

#Enumerating HTTP and HTTPS on additional ports
httpx -title -tech-detect -sc -cl -fr -o httpx_out_extraports -l naabu_out

#Nmap Scan(slow)
while IFS=: read -r ip port; do echo "Scan results for IP: $ip" >> all_scans.txt; nmap -p "$port" "$ip" >> all_scans.txt; echo -e "\n\n" >> all_scans.txt; done < naabu_out


#FUZZ recursivvely
ffuf -recursion -u <url>/FUZZ -w /usr/share/SecLists-master/Discovery/Web-Content/raft-medium-directories.txt -c -recursion-strategy greedy
```
