**RECON**

*Parsing IPs*

Download the scope file(IP for line). Then use the `ipparser.py` script to convert CIDR notations to raw IPs:

`python3 ipparser.py --scope_file scope >> scopeips`

*Detecting & enumerating Webservices*

[httpx](https://github.com/projectdiscovery/httpx)
 
`httpx -status-code -title -tech-detect -l scopeips -o host_recon -fr`

Additional webservices on uncommon ports:

`httpx -status-code -titcle -tech-detect -l <portnumberhosts> http:<uncommonport,https:<uncommonport>`

Example for port 9090:

`grep "9090" allPorts | awk '{print $2}' > 9090_hosts` -> first grep on nmap 

`httpx -status-code -title -tech-detect -p http:9090,https:9090 -l 9090_hosts -o 9090tcp_recon` -> try HTTP/HTTPS connections

*Detecting additional services*

`sudo nmap -sS --top-ports 500 -iL scopeips -Pn --open -n --exclude-ports 80,443,8080,8443 -oG allPorts`

Now you can work with the `allPorts` file as you need.
