#!/usr/bin/python3

import sys
import socket
import ipaddress

if len(sys.argv) < 3:
    print("(+) first execute subfinder -dL <subdomains_file> -o subdomains")
    print(f"(+) usage: python3 {sys.argv[0]} <subdomains_file> <scope_file>")
    sys.exit(1)

# Necessary variables
subdomains_file = sys.argv[1]
scope_file = sys.argv[2]

# List to hold all IP addresses
scope_ips = []

# Read the scope file
with open(scope_file, 'r') as file:
    scope_entries = file.read().splitlines()

# Process each entry
for entry in scope_entries:
    entry = entry.strip()  # Remove any extra whitespace
    try:
        # Check if the entry is a valid CIDR or IP address
        if '/' in entry:
            # Convert CIDR to individual IP addresses
            network = ipaddress.ip_network(entry, strict=False)
            for ip in network:
                scope_ips.append(str(ip))
        else:
            # Directly add the IP address
            ip = ipaddress.ip_address(entry)
            scope_ips.append(str(ip))
    except ValueError:
        # Skip invalid entries
        print(f"Skipping invalid entry: {entry}")

# Remove duplicates by converting list to a set and back to a list
scope_ips = list(set(scope_ips))
#print("(+) scope read successfully") only for debugging purposes

# Function to resolve subdomains
def resolve_subdomains(subdomains):
    resolved_domains = {}
    for subdomain in subdomains:
        try:
            ip_address = socket.gethostbyname(subdomain)
            resolved_domains[subdomain] = ip_address
        except socket.gaierror:
            resolved_domains[subdomain] = None  # Could not resolve the subdomain
    return resolved_domains

# Read the subdomains file
with open(subdomains_file, 'r') as file:
    subdomains = file.read().splitlines()

# Resolve the subdomains
resolved_subdomains = resolve_subdomains(subdomains)

# Check if any resolved IP matches an IP in scope
for subdomain, ip in resolved_subdomains.items():
    if ip in scope_ips:
        print(subdomain)
