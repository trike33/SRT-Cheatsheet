import ipaddress
import re
import socket
import os

# --- From ipparser.py ---
def run_ipparser(scope_file_path, output_dir):
    """
    Reads a scope file, parses IPs and CIDR notations, and writes the
    list of unique IP addresses to a file named 'scopeips' in the output directory.
    """
    scope_ips = []
    try:
        with open(scope_file_path, 'r') as file:
            scope_entries = file.read().splitlines()
    except FileNotFoundError:
        return False, f"Scope file not found: {scope_file_path}"

    for entry in scope_entries:
        entry = entry.strip()
        if not entry:
            continue
        try:
            if '/' in entry:
                network = ipaddress.ip_network(entry, strict=False)
                scope_ips.extend(str(ip) for ip in network)
            else:
                ip = ipaddress.ip_address(entry)
                scope_ips.append(str(ip))
        except ValueError:
            print(f"Skipping invalid entry in scope file: {entry}")

    unique_ips = sorted(list(set(scope_ips)))
    
    output_path = os.path.join(output_dir, 'scopeips')
    with open(output_path, 'w') as out_file:
        for ip in unique_ips:
            out_file.write(f"{ip}\n")
            
    return True, f"Successfully created 'scopeips' with {len(unique_ips)} unique IPs."

# --- From domain-extracter.py ---
def run_domain_extracter(input_file_path, output_file_path):
    """
    Extracts domain names from the output of httpx and appends them to a file.
    """
    domain_pattern = r"https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"
    try:
        with open(input_file_path, 'r') as file:
            content = file.read()
    except FileNotFoundError:
        return False, f"Input file not found: {input_file_path}"

    domains = re.findall(domain_pattern, content)
    unique_domains = sorted(list(set(domains)))

    with open(output_file_path, 'a') as out_file:
        for domain in unique_domains:
            out_file.write(f"{domain}\n")
            
    return True, f"Extracted and saved {len(unique_domains)} unique domains."

# --- From format-ips.py ---
def run_format_ips(input_file_path):
    """
    Reads a file of IPs, formats them with ports 8080 and 8443,
    and returns the formatted list as a string.
    This is designed to be piped to another command.
    """
    ports = [8080, 8443]
    formatted_list = []
    try:
        with open(input_file_path, 'r') as file:
            ips = [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        return False, f"Input file not found: {input_file_path}"

    for ip in ips:
        for port in ports:
            formatted_list.append(f"{ip}:{port}")
    
    # Return as a single string with newlines, simulating stdout
    return True, "\n".join(formatted_list)

# --- From domain_enum.py ---
def run_domain_enum(subdomains_file_path, scope_file_path, output_file_path):
    """
    Reads a list of subdomains, resolves them, and appends the ones
    that are within the given scope to an output file.
    """
    # 1. Read and parse the scope file to get a set of allowed IPs
    scope_ips = set()
    try:
        with open(scope_file_path, 'r') as file:
            ips = [line.strip() for line in file if line.strip()]
            scope_ips.update(ips)
    except FileNotFoundError:
        return False, f"Scope file not found: {scope_file_path}"

    # 2. Read the subdomains to check
    try:
        with open(subdomains_file_path, 'r') as file:
            subdomains = [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        return False, f"Subdomains file not found: {subdomains_file_path}"

    # 3. Resolve subdomains and check against scope
    in_scope_domains = []
    for subdomain in subdomains:
        try:
            ip_address = socket.gethostbyname(subdomain)
            if ip_address in scope_ips:
                in_scope_domains.append(subdomain)
        except socket.gaierror:
            # Could not resolve, so it can't be in scope.
            continue
    
    # 4. Append the results to the output file
    with open(output_file_path, 'a') as out_file:
        for domain in in_scope_domains:
            out_file.write(f"{domain}\n")
            
    return True, f"Found and saved {len(in_scope_domains)} domains in scope."
