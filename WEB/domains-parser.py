#!/usr/bin/python3
import json
import re
import sys
from collections import defaultdict

def parse_json(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)

    include_dict = defaultdict(list)
    exclude_dict = defaultdict(list)

    # Helper function to clean host and file path, remove special characters
    def clean_host_file(item):
        host = re.sub(r'\\', '', item.get('host', '')).replace('^', '').replace('$', '')
        file_path = re.sub(r'\\', '', item.get('file', '')).replace('^', '').replace('$', '')

        # Replace ".*" with "/*" in file paths for more universal path handling
        file_path = file_path.replace('.*', '/*')

        # Handle wildcard hosts (e.g. "^.+\\.example\\.com$" -> "*.example.com")
        if host.startswith('.+'):
            host = f"*.{host[3:]}"
        
        return host, file_path

    # Process the include list
    for item in data.get('target', {}).get('scope', {}).get('include', []):
        if item.get('enabled', False):  # Safely check for 'enabled' field
            host, file_path = clean_host_file(item)
            include_dict[host].append(file_path)

    # Process the exclude list
    for item in data.get('target', {}).get('scope', {}).get('exclude', []):
        if item.get('enabled', False):
            host, file_path = clean_host_file(item)
            exclude_dict[host].append(file_path)

    return include_dict, exclude_dict

def normalize_path(path):
    """
    Normalizes paths by ensuring they either always have or always don't have a trailing '/*'.
    In this case, we will standardize paths by ensuring they end with '/*'.
    """
    if not path.endswith('/*'):
        return path.rstrip('/') + '/*'
    return path

def domain_without_wildcard(domain):
    """
    Given a domain like *.example.com, return the non-wildcard version (example.com).
    If the domain is already non-wildcard, return it as is.
    """
    if domain.startswith('*.'):
        return domain[2:]
    return domain

def format_output(include_dict, exclude_dict):
    output_lines = []
    seen_paths = set()  # To keep track of already printed paths
    wildcard_domains = set()  # To keep track of wildcard domains (e.g. *.domain.com)

    # Helper function to clean double slashes and check for duplicates
    def clean_and_add(domain, path, color_code):
        # Normalize the path by ensuring it ends with '/*' for consistency
        normalized_path = normalize_path(path)
        
        # Construct the full domain + path
        full_path = f"{domain}{normalized_path}"
        
        # Replace double slashes with single slashes
        cleaned_path = re.sub(r'//+', '/', full_path)

        # Check if the path was already printed (based on normalized form)
        if cleaned_path not in seen_paths:
            seen_paths.add(cleaned_path)  # Mark this path as printed
            output_lines.append(f"{color_code}{cleaned_path}\033[0m")

    # Process include dict (green paths)
    for domain in sorted(include_dict):
        # Check if the domain is a wildcard (e.g., *.domain.com)
        if domain.startswith('*.'):
            wildcard_domains.add(domain_without_wildcard(domain))

        for path in sorted(include_dict[domain]):
            # If we have both the wildcard and non-wildcard version, skip the non-wildcard
            base_domain = domain_without_wildcard(domain)
            if base_domain in wildcard_domains and not domain.startswith('*.'):
                continue  # Skip adding non-wildcard if wildcard exists
            
            clean_and_add(domain, path, "\033[92m")  # Green for include

    # Process exclude dict (red paths)
    for domain in sorted(exclude_dict):
        for path in sorted(exclude_dict[domain]):
            normalized_exclude_path = normalize_path(path)
            if domain not in include_dict or normalized_exclude_path not in [normalize_path(p) for p in include_dict[domain]]:
                clean_and_add(domain, path, "\033[91m")  # Red for exclude

    return "\n".join(output_lines)

# Example usage
if len(sys.argv) != 2:
    print(f"usage: python3 {sys.argv[0]} <scope_jsonfile>")
    sys.exit(1)

json_file = sys.argv[1]
include_dict, exclude_dict = parse_json(json_file)
output = format_output(include_dict, exclude_dict)
print(output)
