#!/usr/bin/python3
import json
import re
import sys

def parse_json(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
        
    include_set = set()
    exclude_set = set()
    root_domains = set()
    
    # Process the include list
    for item in data.get('target', {}).get('scope', {}).get('include', []):
        if item['enabled']:
            host = re.sub(r'\\', '', item['host']).replace('^', '').replace('$', '')
            if host.startswith('.+'):
                wildcard_host = f"*.{host[3:]}"
                include_set.add(f"{wildcard_host}/*")
            else:
                root_domains.add(f"{host}/*")
    
    # Only add root domain if its wildcard version isn't present
    include_set |= {domain for domain in root_domains if f"*.{domain}" not in include_set}

    # Process the exclude list
    for item in data.get('target', {}).get('scope', {}).get('exclude', []):
        if item['enabled']:
            host = re.sub(r'\\', '', item['host']).replace('^', '').replace('$', '')
            exclude_set.add(f"{host}/*")
    
    return include_set, exclude_set

def format_output(include_set, exclude_set):
    green_output = "\n".join(f"\033[92m{domain}\033[0m" for domain in include_set)
    red_output = "\n".join(f"\033[91m{domain}\033[0m" for domain in exclude_set)
    return f"{green_output}\n{red_output}"

# Example usage
if len(sys.argv) != 2:
	print(f"usage: python3 {sys.argv[0]} <scope_jsonfile>")
	sys.exit(1)

json_file = sys.argv[1]
include_set, exclude_set = parse_json(json_file)
output = format_output(include_set, exclude_set)
print(output)
