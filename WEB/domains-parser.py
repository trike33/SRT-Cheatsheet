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

    # Process the include list
    for item in data.get('target', {}).get('scope', {}).get('include', []):
        if item['enabled']:
            host = re.sub(r'\\', '', item['host']).replace('^', '').replace('$', '')
            file_path = re.sub(r'\\', '', item.get('file', '')).replace('^', '').replace('$', '')

            # Replace ".*" with "/*" in file paths
            file_path = file_path.replace('.*', '/*')

            # If there's a wildcard host, treat it as such
            if host.startswith('.+'):
                wildcard_host = f"*.{host[3:]}"
                include_dict[wildcard_host].append(file_path)
            else:
                include_dict[host].append(file_path)

    # Process the exclude list
    for item in data.get('target', {}).get('scope', {}).get('exclude', []):
        if item['enabled']:
            host = re.sub(r'\\', '', item['host']).replace('^', '').replace('$', '')
            file_path = re.sub(r'\\', '', item.get('file', '')).replace('^', '').replace('$', '')

            # Replace ".*" with "/*" in file paths for exclusion
            file_path = file_path.replace('.*', '/*')

            exclude_dict[host].append(file_path)

    return include_dict, exclude_dict

def format_output(include_dict, exclude_dict):
    output_lines = []

    # Process include dict
    for domain in sorted(include_dict):
        for path in sorted(include_dict[domain]):
            output_lines.append(f"\033[92m{domain}{path}\033[0m")

    # Process exclude dict
    for domain in sorted(exclude_dict):
        for path in sorted(exclude_dict[domain]):
            output_lines.append(f"\033[91m{domain}{path}\033[0m")

    return "\n".join(output_lines)

# Example usage
if len(sys.argv) != 2:
    print(f"usage: python3 {sys.argv[0]} <scope_jsonfile>")
    sys.exit(1)

json_file = sys.argv[1]
include_dict, exclude_dict = parse_json(json_file)
output = format_output(include_dict, exclude_dict)
print(output)
