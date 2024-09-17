#!/usr/bin/python3
import json
import re
import sys

def parse_json(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
        
    results = set()  # Using a set to avoid duplicates
    
    # Iterate over the included items in the JSON
    for item in data.get('target', {}).get('scope', {}).get('include', []):
        if item['enabled']:
            # Convert the host regex to a plain hostname
            host = re.sub(r'\\', '', item['host']).replace('^', '').replace('$', '')
            
            # Handle directories and subdirectories
            file_path = re.sub(r'\\', '', item.get('file', '')).replace('^', '').replace('$', '')
            
            # Replace ".*" with "/" only when appropriate
            file_path = file_path.replace('.*', '')
            
            # Combine the host and directory
            full_path = f"{host}{file_path}".rstrip('/')  # Remove trailing slash
            
            results.add(full_path)  # Add to the set to avoid duplicates
    
    return list(results)

# Example usage
if len(sys.argv) != 2:
    print(f"usage: python3 {sys.argv[0]} <json_file>")
    sys.exit(1)

json_file = sys.argv[1]
parsed_results = parse_json(json_file)

# Print the results, only domains with directories/subdirectories
for result in sorted(parsed_results):
    print(result)
