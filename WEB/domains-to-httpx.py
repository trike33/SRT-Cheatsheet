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
            results.add(host)  # Add to the set
    
    return list(results)

# Example usage
if len(sys.argv) != 2:
	print(f"usage python3 {sys.argv[0]} <json_file>")
	sys.exit(1)
json_file = sys.argv[1]
parsed_results = parse_json(json_file)
for result in parsed_results:
    print(result)
