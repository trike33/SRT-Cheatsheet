#!/usr/bin/python3

import sys
import requests
from urllib.parse import urljoin
import warnings
import re
from colorama import Fore, Style

# Suppress SSL warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
warnings.simplefilter('ignore', InsecureRequestWarning)

# Function to parse robots.txt and extract Disallow and Allow entries
def parse_robots_txt(base_url):
    try:
        response = requests.get(urljoin(base_url, '/robots.txt'), verify=False)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"Failed to fetch robots.txt: {e}")
        sys.exit(1)

    disallow_entries = []
    allow_entries = []
    
    lines = response.text.splitlines()
    for line in lines:
        line = line.strip()
        if line.startswith('Disallow:'):
            disallow_path = line[len('Disallow:'):].strip()
            disallow_entries.append(disallow_path)
        elif line.startswith('Allow:'):
            allow_path = line[len('Allow:'):].strip()
            allow_entries.append(allow_path)

    return allow_entries, disallow_entries

# Function to filter out entries with wildcards
def filter_entries(entries):
    return [entry for entry in entries if '*' not in entry]

# Function to make requests and print colored output
def check_urls(base_url, paths):
    for path in paths:
        full_url = urljoin(base_url, path)
        try:
            response = requests.get(full_url, verify=False)  # Unsecure connection (no cert check)
            status_code = response.status_code
            content_length = len(response.content)
            
            # Output in color
            if status_code == 200:
                print(f"{Fore.GREEN}{full_url} [{status_code}] [{content_length}]{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}{full_url} [{status_code}] [{content_length}]{Style.RESET_ALL}")
        
        except requests.RequestException as e:
            print(f"{Fore.RED}Failed to request {full_url}: {e}{Style.RESET_ALL}")

# Main script function
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <base_url>")
        sys.exit(1)

    base_url = sys.argv[1]
    
    # Parse robots.txt
    allow_entries, disallow_entries = parse_robots_txt(base_url)
    
    # Filter out wildcard entries
    valid_allow_entries = filter_entries(allow_entries)
    valid_disallow_entries = filter_entries(disallow_entries)

    # Check and print status for allowed URLs
    print(f"{Fore.CYAN}--- Checking Allowed URLs ---{Style.RESET_ALL}")
    check_urls(base_url, valid_allow_entries)

    # Check and print status for disallowed URLs
    print(f"{Fore.CYAN}--- Checking Disallowed URLs ---{Style.RESET_ALL}")
    check_urls(base_url, valid_disallow_entries)
