#!/usr/bin/python3

import requests
from bs4 import BeautifulSoup
import sys
import urllib.parse
import argparse
from tqdm import tqdm
import urllib3

# Disable SSL warnings for insecure requests when verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# List of file extensions to exclude (images, gifs, and css files)
EXCLUDED_EXTENSIONS = ['.jpg', '.ttf', '.tif','.jpeg', '.png', '.gif', '.css', '.webp', '.svg', '.woff', '.woff2', '.jpe', '.bmp']

def fetch_directory_content(url):
    """Fetch and parse the content of a directory listing."""
    try:
        response = requests.get(url, verify=False)  # Disable SSL certificate verification
        response.raise_for_status()  # Check if the request was successful
    except requests.exceptions.RequestException as e:
        print(f"Error fetching {url}: {e}", file=sys.stderr)
        return []

    soup = BeautifulSoup(response.text, 'html.parser')
    links = soup.find_all('a')

    directory_contents = []
    for link in links:
        href = link.get('href')
        if href and not href.startswith('?') and href != '/' and not href.startswith('..'):
            # Normalize the URL to prevent duplicate paths
            full_url = urllib.parse.urljoin(url, href)
            directory_contents.append(full_url)

    return directory_contents

def is_file_excluded(file_url):
    """Check if the file should be excluded based on its extension."""
    return any(file_url.lower().endswith(ext) for ext in EXCLUDED_EXTENSIONS)

def list_files_recursive(url, base_url, visited, valid_urls):
    """Recursively list all files within the domain and path of base_url, skipping directories and excluded files."""
    if url in visited:
        return  # Prevent revisiting directories

    visited.add(url)  # Mark this URL as visited
    contents = fetch_directory_content(url)

    if not contents:
        return

    for item in contents:
        # Only process URLs that are within the base URL's domain and path
        if item.startswith(base_url):
            # Only print the item if it is a file (i.e., doesn't end with '/')
            if not item.endswith('/'):
                if not is_file_excluded(item):
                    valid_urls.append(item)  # Add valid file URLs to the list

            # If the item is a subdirectory, continue exploring it
            elif item.endswith('/'):
                list_files_recursive(item, base_url, visited, valid_urls)

def read_url_file(file_path):
    """Read URLs from a file."""
    try:
        with open(file_path, 'r') as f:
            urls = f.read().splitlines()
        return urls
    except FileNotFoundError:
        print(f"File not found: {file_path}", file=sys.stderr)
        return []

def main():
    parser = argparse.ArgumentParser(description="Recursively list files within the same domain and path of directory URLs.")
    parser.add_argument("file_path", help="Path to the file containing directory URLs.")
    args = parser.parse_args()

    urls = read_url_file(args.file_path)

    if not urls:
        print("No URLs to process.")
        return

    visited = set()  # Keep track of visited directories to avoid infinite loops
    valid_urls = []  # List to store valid file URLs

    for url in urls:
        # Use the base URL (without query params, etc.) to restrict output to the same domain and path
        base_url = urllib.parse.urljoin(url, '/')
        # Using tqdm for progress bar
        list_files_recursive(url, base_url, visited, valid_urls)

    # Write valid URLs to a file
    with open('valid_urls.txt', 'w') as file:
        for url in valid_urls:
            file.write(url + '\n')

    print(f"Valid URLs have been written to 'valid_urls.txt'")

if __name__ == "__main__":
    main()
