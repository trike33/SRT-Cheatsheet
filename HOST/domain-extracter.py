#!/usr/bin/env python3
import re
import sys

def extract_domains(file_path):
    # Regular expression to match domain names and ignore IP addresses
    domain_pattern = r"https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"

    try:
        with open(file_path, 'r') as file:
            content = file.read()

            # Find all domain names (excluding IPs)
            domains = re.findall(domain_pattern, content)

            # Print extracted domain names
            for domain in domains:
                print(domain)

    except FileNotFoundError:
        print(f"Error: The file '{file_path}' does not exist.")
    except Exception as e:
        print(f"An error occurred: {e}")

# Ensure script is run from the command line with a file argument
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <httpx_out>")
    else:
        extract_domains(sys.argv[1])
