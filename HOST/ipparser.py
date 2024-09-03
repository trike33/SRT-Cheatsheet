import argparse
import ipaddress

def read_scope_file(scope_file):
    """
    Reads a scope file containing IP addresses and CIDR notations, processes them, and returns a list of unique IP addresses.
    
    Args:
        scope_file (str): Path to the file containing IPs and CIDR notations.

    Returns:
        list: A list of unique IP addresses.
    """
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

    return scope_ips

def main():
    parser = argparse.ArgumentParser(description="Process a scope file containing IPs and CIDR notations.")
    parser.add_argument('--scope_file', type=str, required=True, help='Path to the scope file')
    args = parser.parse_args()

    scope_ips = read_scope_file(args.scope_file)

    # Print the processed IPs
    for ip in scope_ips:
        print(ip)

if __name__ == "__main__":
    main()
