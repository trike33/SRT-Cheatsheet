#!/usr/bin/env python3
import sys

def format_ips(file_path):
    # List of ports to append to each IP address
    ports = [8080, 8443]

    try:
        with open(file_path, 'r') as file:
            ips = file.readlines()

            # Iterate over each IP in the file
            for ip in ips:
                ip = ip.strip()  # Remove any leading/trailing whitespace

                if ip:  # Check if the line is not empty
                    for port in ports:
                        print(f"{ip}:{port}")
    
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' does not exist.")
    except Exception as e:
        print(f"An error occurred: {e}")

# Ensure script is run from the command line with a file argument
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <file_path>")
    else:
        format_ips(sys.argv[1])
