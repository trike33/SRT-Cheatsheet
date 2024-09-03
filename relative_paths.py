import os
import sys

def get_relative_file_paths(root_dir):
    relative_paths = []
    
    # Walk through the directory and its subdirectories
    for dirpath, _, filenames in os.walk(root_dir):
        for filename in filenames:
            # Construct the relative path and add it to the list
            relative_path = os.path.relpath(os.path.join(dirpath, filename), root_dir)
            relative_paths.append(relative_path)
    
    return relative_paths

# Example usage:
if len(sys.argv) <= 2:
	print(f"usage: {sys.argv[0]} <directory>")
	sys.exit(1)

root_directory = sys.argv[1]  # or specify your directory path here
file_paths = get_relative_file_paths(root_directory)

# Print the relative file paths
for path in file_paths:
    print(path)
