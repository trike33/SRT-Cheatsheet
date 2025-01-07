import requests as r
from bs4 import BeautifulSoup
import re
import urllib3
from tabulate import tabulate

#Notes(7/1/2025)
"""
1. All data is on only 1 HTML page
"""

def normalize_version(version):
    """
    Normalize shorthand version inputs to full XX.XX.XX format.
    Examples:
        '3' -> '3.0.0'
        '3.7' -> '3.7.0'
        '3.7.2' -> '3.7.2' (unchanged)
    """
    parts = version.split(".")
    while len(parts) < 3:
        parts.append("0")
    return ".".join(parts[:3])

def parse_constraints(constraints_string):
    """
    Parse a string of constraints into a list of individual constraints.
    Example input: '<3.1.12>=3.2.0, <3.2.9>=3.3.0, <3.3.6>=3.4.0, <3.4.3'
    Output: ['<3.1.12', '>=3.2.0', '<3.2.9', '>=3.3.0', '<3.3.6', '>=3.4.0', '<3.4.3']
    """
    # Split the string by commas and spaces, keeping relational operators intact
    return re.findall(r"[<>]=?\d+\.\d+\.\d+", constraints_string)

def is_valid_version(version):
    """
    Validate the version format XX.XX.XX.
    """
    pattern = r"^\d{1,2}\.\d{1,2}\.\d{1,2}$"
    return bool(re.match(pattern, version))

def compare_versions(version1, version2):
    """
    Compare two valid versions.
    Returns:
        -1 if version1 < version2
         0 if version1 == version2
         1 if version1 > version2
    """
    v1_parts = list(map(int, version1.split(".")))
    v2_parts = list(map(int, version2.split(".")))

    for v1, v2 in zip(v1_parts, v2_parts):
        if v1 < v2:
            return -1
        elif v1 > v2:
            return 1
    return 0

def is_version_vulnerable(version, constraint):
    """
    Check if a version is vulnerable based on a constraint.
    Supports constraints like >=4.4.0, <4.4.4.
    """
    # Parse the constraint
    match = re.match(r"([<>]=?|==)\s*(\d+\.\d+\.\d+)", constraint)
    if not match:
        raise ValueError(f"Invalid constraint format: {constraint}")

    operator, target_version = match.groups()
    if not is_valid_version(version) or not is_valid_version(target_version):
        raise ValueError("Invalid version format. Expected format is XX.XX.XX")

    # Compare the versions
    comparison = compare_versions(version, target_version)

    # Evaluate based on the operator
    if operator == ">=":
        return comparison >= 0
    elif operator == "<=":
        return comparison <= 0
    elif operator == ">":
        return comparison > 0
    elif operator == "<":
        return comparison < 0
    elif operator == "==":
        return comparison == 0
    else:
        raise ValueError(f"Unsupported operator: {operator}")

def check_vulnerabilities(version, constraints_string):
    """
    Check if a version is vulnerable based on constraints stored as a string.
    """
    constraints = parse_constraints(constraints_string)
    for constraint in constraints:
        if is_version_vulnerable(version, constraint):
            return True
    return False

def print_table(headers, data):
	"""
	Helper function to pretty print the results
	"""
	#print(f"\n{headers[0]}{" "*20}{headers[1]}{" "*20}{headers[2]}")
	#print("-" * 90)
	table_entries = []
	for item in data:
		#print(item)
		if len(item) != 0:
			table_entry = []
			severity = item[0][0]
			table_entry.append(severity)
			vulnerability = item[0][1:20]
			table_entry.append(vulnerability)
			#versions = item[1]
			if len(item) == 3:
				link = "https://security.snyk.io"+item[2]
			else:
				link = "Not found"
			table_entry.append(link)
			table_entries.append(table_entry)
			#print(f"{severity}{" "*20}{vulnerability}{" "*20}{link}\n")

	print(tabulate(table_entries, headers=headers, tablefmt="grid"))
	print(f"\nVulnerabilities found >>> {len(data)}")

def main():
	#Global variables
	url = "https://security.snyk.io/package/composer/moodle%2Fmoodle" #change it
	version = "3.7" #change it
	column_headers = ["Severity","Vulnerability", "Link"]
	global_data = []

	urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) #disable unsecure ssl warning
	version = normalize_version(version)

	print(f"URL >>> {url}")
	print(f"Version tested >>> {version}")

	response = r.get(url=url, verify=False)
	if response.status_code == 200:
		soup = BeautifulSoup(response.content, 'lxml')
		table = soup.find('table')
		if table:
			rows = table.find_all("tr")
			for row in rows:
				cells = row.find_all("td")
				cell_data = [cell.text.strip() for cell in cells]

				if len(cell_data) == 0:
					continue

				i = [cell.find("a") for cell in cells]
				for a_tag in i:
					if a_tag and a_tag.has_attr("href") and "vuln" in a_tag["href"]:
						cell_data.append(a_tag["href"])
				
				constraints_string = cell_data[1]
				if not is_valid_version(version):
					print("Invalid input version format. Use the format XX.XX.XX.")
				else:
					if check_vulnerabilities(version, constraints_string):
						global_data.append(cell_data)

			if len(global_data) <= 1:
				print("No vulnerailities found!")
			else:
				print_table(column_headers, global_data)
		else:
			print("table not found!")
	else:
		print(f"Error >>> URL: {url} returned Response code: {response.status_code}")

if __name__ == '__main__':
	main()
