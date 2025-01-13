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
		'3.7.2' -> '3.7.2'
	"""
	parts = version.split(".")
	while len(parts) < 3:
		parts.append("0")
	return ".".join(parts[:3])

def check_for_recursion(constraint):
	"""
	Checks if a constraint needs recurion and returns the number of rounds needed to parse it
	"""
	lower_than_count = constraint.count("<")
	greater_than_count = constraint.count(">")

	return lower_than_count+greater_than_count

def find_first_matched(target_chars, string):
	"""
	Find the first character or substring from target_chars that appears in the string.

	Args:
		target_chars (list): A list of characters or substrings to search for.
		string (str): The string to search in.

	Returns:
		str: The first matched character or substring.
		None: If no characters or substrings are matched.
	"""
	# Sort target_chars to check longer substrings first (so '<=' and '>=' are matched before '<' and '>')
	target_chars.sort(key=lambda x: -len(x))  # Sort by length in descending order
	matches = ((char, string.find(char)) for char in target_chars if string.find(char) != -1)

	# Get the first match (smallest index)
	first_match = min(matches, key=lambda x: x[1], default=(None, -1))
	return first_match[0]


def version_extractor(constraint, start_character):
	# Find the start and end positions of the version
	start = constraint.find(start_character) + 1
	end = min(
		(constraint.find(op, start) for op in ("<", ">") if constraint.find(op, start) != -1),
		default=len(constraint)
	)
	version = constraint[start:end].strip()
	version = version.replace("=", "")
	version = version.replace("-beta", "")
	return version

def parse_global_constraints(constraints):
	"""
	Parse constraint strings into a list of tuples.
	Each tuple contains the comparator and the normalized version.
	Examples:
	'<2.4.1' -> ('<', '2.4.1')
	"""
	global_parsed = []
	for constraint in constraints.split(","):
		constraint = constraint.strip()
		local_parsed = []
		rounds = check_for_recursion(constraint)
		target_chars = ["<", ">", "<=", ">="]
		for i in range(rounds):
			result = find_first_matched(target_chars, constraint)
			if result == ">=":
				comparator = ">="
				version = version_extractor(constraint, comparator)
				remove = f"{comparator}{version}"
				local_parsed.append((comparator, normalize_version(version)))
				constraint = constraint.replace(version, "") # we remove to avoid duplicates
			elif result == "<=":
				comparator = "<="
				version = version_extractor(constraint, comparator)
				remove = f"{comparator}{version}"
				local_parsed.append((comparator, normalize_version(version)))
				constraint = constraint.replace(remove, "") #we remove to avoid duplicates
			elif result == ">":
				comparator = ">"
				version = version_extractor(constraint, comparator)
				remove = f"{comparator}{version}"
				local_parsed.append((comparator, normalize_version(version)))
				constraint = constraint.replace(remove, "") #we remove to avoid duplicates
			elif result == "<":
				comparator = "<"
				version = version_extractor(constraint, comparator)
				remove = f"{comparator}{version}"
				local_parsed.append((comparator, normalize_version(version)))
				constraint = constraint.replace(remove, "") #we remove to avoid duplicates
			else:
				print(f"Unkown operand in constraint: {constraint}")
		global_parsed.append(local_parsed)
	return global_parsed

def is_version_allowed(target_version, constraints):
	"""
	Check if a version is allowed under the given constraints.

	Args:
	version (str): The version string to check.
	constraints (list): A list of tuples containing comparator and version strings.

	Returns:
	bool: True if the version is allowed, False otherwise.
	"""
	global_result = True #only set it to true if complies with all constraints
	local_result = True
	for constraint in constraints:
		for comparator, constraint_version in constraint:
			if comparator == "<" and not target_version < constraint_version:
				local_result =  False
				global_result = False
			elif comparator == ">" and not target_version > constraint_version:
				local_result =  False
				global_result = False
			elif comparator == "<=" and not target_version <= constraint_version:
				local_result =  False
				global_result = False
			elif comparator == ">=" and not target_version >= constraint_version:
				local_result =  False
				global_result = False

		"""if local_result:
			print(f"Version {target_version} is inside {constraint}")
		else:
			print(f"Version {target_version} is not inside {constraint}") 
		"""
	return global_result

def check_vulnerabilities(target_version, constraints_string):
	# Parse constraints
	constraints = parse_global_constraints(constraints_string)

	#print("Constraints:", constraints)

	target_version = normalize_version(target_version)
	result = is_version_allowed(target_version, constraints)

	return result

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
