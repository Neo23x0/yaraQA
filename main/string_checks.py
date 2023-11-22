"""
String checks
"""

import string
import binascii

def check_duplicate_strings(self, rule):
	"""
	Check for duplicate strings in the rule
	"""

	test_issues = []

	# Loop over the strings once and create a list of all strings
	string_list = []
	for s in rule['strings']:
		string_list.append({
			'name': s['name'],
			'value': s['value'],
		})

	# Combinations already checked
	strings_reported = []

	# Loop over the strings again and check for duplicates
	for s in rule['strings']:

		# Duplicate strings check
		for s2 in string_list:
			if s['value'] == s2['value'] and s['name'] != s2['name']:
				# Check if the combination has already been reported
				# Modifier string
				modifier_string = ""
				if 'modifiers' in s:
					modifier_string = ":".join(sorted(s['modifiers']))
				string_with_modifiers = f""
				if string_with_modifiers in strings_reported:
					strings_reported.append(string_with_modifiers)
					test_issues.append(
						{
							"rule": rule['rule_name'],
							"id": "DS1",
							"issue": "The rule contains a duplicate string",
							"element": {'string_name': s['name'], 'string_value': s['value']},
							"level": 2,
							"type": "logic",
							"recommendation": "Fix the strings",
						}
					)

	return test_issues

def analyze_strings(self, rule):
	"""
	Analyze the strings of the rules
	"""
	string_issues = []

	# Loop over strings
	if 'strings' in rule:

		# Run some tests that need all strings for the checks
		string_issues.extend(check_duplicate_strings(self, rule))

		# High number of strings check
		# if the number of strings is higher than 40, it's probably a good idea to check the rule

		# Evaluate the number of strings
		string_count = 0
		filter_string_prefixes = ['$filter', '$fp', '$false', '$exclu']
		for s in rule['strings']:
			# if the string name starts with one of the filter string prefixes, don't count it
			if not any(s['name'].startswith(prefix) for prefix in filter_string_prefixes):
				string_count += 1
				
		if string_count > 40:
			string_issues.append(
				{
					"rule": rule['rule_name'],
					"id": "HS2",
					"issue": "The rule contains a very high number of strings.",
					"element": f"Number of rule strings {len(rule['strings'])}",
					"level": 2,
					"type": "resources",
					"recommendation": "Try to reduce the number of strings. Usually rules don't require such a high number of strings to be effective. I know it's hard, but try to sort out strings that are similar or of a similar type (e.g. many error messages, many file paths, many registry keys, etc.).",
				}
			)
		# if the number of strings in a rule is between 20 and 40, it's a warning
		elif string_count > 20:
			string_issues.append(
				{
					"rule": rule['rule_name'],
					"id": "HS1",
					"issue": "The rule contains a high number of strings.",
					"element": f"Number of rule strings {len(rule['strings'])}",
					"level": 1,
					"type": "resources",
					"recommendation": "Try to reduce the number of strings. Usually rules don't require such a high number of strings to be effective. I know it's hard, but try to sort out strings that are similar or of a similar type (e.g. many error messages, many file paths, many registry keys, etc.).",
				}
			)

		# Loop over strings
		for s in rule['strings']:

			# Some vars (performance tweak)
			string_lower = s['value'].lower()

			# Repeating characters
			if self.re_repeating_chars.search(s['value']):
				string_issues.append(
					{
						"rule": rule['rule_name'],
						"id": "SV1",
						"issue": "The rule uses a string that contains a repeating character, which could lead to 'too many strings' errors on large files.",
						"element": s,
						"level": 2,
						"type": "logic",
						"recommendation": "Try to anchor the string with a different character at the beginning or end.",
					}
				)

			# String that is encoded as hex but can be written as text
			if s['type'] == "byte":
				# Define a set of acceptable characters
				acceptable_chars = set(string.ascii_letters + string.digits + string.punctuation + ' ')
				# Remove spaces and braces
				hex_string = s['value'].replace(" ", "").replace("{", "").replace("}", "")
				try:
					# Decode the hex string into bytes
					decoded_bytes = binascii.unhexlify(hex_string)
					# Convert bytes to string using ASCII encoding
					ascii_string = decoded_bytes.decode('ascii')
					# Check if all characters are ASCII
					if all(char in acceptable_chars for char in ascii_string):
						string_issues.append(
							{
								"rule": rule['rule_name'],
								"id": "SV2",
								"issue": "The rule uses a string that is encoded as hex but can be written as text.",
								"element": s,
								"level": 1,
								"type": "style",
								"recommendation": "Write the string as text instead of hex and make it readable. There's absolutely no need to encode it as hex.",
							}
						)
				except binascii.Error:
					pass
				except UnicodeDecodeError:
					pass

			# MODIFIER ONLY ISSUES ---------------------------------------

			# Noob modifier use
			if 'modifiers' in s:
				if 'ascii' in s['modifiers'] and 'wide' in s['modifiers'] and 'nocase' in s['modifiers']:
					string_issues.append(
						{
							"rule": rule['rule_name'],
							"id": "NO1",
							"issue": "The string uses 'ascii', 'wide' and 'nocase' modifier. Are you sure you know what you're doing.",
							"element": s,
							"level": 1,
							"type": "performance",
							"recommendation": "Limit the modifiers to what you actually find in the samples.",
						}
					)

			# STRING ONLY TESTS ------------------------------------------

			# Short atom test
			# Problem : $ = "ab" ascii fullword
			# Reason  : short atoms can cause longer scan times and blow up memory usage
			if ( s['type'] == "text" and len(s['value']) < 4 ) or \
				( s['type'] == "byte" and len(s['value'].replace(' ', '')) < 9 ):
						set_level = 2
						for v in self.less_avoidable_short_atoms:
							if v == s['value']:
								set_level = 1
						string_issues.append(
							{
								"rule": rule['rule_name'],
								"id": "PA2",
								"issue": "The rule contains a string that turns out to be a very short atom, which could cause a reduced performance of the complete rule set or increased memory usage.",
								"element": s,
								"level": set_level,
								"type": "performance",
								"recommendation": "Try to avoid using such short atoms, by e.g. adding a few more bytes to the beginning or the end (e.g. add a binary 0 in front or a space after the string). Every additional byte helps.",
							}
						)

			# Short Regex Anchors
			if s['type'] == "regex":
				if not self.re_short_regex_anchor.search(s['value']):
					string_issues.append(
						{
							"rule": rule['rule_name'],
							"id": "RE1",
							"issue": "The rule contains a regular expression that doesn't use anchors with at least 4 bytes, which could lead to a reduced performance of the complete rule set or increased memory usage.",
							"element": s['value'],
							"level": 2,
							"type": "performance",
							"recommendation": "Add longer anchors or try to write it as a string with at least 4 bytes. (add a line break, binary zero or space at the beginning, if possible)",
						}
					)

			# PDB string wide modifier
			if self.re_pdb.search(s['value']):
				if 'modifiers' in s:
					if 'wide' in s['modifiers']:
						string_issues.append(
							{
								"rule": rule['rule_name'],
								"id": "SM1",
								"issue": "The rule uses a PDB string with the modifier 'wide'. PDB strings are always included as ASCII strings. The 'wide' keyword is unneeded.",
								"element": s,
								"level": 1,
								"type": "logic",
								"recommendation": "Remove the 'wide' modifier",
							}
						)
					if 'wide' in s['modifiers'] and not 'ascii' in s['modifiers']:
						string_issues.append(
							{
								"rule": rule['rule_name'],
								"id": "SM6",
								"issue": "The rule uses a PDB string with the modifier 'wide'. PDB strings are always included as ASCII strings. You should use 'ascii' instead.",
								"element": s,
								"level": 3,
								"type": "logic",
								"recommendation": "Replace the 'wide' modifier with 'ascii'",
							}
						)


			# NOCASE MODIFIER ISSUES --------------------------------------------------------

			# Nocase use
			if 'modifiers' in s:
				if 'nocase' in s['modifiers']:
					if len(s['value']) > 3 and not self.re_nocase_save.search(s['value']):
						string_issues.append(
							{
								"rule": rule['rule_name'],
								"id": "NC1",
								"issue": "The string uses the 'nocase' modifier and does not contain any special characters or digits.",
								"element": s,
								"level": 1,
								"type": "performance",
								"recommendation": "By adding a single character that is not a letter (e.g. space, digit) you can improve the performance of the string significantly.",
							}
						)

			# FULLWORD MODIFIER ISSUES ------------------------------------------------------

			# E.g.
			# Problem : $ = "\\i386\\mimidrv.pdb" ascii fullword
			# Reason  : Rules won't match

			# Fullword in modifiers
			if 'modifiers' in s:
				if 'fullword' in s['modifiers']:

					# Starts with \\ (path)
					if s['value'].startswith(r'\\'):
						is_allowed = False
						for allowed_value in self.fullword_allowed_1st_segments:
							if string_lower.startswith(allowed_value):
								is_allowed = True
						for allowed_value in self.fullword_allowed_last_segments:
							if string_lower.endswith(allowed_value):
								is_allowed = True
						for allowed_re in self.re_fw_allowed_res:
							if allowed_re.search(string_lower):
								is_allowed = True
						if not is_allowed:
							string_issues.append(
								{
									"rule": rule['rule_name'],
									"id": "SM4",
									"issue": "The string seems to look for a segment in a path but uses the 'fullword' modifier, which can lead to a string that doesn't match.",
									"element": s,
									"level": 2,
									"type": "logic",
									"recommendation": "Remove the 'fullword' modifier",
								}
							)

					# Characters at the beginning or end that don't work well with 'fullword'
					if self.re_fw_start_chars.search(s['value']) and s['type'] == "text" and len(s['value']) > 8:
						is_allowed = False
						for allowed_value in self.fullword_allowed_1st_segments:
							if string_lower.startswith(allowed_value):
								is_allowed = True
						if not is_allowed:
							string_issues.append(
								{
									"rule": rule['rule_name'],
									"id": "SM5",
									"issue": "The modifier is 'fullword' but the string seems to start with a character / characters that could be problematic to use with that modifier.",
									"element": s,
									"level": 1,
									"type": "logic",
									"recommendation": "Remove the 'fullword' modifier",
								}
							)
					if self.re_fw_end_chars.search(s['value']) and s['type'] == "text" and len(s['value']) > 6:
						is_allowed = False
						for allowed_value in self.fullword_allowed_last_segments:
							if string_lower.endswith(allowed_value):
								is_allowed = True
						if not is_allowed:
							string_issues.append(
								{
									"rule": rule['rule_name'],
									"id": "SM5",
									"issue": "The modifier is 'fullword' but the string seems to end with a character / characters that could be problematic to use with that modifier.",
									"element": s,
									"level": 2,
									"type": "logic",
									"recommendation": "Remove the 'fullword' modifier",
								}
							)

					# PDB string starts with \\ 
					if self.re_pdb_folder.search(s['value']):
						string_issues.append(
							{
								"rule": rule['rule_name'],
								"id": "SM2",
								"issue": "The rule uses a PDB string with the modifier 'fullword' but it starts with two backslashes and thus the modifier could lead to a dysfunctional rule.",
								"element": s,
								"level": 2,
								"type": "logic",
								"recommendation": "Remove the 'fullword' modifier",
							}
						)

					# File path string
					if self.re_filepath_section.search(s['value']):
						string_issues.append(
							{
								"rule": rule['rule_name'],
								"id": "SM3",
								"issue": "The rule uses a string with the modifier 'fullword' but it starts and ends with two backslashes and thus the modifier could lead to a dysfunctional rule.",
								"element": s,
								"level": 2,
								"type": "logic",
								"recommendation": "Remove the 'fullword' modifier",
							}
						)

	return string_issues