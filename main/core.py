import sys
import re
import json
import plyara
import hashlib
import binascii
import traceback
import logging
from pprint import pprint

class YaraQA(object):
	
	input_files = []

	def __init__(self):
		"""
		Initialize the object with the files to process
		:param input_files:
		"""
		self.initialize_regular_expressions()

	def initialize_regular_expressions(self):
		# Prepare regular expressions
		self.re_pdb_folder = re.compile(r'^\\.*\.(pdb|PDB)$')
		self.re_pdb = re.compile(r'\.(pdb|PDB)$')
		self.re_filepath_section = re.compile(r'^\\.+\\$')
		self.re_num_of_them = re.compile(r'([\d]) of')
		self.re_at_pos = re.compile(r'(\$[a-zA-Z0-9]{1,50}) at ([^\s]+)')
		self.re_fw_start_chars = re.compile(r'^[\.\)_]')
		self.re_fw_end_chars = re.compile(r'[\(\/\\_-]$')
		self.re_repeating_chars = re.compile(r'^(.)\1{1,}$')
		self.re_condition_fails = re.compile(r'\([\s]?[0-9]{1,3},[\s]?filesize[\s]?[\-]?[0-9]{0,3}[\s]?\)')
		self.re_nocase_save = re.compile(r'[^a-zA-Z]')
		# Some lists
		self.fullword_allowed_1st_segments = [r'\\\\.', r'\\\\device', r'\\\\global', r'\\\\dosdevices', 
			r'\\\\basenamedobjects', r'\\\\?', r'\\?', r'\\\\*', r'\\\\%', r'.?', r'./', '_vba',
			r'\\\\registry', r'\\registry', r'\\systemroot', r'\\\\systemroot', r'.\\',
			r'. ', r'/tmp/', r'/etc/', r'/home/', r'/root/', r'/var/']  # will be applied lower-cased
		self.fullword_allowed_last_segments = [r'*/', r'---', r' //', r';//', r'; //', r'# //', r'ipc$', r'c$', r'admin$']  # will # applied lower-cased
		self.less_avoidable_short_atoms = ['<?', '<%', '<% ', '<?=', 'GET', '%>']
		# Regex Lists
		self.re_fw_allowed_strings = [r'\\\\[a-zA-Z]+']
		self.re_fw_allowed_res = []
		for re_value in self.re_fw_allowed_strings:
			self.re_fw_allowed_res.append(re.compile(re_value))

	def analyze_rules(self, rule_sets):

		# Rule set issues
		rule_set_issues = []

		# Save modules
		save_modules = ['math', 'hash']

		# RULE LOOP ---------------------------------------------------------------
		
		# Rule set analytics ------------------------------------------------------
		number_of_rules = 0
		
		# Detect duplicate rules
		# structure:
		# rule_hashes = {
		#   "c85ff8f582d8ae533f36cde5f01a6f6b": ['Demo_Rule_1', 'Demo_Rule2'],   <-- duplicate
		#   "dfbc4a84f58fa29f2ed38d2b77d71824": ['Demo_Rule_3'],
		# }
		rule_hash_stats = {}

		# Module usage
		# rule_modules = {
		#   "pe": ['Demo_Rule_1', 'Demo_Rule2'], ...   
		#   "elf": ['Demo_Rule_3'],                  <-- only rule using that module = slowing down scan process
		# }
		rule_module_stats = {}

		# Loop over rule sets ------------------------------------------------------
		for rule_set in rule_sets:

			# Increase counter
			number_of_rules += len(rule_set)

			# Loop over rules
			for rule in rule_set:

				# Calculate the rule hash
				rule_hash = calculate_rule_hash(rule)
				
				# Print the generated rule hash
				logging.debug("YARA rule hash: %s" % rule_hash) 

				# Hash statistics
				# Add to rule hash structure for later duplicate checking
				if not rule_hash in rule_hash_stats:
					rule_hash_stats[rule_hash] = []
				rule_hash_stats[rule_hash].append(rule['rule_name'])

				# Module statistics
				if 'imports' in rule: 
					for module in rule['imports']:
						# check if the imported module is actually used in the condition
						module_found = False
						for element in rule['condition_terms']:
							if element.startswith("%s." % module):
								module_found = True
						# only add it to the stats if the rule uses it
						if module_found:
							if not module in rule_module_stats:
								rule_module_stats[module] = []
							rule_module_stats[module].append(rule['rule_name'])

				# Analyze the rule's issues
				analyzed_rule_issues = self.analyze_rule(rule)
				rule_set_issues.extend(analyzed_rule_issues)

		# RULE SET CHECKS -----------------------------------------------------

		# Logical duplicate checks
		for hash_value, rule_names in rule_hash_stats.items():
			# Check if single rule hash was calculated for two or more rules
			if len(rule_names) > 1:
				for rule in rule_names:
					rule_set_issues.append(
						{
							"rule": rule,
							"id": "DU1",
							"issue": "This rule looks like a logical duplicate of one or more other rules in this rule set",
							"element": {
								'duplicate_rules': rule_names,
								},
							"level": 2,
							"type": "logic",
							"recommendation": "Remove all duplicate rules",
						}
					)

		# Module usage checks
		for module_name, rule_names in rule_module_stats.items():
			# Marker
			report_module_issue = False
			num_rules_using_module = len(rule_names)
			# Only a few rules
			if num_rules_using_module < 3 and number_of_rules > 30:
				string_segment = "This rule is the only one using a particular module"
				if num_rules_using_module > 1:
					string_segment = "This rule is one of %d using a particular module" % num_rules_using_module
				report_module_issue = True
			# Only a low percentage
			percentage_using_module = 100 * float(num_rules_using_module) / float(number_of_rules)
			if percentage_using_module < 1:
				string_segment = "This rule is one of only %.2f%% of rules using that module" % percentage_using_module
				report_module_issue = True
			# Report it
			if module_name not in save_modules:
				if report_module_issue:
					for rule in rule_names:
						rule_set_issues.append(
							{
								"rule": rule,
								"id": "MO1",
								"issue": "%s, which slows down the whole scanning process." % string_segment,
								"element": {
									'module': module_name,
									},
								"level": 1,
								"type": "performance",
								"recommendation": "Try to refactor the rules so that they don't require the module.",
							}
						)

		return rule_set_issues
	

	def analyze_rule(self, rule):

		rule_issues = []

		# Some calculations or compositions used in many loops (performance tweak)
		condition_combined = ' '.join(rule['condition_terms'])

		# CONDITION TESTS ###################################################

		# Condition segments that cause performance issues / are very inefficient
		result_re_fail = self.re_condition_fails.search(rule['raw_condition'])
		if result_re_fail:
			rule_issues.append(
				{
					"rule": rule['rule_name'],
					"id": "CF1",
					"issue": "The rule uses a condition that includes a calculation over the full file content (hash, mathematical calculation) or almost the full size of the file",
					"element": {'condition_segment': result_re_fail.group(0)},
					"level": 2,
					"type": "performance",
					"recommendation": "Make sure that the calculation appears last in the condition to make use of the short circuit evaluation. (DON'T: 'math.entropy(500, filesize-500) >= 5.7 and all of them' DO: 'all of them and math.entropy(500, filesize-500) >= 5.7'",
				}
			)

		# Problem : '2 of them' in condition but rule contains only 1 string
		# Reason  : rule will never match
		if 'strings' in rule:
			result_num_of = self.re_num_of_them.search(condition_combined)
			if result_num_of:
				num_of = result_num_of.group(0)
				num = result_num_of.group(1)
				if int(num) > len(rule['strings']):
							rule_issues.append(
								{
									"rule": rule['rule_name'],
									"id": "CE1",
									"issue": "The rule uses a condition that will never match",
									"element": {'condition_segment': num_of, 'num_of_strings': len(rule['strings'])},
									"level": 3,
									"type": "logic",
									"recommendation": "Fix the condition",
								}
							)

		# String at position test
		# Problem : $mz = "MZ" condition: $mz at 0
		# Reason  : the very short string MZ will be searched in a file, which can be huge, causing many matches
		if 'strings' in rule:
			if " at 0" in condition_combined:
				result_at_pos = self.re_at_pos.search(condition_combined)
				if result_at_pos:
					at_pos_string = result_at_pos.group(1)
					at_pos_pos = result_at_pos.group(2)
					at_pos_expression = result_at_pos.group(0)
					for s in rule['strings']:
						if at_pos_string == s['name']:
							if ( s['type'] == "text" and len(s['value']) < 3 ) or \
							( s['type'] == "byte" and len(s['value'].replace(' ', '')) < 7 ):
								# Calculate a fitting replacement
								replacement_string = calculate_uint_replacement(s['value'], s['type'], at_pos_pos)
								# Add the issue
								rule_issues.append(
									{
										"rule": rule['rule_name'],
										"id": "PA1",
										"issue": "This rule looks for a short string at a particular position. A short string represents a short atom and could be rewritten to an expression using uint(x) at position.",
										"element": {
											'condition_segment': at_pos_expression, 
											'string': s['name'], 
											'value': s['value']
											},
										"level": 2,
										"type": "performance",
										"recommendation": "Rewrite as %s" % replacement_string,
									}
								)

		# STRING TESTS ####################################################

		# Loop over strings
		if 'strings' in rule:
			for s in rule['strings']:

				# Some vars (performance tweak)
				string_lower = s['value'].lower()

				# Repeating characters
				if self.re_repeating_chars.search(s['value']):
					rule_issues.append(
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

				# MODIFIER ONLY ISSUES ---------------------------------------

				# Noob modifier use
				if 'modifiers' in s:
					if 'ascii' in s['modifiers'] and 'wide' in s['modifiers'] and 'nocase' in s['modifiers']:
						rule_issues.append(
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

				# Duplicate string tests
				# TODO

				# Short atom test
				# Problem : $ = "ab" ascii fullword
				# Reason  : short atoms can cause longer scan times and blow up memory usage
				if ( s['type'] == "text" and len(s['value']) < 4 ) or \
					( s['type'] == "byte" and len(s['value'].replace(' ', '')) < 9 ):
							set_level = 2
							for v in self.less_avoidable_short_atoms:
								if v == s['value']:
									set_level = 1
							rule_issues.append(
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

				# PDB string wide modifier
				if self.re_pdb.search(s['value']):
					if 'modifiers' in s:
						if 'wide' in s['modifiers']:
							rule_issues.append(
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
							rule_issues.append(
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
							rule_issues.append(
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
								rule_issues.append(
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
								rule_issues.append(
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
								rule_issues.append(
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
							rule_issues.append(
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
							rule_issues.append(
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

		return rule_issues


	def print_issues(self, rule_issues, outfile, min_level, baseline, ignore_performance):

		# Apply some filters
		filtered_issues = []
		# Read a baseline 
		baselined_issues = []
		# Counts
		excluded_count_level = 0
		excluded_count_performance = 0
		excluded_count_baselined = 0
		# Read baselined issues
		if baseline:
			with open(baseline) as json_file:
				baselined_issues = json.load(json_file)
			logging.debug("Read %d issues from the baseline file %s" % (len(baselined_issues), baseline))
		# Now filter the issues
		for issue in rule_issues:
			# Ignore all rules with level lower than minium level
			if min_level > issue['level']:
				excluded_count_level += 1
				continue
			# Ignore performance issues
			if ignore_performance and issue['type'] == "performance":
				excluded_count_performance += 1
				continue
			# Ignore base-lined issues (based on rule name and issue id)
			skip_issue = False
			for bi in baselined_issues:
				if bi['rule'] == issue['rule'] and bi['id'] == issue['id']: 
					skip_issue = True
					excluded_count_baselined += 1
			if skip_issue:
				continue
			# Otherwise add the issue to the filtered list to be printed
			filtered_issues.append(issue)

		# Show excluded counts
		total_excluded_count = excluded_count_level + excluded_count_baselined + excluded_count_performance
		logging.info("%d rules have been excluded from the output (lower level: %d performance issues: %d, baselined issues: %d)" % 
							(total_excluded_count, excluded_count_level, excluded_count_performance, excluded_count_baselined))

		# Print info if issues have been found
		if len(filtered_issues) > 0:
			logging.info("The following issues have been found")
		else:
			if baseline:
				logging.info("No new issues have been found")
			else:
				logging.info("No issues have been found")

		# Print it to the cmdline
		for iid, issue in enumerate(filtered_issues):
			# Print the issue
			logging.warning("ISSUE: %d ID: %s TYPE: %s LEVEL: %s RULE: %s ISSUE: %s ELEMENT: %s RECOMMENDATION: %s" % (
				(iid+1),
				issue['id'],
				issue['type'],
				issue['level'], 
				issue['rule'],
				issue['issue'],
				issue['element'],
				issue['recommendation'],
			))
		
		with open(outfile, 'w') as out_fh:
			out_fh.write(json.dumps(filtered_issues, indent=4))

		return len(filtered_issues)


def read_files(input_files):
	"""
	Reads the YARA input files
	:return:
	"""
	rule_sets = []
	# Loop over input files
	for f in input_files:
		try:
			p = plyara.Plyara()
			file_data = ""
			# Read file
			with open(f, 'r') as fh:
				file_data = fh.read()
			# Skip files without rule
			if 'rule' not in file_data:
				continue
			rule_set = p.parse_string(file_data)
			rule_sets.append(rule_set)
		except Exception as e:
				print("Error parsing YARA rule file '%s'" % f)
				traceback.print_exc()
				sys.exit(1)
	# Return the parsed rules
	return rule_sets

def calculate_rule_hash(rule):
	 """
	 Calculates a hash over the relevant YARA rule content (string contents, sorted condition)
	 Requires a YARA rule object as generated by 'plyara': https://github.com/plyara/plyara
	 :param rule: yara rule object
	 :return hash: generated hash
	 """
	 hash_strings = []
	 m = hashlib.md5()

	 # Adding all string contents to the list
	 if 'strings' in rule:

		  # Loop over strings
		  for s in rule['strings']:

				# String to work with 
				string_value = s['value']
				# List of modifiers
				modifiers = []

				# Byte chains
				if s['type'] == "byte":
					 hash_strings.append(re.sub(r'[^a-fA-F\?0-9]+', '', string_value))

				# Others: strings, regex
				else: 
					 # If modifiers exist, just use them
					 if 'modifiers' in s:
						  modifiers = s['modifiers']
					 # One exception: if no 'wide' modifier is set, add an 'ascii' modifier
					 if not 'wide' in modifiers and not 'ascii' in modifiers:
						  modifiers.append('ascii')
					 # If nocase in list, lowercase the string
					 if 'nocase' in modifiers:
						  string_value = string_value.lower()
					 # Sort all modifiers
					 modifiers = sorted(modifiers)
					 # Now add it to the string to hash
					 hash_strings.append("{0}|{1}".format(string_value, ":".join(modifiers)))

	 # Adding the components of the condition to the list (except the variables)
	 for e in rule['condition_terms']:
		  if not e.startswith("$") and not e.startswith("#"):
				hash_strings.append(e)

	 # Empty
	 if len(hash_strings) == 0:
		  return ""

	 # Generate a hash from the sorted contents
	 hash_strings.sort()
	 #print(hash_strings)
	 m.update("".join(hash_strings).encode("ascii"))
	 return m.hexdigest()


def calculate_uint_replacement(value, value_type, position):
	 """
	 Calculate a unit alternative for a 'string at position' expression 
	 """
	 value_len = len(value)
	 uint_string = "(couldn't transform)"
	 # Transform position to int
	 pos_int = 0
	 if position.startswith("0x"):
		  pos_int = int(position,16)
	 else:
		  try:
				pos_int = int(position)
		  except Exception as e:
				return uint_string

	 # Transform the values
	 if value_len == 1:
		  hex_string = binascii.hexlify(value.encode('utf-8')).decode('utf-8')
		  uint_string = "uint8(%d) == 0x%s" % (pos_int, hex_string)
	 elif value_len == 2:
		  hex_string = binascii.hexlify(value.encode('utf-8')).decode('utf-8')
		  uint_string = "uint16be(%d) == 0x%s" % (pos_int, hex_string)
	 elif value_len == 3:
		  hex_string = binascii.hexlify(value.encode('utf-8')).decode('utf-8')
		  uint_string = "uint16be(%d) == 0x%s and uint8(%d) == 0x%s" % (pos_int, hex_string[:4], pos_int+2, hex_string[2:])
	 elif value_len == 4:
		  hex_string = binascii.hexlify(value.encode('utf-8')).decode('utf-8')
		  uint_string = "uint16be(%d) == 0x%s and uint16be(%d) == 0x%s" % (pos_int, hex_string[:4], pos_int+2, hex_string[4:])
	 return uint_string
