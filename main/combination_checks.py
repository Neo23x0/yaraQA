

def analyze_combinations(self, rule):
	"""
	String checks
	"""
	combination_issues = []

	# Loop over strings
	if 'strings' in rule:

		# Run some tests
		combination_issues.extend(substring_test(self, rule))

	return combination_issues


def substring_test(self, rule):
	"""
	Checks if a string is the sub string of another string 
	but only reports this as an issue if the rule has a certain condition
	"""

	test_issues = []

	# Only check if the condition has certain characteristics
	condition_combined = ' '.join(rule['condition_terms'])
	if (not self.re_x_of_them_condition_1.search(condition_combined) and 
		not self.re_x_of_them_condition_2.search(condition_combined)):
		# If the condition doesn't have the characteristics, return
		return test_issues

	# Loop over the strings once and create a list of all strings
	string_list = []
	for s in rule['strings']:
		string_list.append({
			'name': s['name'],
			'value': s['value'],
		})

	for s in rule['strings']:

		# Duplicate strings check
		# Check if the current string is a substring of one of the other strings
		# Problem : $a = "abc" $b = "bc" condition: $a or $b 
		for s2 in string_list:
			if s['value'] in s2['value'] and s['name'] != s2['name']:
				test_issues.append(
					{
						"rule": rule['rule_name'],
						"id": "CS1",
						"issue": "The rule uses a string that is a substring of another string",
						"element": {'string_name': s['name'], 'string_value': s['value'], 'substring': s2},
						"level": 2,
						"type": "logic",
						"recommendation": "Fix the strings and check the condition",
					}
				)

	return test_issues
