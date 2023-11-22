"""
Condition Checks
"""

from .utils import calculate_uint_replacement

def analyze_condition(yaraQA, rule):
	"""
	Analyze the condition of a rule for issues
	"""
	
	# Condition issues
	condition_issues = []
	
	# Some calculations or compositions used in many loops (performance tweak)
	condition_combined = ' '.join(rule['condition_terms'])

	# Condition segments that cause performance issues / are very inefficient
	result_re_fail = yaraQA.re_condition_fails.search(rule['raw_condition'])
	if result_re_fail:
		condition_issues.append(
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

	# If the number of "math." functions in a condition exceeds a threshold, it is likely that the condition is too complex
	# Check the raw condition string for occurrences of math. and count them
	# If the number of occurrences exceeds the threshold, add an issue
	if rule['raw_condition'].count('math.') > 3:
		condition_issues.append(
			{
				"rule": rule['rule_name'],
				"id": "CF2",
				"issue": "The rule uses a condition that includes more than 3 mathematical calculations",
				"element": {'condition_segment': rule['raw_condition']},
				"level": 3,
				"type": "performance",
				"recommendation": "Rewrite the condition to use less mathematical calculations",
			}
		)
	elif rule['raw_condition'].count('math.') > 0:
		condition_issues.append(
			{
				"rule": rule['rule_name'],
				"id": "CF2",
				"issue": "The rule uses a condition that a mathematical calculation, which has a performance impact",
				"element": {'condition_segment': rule['raw_condition']},
				"level": 2,
				"type": "performance",
				"recommendation": "Avoid mathematical calculations in the condition",
			}
		)

	# Problem : '2 of them' in condition but rule contains only 1 string
	# Reason  : rule will never match
	if 'strings' in rule:
		result_num_of = yaraQA.re_num_of_them.search(condition_combined)
		if result_num_of:
			num_of = result_num_of.group(0)
			num = result_num_of.group(1)
			if int(num) > len(rule['strings']):
						condition_issues.append(
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
			result_at_pos = yaraQA.re_at_pos.search(condition_combined)
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
							condition_issues.append(
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

	# Return the found issues
	return condition_issues
