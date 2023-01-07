import sys
import re
import json
import traceback
from pprint import pprint
import plyara

class YaraQA(object):
   
   input_files = []

   def __init__(self, log, debug=False):
      """
      Initialize the object with the files to process
      :param input_files:
      """
      self.debug = debug
      self.log = log

   def readFiles(self, input_files):
      """
      Reads the YARA input files
      :return:
      """
      rule_sets = []
      # Loop over input files
      for f in input_files:
         try:
            self.log.info("Processing %s ..." % f)
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
               self.log.error("Error parsing YARA rule file '%s'" % f)
               traceback.print_exc()
               sys.exit(1)
      # Return the parsed rules
      return rule_sets

   def analyzeRules(self, rule_sets):

      # Rule issues
      rule_issues = []

      # Prepare regular expressions
      re_pdb_folder = re.compile(r'^\\.*\.(pdb|PDB)$')
      re_pdb = re.compile(r'\.(pdb|PDB)$')
      re_filepath_section = re.compile(r'^\\.+\\$')
      re_num_of_them = re.compile(r'([\d]) of')
      re_at_pos = re.compile(r'(\$[a-zA-Z0-9]{1,50}) at ([^\s]+)')
      re_fw_start_chars = re.compile(r'^[\.\)_]')
      re_fw_end_chars = re.compile(r'[\(\/\\_-]$')
      re_repeating_chars = re.compile(r'^(.)\1{1,}$')
      # Some lists
      fullword_allowed_1st_segments = [r'\\\\.', r'\\\\device', r'\\\\global', r'\\\\dosdevices', 
         r'\\\\basenamedobjects', r'\\\\?', r'\\\\*', r'\\\\%', r'.?', r'./', r'\\\\systemroot', '_VBA',
         r'\\\\registry', r'\\systemroot']  # will be applied lower-cased
      fullword_allowed_last_segments = [r'*/', r'---']  # will be applied lower-cased

      # RULE LOOP ---------------------------------------------------------------
      for rule_set in rule_sets:
         for rule in rule_set:
            
            if self.debug:
               pprint(rule)

            # Some calculations or compositions used in many loops (performance tweak)
            condition_combined = ' '.join(rule['condition_terms'])

            # Condition test
            # Problem : '2 of them' in condition but rule contains only 1 string
            # Reason  : rule will never match
            if 'strings' in rule:
               result_num_of = re_num_of_them.search(condition_combined)
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
                  result_at_pos = re_at_pos.search(condition_combined)
                  if result_at_pos:
                     at_pos_string = result_at_pos.group(1)
                     at_pos_expression = result_at_pos.group(0)
                     for s in rule['strings']:
                        if at_pos_string == s['name']:
                           if ( s['type'] == "text" and len(s['value']) < 3 ) or \
                           ( s['type'] == "byte" and len(s['value'].replace(' ', '')) < 7 ):
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
                                    "recommendation": "",
                                 }
                              )

            # Loop over strings
            if 'strings' in rule:
               for s in rule['strings']:

                  # Some vars (performance tweak)
                  string_lower = s['value'].lower()

                  # Repeating characters
                  if re_repeating_chars.search(s['value']):
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

                  # Noob modifier use
                  if 'modifiers' in s:
                     if 'ascii' in s['modifiers'] and 'wide' in s['modifiers'] and 'nocase' in s['modifiers']:
                        rule_issues.append(
                           {
                              "rule": rule['rule_name'],
                              "id": "NO1",
                              "issue": "The string uses 'ascii', 'wide' and 'nocase' modifier. Are you sure you know what you're doing. Please don't drink and write YARA rules.",
                              "element": s,
                              "level": 1,
                              "type": "performance",
                              "recommendation": "Limit the modifiers to what you actually find in the samples.",
                           }
                        )

                  # Short atom test
                  # Problem : $ = "ab" ascii fullword
                  # Reason  : short atoms can cause longer scan times and blow up memory usage
                  if ( s['type'] == "text" and len(s['value']) < 4 ) or \
                     ( s['type'] == "byte" and len(s['value'].replace(' ', '')) < 9 ):
                           rule_issues.append(
                              {
                                 "rule": rule['rule_name'],
                                 "id": "PA2",
                                 "issue": "The rule contains a string that turns out to be a very short atom, which could cause a reduced performance of the complete rule set or increased memory usage.",
                                 "element": s,
                                 "level": 2,
                                 "type": "performance",
                                 "recommendation": "Try to avoid using such short atoms, by e.g. adding a few more bytes to the beginning or the end (e.g. add a binary 0 in front or a space after the string). Every additional byte helps.",
                              }
                           )

                  # PDB string wide modifier
                  if re_pdb.search(s['value']):
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

                  # Fullword string tests
                  # Problem : $ = "\\i386\\mimidrv.pdb" ascii fullword
                  # Reason  : Rules won't match

                  # Fullword in modifiers
                  if 'modifiers' in s:
                     if 'fullword' in s['modifiers']:

                        # Starts with \\ (path)
                        if s['value'].startswith(r'\\'):
                           is_allowed = False
                           for allowed_value in fullword_allowed_1st_segments:
                              if string_lower.startswith(allowed_value):
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
                        if re_fw_start_chars.search(s['value']) and s['type'] == "text" and len(s['value']) > 4:
                           is_allowed = False
                           for allowed_value in fullword_allowed_1st_segments:
                              if string_lower.startswith(allowed_value):
                                 is_allowed = True
                           if not is_allowed:
                              rule_issues.append(
                                 {
                                    "rule": rule['rule_name'],
                                    "id": "SM5",
                                    "issue": "The modifier is 'fullword' but the string seems to start with a character / characters that could be problematic to use with that modifier.",
                                    "element": s,
                                    "level": 2,
                                    "type": "logic",
                                    "recommendation": "Remove the 'fullword' modifier",
                                 }
                              )
                        if re_fw_end_chars.search(s['value']) and s['type'] == "text" and len(s['value']) > 4:
                           is_allowed = False
                           for allowed_value in fullword_allowed_last_segments:
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
                        if re_pdb_folder.search(s['value']):
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
                        if re_filepath_section.search(s['value']):
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

   def printIssues(self, rule_issues, outfile, min_level, baseline, ignore_performance):

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
         if self.debug:
            self.log.info("Read %d issues from the baseline file %s" % (len(baselined_issues), baseline))
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
      self.log.info("%d rules have been excluded from the output (lower level: %d performance issues: %d, baselined issues: %d)" % 
                     (total_excluded_count, excluded_count_level, excluded_count_performance, excluded_count_baselined))

      # Print info if issues have been found
      if len(filtered_issues) > 0:
         self.log.info("The following issues have been found")
      else:
         if baseline:
            self.log.info("No new issues have been found")
         else:
            self.log.info("No issues have been found")

      # Print it to the cmdline
      for iid, issue in enumerate(filtered_issues):
         # Print the issue
         self.log.warning("ISSUE: %d ID: %s TYPE: %s LEVEL: %s RULE: %s ISSUE: %s ELEMENT: %s RECOMMENDATION: %s" % (
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

