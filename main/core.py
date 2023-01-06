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
                                 "level": "error",
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
                                    "level": "warning",
                                    "type": "performance",
                                    "recommendation": "",
                                 }
                              )

            # Short atom test
            # Problem : $ = "ab" ascii fullword
            # Reason  : short atoms can cause longer scan times and blow up memory usage
            if 'strings' in rule:
               for s in rule['strings']:
                  if ( s['type'] == "text" and len(s['value']) < 4 ) or \
                     ( s['type'] == "byte" and len(s['value'].replace(' ', '')) < 9 ):
                           rule_issues.append(
                              {
                                 "rule": rule['rule_name'],
                                 "id": "PA2",
                                 "issue": "The rule contains a string that turns out to be a very short atom, which could cause a reduced performance of the complete rule set or increased memory usage.",
                                 "element": s,
                                 "level": "warning",
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
                                 "level": "info",
                                 "type": "logic",
                                 "recommendation": "Remove the 'wide' modifier",
                              }
                           )

                  # Fullword PDB string tests
                  # Problem : $ = "\\i386\\mimidrv.pdb" ascii fullword
                  # Reason  : Rules won't match

                  # PDB string starts with \\ 
                  if re_pdb_folder.search(s['value']):
                     if 'modifiers' in s:
                        if 'fullword' in s['modifiers']:
                           rule_issues.append(
                              {
                                 "rule": rule['rule_name'],
                                 "id": "SM2",
                                 "issue": "The rule uses a PDB string with the modifier 'fullword' but it starts with two backslashes and thus the modifier could lead to a dysfunctional rule.",
                                 "element": s,
                                 "level": "warning",
                                 "type": "logic",
                                 "recommendation": "Remove the 'fullword' modifier",
                              }
                           )

                  # File path string
                  if re_filepath_section.search(s['value']):
                     if 'modifiers' in s:
                        if 'fullword' in s['modifiers']:
                           rule_issues.append(
                              {
                                 "rule": rule['rule_name'],
                                 "id": "SM3",
                                 "issue": "The rule uses a string with the modifier 'fullword' but it starts and ends with two backslashes and thus the modifier could lead to a dysfunctional rule.",
                                 "element": s,
                                 "level": "warning",
                                 "type": "logic",
                                 "recommendation": "Remove the 'fullword' modifier",
                              }
                           )

      return rule_issues

   def printIssues(self, rule_issues, outfile, baseline, ignore_performance):

      # Apply some filters
      filtered_issues = []
      # Read a baseline 
      baselined_issues = []
      if baseline:
         with open(baseline) as json_file:
            baselined_issues = json.load(json_file)
         if self.debug:
            self.log.info("Read %d issues from the baseline file %s" % (len(baselined_issues), baseline))
      # Now filter the issues
      for issue in rule_issues:
         # Ignore performance issues
         if ignore_performance and issue['type'] == "performance":
            continue
         # Ignore base-lined issues (based on rule name and issue id)
         skip_issue = False
         for bi in baselined_issues:
            if bi['rule'] == issue['rule'] and bi['id'] == issue['id']: 
               skip_issue = True 
         if skip_issue:
            continue
         # Otherwise add the issue to the filtered list to be printed
         filtered_issues.append(issue)

      # Print it to the cmdline
      for iid, issue in enumerate(filtered_issues):
         # Print the issue
         self.log.warning("ID: %d TYPE: %s LEVEL: %s RULE: %s ISSUE: %s ELEMENT: %s RECOMMENDATION: %s" % (
            (iid+1),
            issue['type'],
            issue['level'], 
            issue['rule'],
            issue['issue'],
            issue['element'],
            issue['recommendation'],
         ))
      
      with open(outfile, 'w') as out_fh:
         out_fh.write(json.dumps(filtered_issues, indent=4))

