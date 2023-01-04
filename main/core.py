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
      re_pdb = re.compile(r'^\\.*\.(pdb|PDB)$')
      re_filepath_section = re.compile(r'^\\.+\\$')
      re_num_of_them = re.compile(r'([\d]) of')

      # RULE LOOP ---------------------------------------------------------------
      for rule_set in rule_sets:
         for rule in rule_set:
            
            # pprint(rule)

            # Condition test
            # Problem : '2 of them' in condition but rule contains only 1 string
            # Reason  : rule will never match
            if 'strings' in rule:
               condition_combined = ' '.join(rule['condition_terms'])
               result_numof = re_num_of_them.search(condition_combined)
               if result_numof:
                  num_of = result_numof.group(0)
                  num = result_numof.group(1)
                  if int(num) > len(rule['strings']):
                           rule_issues.append(
                              {
                                 "rule": rule['rule_name'],
                                 "issue": "The rule uses a condition that will never match",
                                 "element": {'condition_segment': num_of, 'num_of_strings': len(rule['strings'])},
                                 "level": "error",
                                 "type": "logic",
                              }
                           )        

            # Short atom test
            # Problem : $ = "ab" ascii fullword
            # Reason  : short atoms can cause longer scan times and blow up memory usage
            if 'strings' in rule:
               for s in rule['strings']:
                  if ( s['type'] == "text" and len(s['value']) < 3 ) or \
                     ( s['type'] == "byte" and len(s['value'].replace(' ', '')) < 9 ):
                           rule_issues.append(
                              {
                                 "rule": rule['rule_name'],
                                 "issue": "The rule contains a string that turns out to be a very short atom, which could cause a reduced performance of the complete rule set or increased memory usage.",
                                 "element": s,
                                 "level": "warning",
                                 "type": "performance",
                              }
                           )

            # Fullword tests
            # Problem : $ = "\\i386\\mimidrv.pdb" ascii fullword
            # Reason  : Rules won't match
            if 'strings' in rule:
               for s in rule['strings']:

                  # PDB string
                  if re_pdb.search(s['value']):
                     if 'modifiers' in s:
                        if 'fullword' in s['modifiers']:
                           rule_issues.append(
                              {
                                 "rule": rule['rule_name'],
                                 "issue": "The rule uses a PDB string with the modifier 'fullword' but it starts with two backslashes and thus the modifier could lead to a dysfunctional rule.",
                                 "element": s,
                                 "level": "warning",
                                 "type": "logic",
                              }
                           )

                  # File path string
                  if re_filepath_section.search(s['value']):
                     if 'modifiers' in s:
                        if 'fullword' in s['modifiers']:
                           rule_issues.append(
                              {
                                 "rule": rule['rule_name'],
                                 "issue": "The rule uses a string with the modifier 'fullword' but it starts and ends with two backslashes and thus the modifier could lead to a dysfunctional rule.",
                                 "element": s,
                                 "level": "warning",
                                 "type": "logic",
                              }
                           )

      return rule_issues

   def printIssues(self, rule_issues, outfile, as_json, ignore_performance):

      # Apply some filters
      filtered_issues = []
      for issue in rule_issues:
         if ignore_performance and issue['type'] == "performance":
            continue
         filtered_issues.append(issue)

      # Print it to the cmdline
      for iid, issue in enumerate(filtered_issues):
         # Print the issue
         self.log.warning("ID: %d TYPE: %s LEVEL: %s RULE: %s ISSUE: %s ELEMENT: %s" % (
            (iid+1),
            issue['type'],
            issue['level'], 
            issue['rule'],
            issue['issue'],
            issue['element']
         ))
      
      # Write to output file
      # as text
      if not as_json:
         with open(outfile, 'w') as out_fh:
            # Loop over issues
            for iid, issue in enumerate(filtered_issues):
               # Print the issue
               out_fh.write("ID: %d TYPE: %s LEVEL: %s RULE: %s ISSUE: %s ELEMENT: %s\n" % (
                  (iid+1),
                  issue['type'],
                  issue['level'], 
                  issue['rule'],
                  issue['issue'],
                  issue['element']
               ))
      # as JSON
      if as_json:
         with open(outfile, 'w') as out_fh:
            out_fh.write(json.dumps(filtered_issues, indent=4))
