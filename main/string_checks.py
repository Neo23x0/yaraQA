

def analyze_strings(self, rule):
   """
   String checks
   """
   string_issues = []

   # Loop over strings
   if 'strings' in rule:
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