import sys
import re
import json
import hashlib
import traceback
import logging
import plyara
#from pprint import pprint

from .condition_checks import analyze_condition
from .string_checks import analyze_strings
from .combination_checks import analyze_combinations
from .performance_timer import PerformanceTimer

class YaraQA(object):
    """
    YARA QA Object
    """

    input_files = []

    def __init__(self):
        """
        Initialize the object with the files to process
        :param input_files:
        """
        self.initialize_regular_expressions()

        # Create a performance timer object
        self.performance_timer = PerformanceTimer()

    def initialize_regular_expressions(self):
        """
        Initializes the regular expressions
        """
        # Prepare regular expressions
        logging.info("Initializing regular expressions ...")
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
        self.re_short_regex_anchor = re.compile(r'[a-zA-Z0-9_\s\.=\"\']{4,}') # it's not correct but good enough for now
        self.re_x_of_them_condition_1 = re.compile(r'(^|or )([0-9]{1,3}|any|all) of them$')
        self.re_x_of_them_condition_2 = re.compile(r'^([0-9]{1,3}|any|all) of them($| or)')
        # Some lists
        self.fullword_allowed_1st_segments = [r'\\\\.', r'\\\\device', r'\\\\global', r'\\\\dosdevices', 
            r'\\\\basenamedobjects', r'\\\\?', r'\\?', r'\\\\*', r'\\\\%', r'.?', r'./', '_vba',
            r'\\\\registry', r'\\registry', r'\\systemroot', r'\\\\systemroot', r'.\\',
            r'. ', r'/tmp/', r'/etc/', r'/home/', r'/root/', r'/var/', '\t']  # will be applied lower-cased
        self.fullword_allowed_last_segments = [r'*/', r'---', r' //', r';//', r'; //', r'# //', r'ipc$', r'c$', r'admin$']  # will # applied lower-cased
        self.less_avoidable_short_atoms = ['<?', '<%', '<% ', '<?=', 'GET', '%>']
        # Regex Lists
        self.re_fw_allowed_strings = [r'\\\\[a-zA-Z]+']
        self.re_fw_allowed_res = []
        for re_value in self.re_fw_allowed_strings:
            self.re_fw_allowed_res.append(re.compile(re_value))

    def analyze_rules(self, rule_sets):
        """
        Analyzes the rules for issues
        """
        
        logging.info("Analyzing rules for issues ...")

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
                logging.debug("YARA rule hash: %s", rule_hash) 

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
                            if element.startswith(f"{module}."):
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
        for _, rule_names in rule_hash_stats.items():
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
        """
        Analyzes a single rule for issues
        """

        rule_issues = []

        # CONDITION TESTS ###################################################
        condition_issues = analyze_condition(self, rule)
        rule_issues.extend(condition_issues)

        # STRING TESTS ####################################################
        string_issues = analyze_strings(self, rule)
        rule_issues.extend(string_issues)

        # COMBINATION TESTS ###############################################
        combination_issues = analyze_combinations(self, rule)
        rule_issues.extend(combination_issues)

        # PERFORMANCE TESTS ###############################################
        performance_issues = self.analyze_live_rule_performance(rule)
        rule_issues.extend(performance_issues)

        return rule_issues


    def analyze_live_rule_performance(self, rule):
        """
        Analyzes the performance of a rule with live tests.
        """
        performance_issues = []

        # Check if the rule has strings
        if 'strings' not in rule:
            return performance_issues
        # Loop over the strings in the rule
        for s in rule['strings']:
            # Check if the string is a hex string
            if s['type'] == 'regex':
                # Test the performance of the regex
                duration = self.performance_timer.test_regex_performance(s['value'])
                logging.debug("Performance of regex '%s': %f", s['value'], duration)
                if duration > self.performance_timer.threshold:
                    performance_issues.append({
                        "rule": rule['rule_name'],
                        "id": "PI1",
                        "issue": "The regex string has a measurable performance impact",
                        "element": s['value'],
                        "level": 2,
                        "type": "performance",
                        "recommendation": "Use a better performing regex string or replace the regex with a (hex) string",
                    })

        return performance_issues



    def print_issues(self, rule_issues, outfile, min_level, baseline, ignore_performance):
        """
        Prints the issues to the cmdline
        """

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
            with open(baseline, encoding="utf-8") as json_file:
                baselined_issues = json.load(json_file)
            logging.debug("Read %d issues from the baseline file %s", len(baselined_issues), baseline)
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
        logging.info("%d rules have been excluded from the output (lower level: %d performance issues: %d, baselined issues: %d)", 
                        total_excluded_count, excluded_count_level, excluded_count_performance, excluded_count_baselined)

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
            logging.warning("ISSUE: %d ID: %s TYPE: %s LEVEL: %s RULE: %s ISSUE: %s ELEMENT: %s RECOMMENDATION: %s",
                (iid+1),
                issue['id'],
                issue['type'],
                issue['level'], 
                issue['rule'],
                issue['issue'],
                issue['element'],
                issue['recommendation'],
            )
        
        logging.info("Writing %d issues to output file %s", len(filtered_issues), outfile)
        with open(outfile, 'w', encoding="utf-8") as out_fh:
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
            with open(f, 'r', encoding="utf-8") as fh:
                file_data = fh.read()
            # Skip files without rule
            if 'rule' not in file_data:
                continue
            rule_set = p.parse_string(file_data)
            rule_sets.append(rule_set)
        except Exception as e:
            print(f"Error parsing YARA rule file {f} - Error: {e}")
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

