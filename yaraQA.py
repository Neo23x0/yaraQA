#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# yaraQA - YARA Rule Analyzer
# Florian Roth
#
# IMPORTANT: Requires plyara
#            Do not install plyara via pip
#            Use https://github.com/plyara/plyara

__version__ = "0.11.0"

import os
import sys
import argparse
import logging
import pprint
import platform

from main.core import YaraQA, read_files

sys.path.insert(0, os.getcwd())


if __name__ == '__main__':
    # Parse Arguments
    parser = argparse.ArgumentParser(description='YARA RULE ANALYZER')
    parser.add_argument('-f', action='append', nargs='+', help='Path to input files (one or more YARA rules, separated by space)',
                        metavar='yara files')
    parser.add_argument('-d', action='append', nargs='+', help='Path to input directory '
                                                               '(YARA rules folders, separated by space)',
                        metavar='yara files')
    parser.add_argument('-o', help="Output file that lists the issues (JSON, default: 'yaraQA-issues.json')", metavar='outfile', default=r'yaraQA-issues.json')
    parser.add_argument('-b', help='Use a issues baseline (issues found and reviewed before) to filter issues', metavar='baseline', default=r'')
    parser.add_argument('-l', help='Minimum level to show (1=informational, 2=warning, 3=critical)', metavar='level', default=1)

    parser.add_argument('--ignore-performance', action='store_true', default=False, help='Suppress performance-related rule issues')
    parser.add_argument('--debug', action='store_true', default=False, help='Debug output')

    args = parser.parse_args()

    print(" ")
    print("                             ____    ___  ")
    print("     __  ______ __________ _/ __ \\  /   | ")
    print("    / / / / __ `/ ___/ __ `/ / / / / /| | ")
    print("   / /_/ / /_/ / /  / /_/ / /_/ / / ___ | ")
    print("   \\__, /\\__,_/_/   \\__,_/\\___\\_\\/_/  |_| ")
    print("  /____/                                  ")
    print(" ")
    print("   Florian Roth, November 2023, %s" % __version__)
    print(" ")
    
    # Create a new logger to log into the command line and a log file name yara-forge.log
    # (only set the level to debug if the debug argument is set)
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG if args.debug else logging.INFO)
    # Set the level of the plyara logger to warning
    logging.getLogger('plyara').setLevel(logging.WARNING)
    logging.getLogger('tzlocal').setLevel(logging.CRITICAL)
    # Create a handler for the command line
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG if args.debug else logging.INFO)
    # Create a handler for the log file
    fh = logging.FileHandler("yara-forge.log")
    fh.setLevel(logging.DEBUG)
    # Create a formatter for the log messages that go to the log file
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    # Create a formatter for the log messages that go to the command line
    formatter_cmd = logging.Formatter('%(message)s')
    # Add the formatter to the handlers
    ch.setFormatter(formatter_cmd)
    fh.setFormatter(formatter)
    # Add the handlers to the logger
    logger.addHandler(ch)
    logger.addHandler(fh)

    # Check the input files and directories
    input_files = []
    # File list
    if args.f:
        for f in args.f[0]:
            if not os.path.exists(f):
                logging.error("[E] Error: input file '%s' doesn't exist" % f)
            else:
                input_files.append(f)
    # Directory list
    elif args.d:
        for d in args.d[0]:
            if not os.path.exists(d):
                logging.error("[E] Error: input directory '%s' doesn't exist" % d)
            else:
                for dirpath, dirnames, files in os.walk(d):
                    for f in files:
                        if ".yar" in f:
                            input_files.append(os.path.join(dirpath, f))
    else:
            
        logging.error("[E] No input files selected")

    logging.debug("NUMBER OF INPUT FILES: %s" % len(input_files))

    # Create yaraQA object
    m = YaraQA()

    # Read files
    logging.info("Reading input files ...")
    rule_sets = read_files(input_files=input_files)
    logging.info("%d rule sets have been found and parsed" % len(rule_sets))

    # Analyze rules
    logging.info("Analyzing rules for issues ...")
    rule_issues = m.analyze_rules(rule_sets)
    logging.info("%d rule issues have been found (all types)" % len(rule_issues))

    # Print rule issues
    if len(rule_issues) > 0:
        # Output file preparation
        outfile = args.o
        # Now show the issues
        num_printed_issues = m.print_issues(rule_issues, outfile, int(args.l), args.b, args.ignore_performance)

        if num_printed_issues > 0:
            sys.exit(1)

    sys.exit(0)
