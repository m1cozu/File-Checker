# File-Checker

## Overview

**File-Checker** is a robust Python utility designed to enhance your code security by scanning for potential threats in Python and Batch script files. This tool helps you identify and flag risky code patterns, providing essential protection against malicious activities and securing your codebase.

## Key Features

- **Comprehensive Scanning**: Detects dangerous code patterns such as `eval()`, `exec()`, and `os.system()` in Python scripts, and critical commands like `shutdown` and `rmdir` in Batch files.
- **Real-Time Monitoring**: Automatically monitors for changes in specified files, alerting you to modifications that may introduce threats.
- **Detailed Reporting**: Generates a report listing all detected threats and provides the option to delete files identified as containing risks.
- **Logging**: Keeps a log of scanning activities and detected threats for review and auditing.

## Installation

To get started with File-Checker, follow these steps:

1. **Tutorial**

   ```bash
   - Install the zip file
   - move the python file inside the folder what you want to scan
   - Open cmd inside folder and run:
   pip install colorama tqdm watchdog
   - cd File-Checker
   - And lastly run in cmd: python File-Checker.py


   


   
