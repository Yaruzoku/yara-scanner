# YARA Scanner

A lightweight GUI and command-line YARA scanning utility for Windows.

YARA Scanner provides a simple interface for scanning individual files or directories with YARA rules, viewing detailed rule matches, inspecting matched strings and metadata, calculating file hashes and entropy, managing rule selections, and exporting scan results to JSON.

> **Disclaimer:** This project is not an original concept. It was created as a learning and personal cybersecurity project, drawing inspiration from existing YARA-based malware analysis and scanning tools. The implementation, interface, and features of this project are my own work.

---

## Features

* Scan individual files or entire directories
* Recursive directory scanning
* YARA rule loading from arbitrary rule directories
* Support for `.yar` and `.yara` rule files
* YARA `include` dependency handling
* Rule tags and metadata
* Rule Management interface
* Individual rule enable/disable selection
* Enable or disable all rules at once
* Rule search and filtering
* Rule state persistence when refreshing rules
* Rule presets for quickly saving and restoring rule configurations
* SHA-256 file hashing
* Shannon entropy calculation
* Basic file type detection
* Matched string and offset information
* File exclusion patterns
* Scan progress information
* Rule statistics
* JSON report generation
* Dark mode
* Command-line interface
* Graphical user interface
* Standalone Windows executable

---

# Graphical Interface

The graphical interface provides a convenient way to configure and run scans without using the command line.

### Rule Management

The Rule Management panel allows individual YARA rules to be controlled before a scan.

Available features include:

* Search and filter loaded rules
* Enable individual rules
* Disable individual rules
* Enable all rules
* Disable all rules
* View rule information and metadata
* Refresh the loaded rule collection
* Preserve enabled/disabled rule state when refreshing

This makes it possible to work with large rule collections without having to run every loaded rule for every scan.

### Rule Presets

Rule configurations can be saved as presets.

A preset stores the enabled/disabled state of the rules, allowing commonly used rule configurations to be quickly restored later.

Presets can be:

* Saved
* Loaded
* Deleted
* Reset to the default rule configuration

This is useful when switching between different rule collections or analysis purposes.

### Dark Mode

The GUI supports dark mode for a more comfortable interface in low-light environments.

---

# Using the Windows Executable

A prebuilt executable can be used without installing Python or the project's Python dependencies.

```text
YaraScanner.exe
```

Launch the executable and use the graphical interface to select:

1. A directory containing YARA rules
2. A file or directory to scan

The rules and scan target can be located anywhere accessible to the system.

### Important

The executable is a security-analysis tool and should still be treated like any other downloaded executable. Verify the source of the executable before running it.

---

# Running from Source

## Requirements

* Python 3.11+ recommended
* YARA Python bindings
* Colorama
* Tkinter for the GUI

Install the Python dependencies:

```powershell
pip install -r requirements.txt
```

Then launch the GUI as a module from the project root:

```powershell
python -m gui.app
```

The command-line scanner can be launched with:

```powershell
python yara-scan.py <rules> <target>
```

For example:

```powershell
python yara-scan.py "C:\YARA Rules" "C:\Samples"
```

---

# Command-Line Usage

```text
yara-scan.py [-h] [-v] [--json] [--output FILE]
             [--exclude PATTERN] [--hash-all] [--quiet]
             [--tag TAG] [--list-rules]
             rules [target]
```

### Basic scan

```powershell
python yara-scan.py "C:\YARA Rules" "C:\Samples"
```

### Verbose output

```powershell
python yara-scan.py "C:\YARA Rules" "C:\Samples" --verbose
```

### Calculate SHA-256 for every scanned file

```powershell
python yara-scan.py "C:\YARA Rules" "C:\Samples" --hash-all
```

### Filter rules by tag

```powershell
python yara-scan.py "C:\YARA Rules" "C:\Samples" --tag malware
```

Multiple tags can be supplied:

```powershell
python yara-scan.py "C:\YARA Rules" "C:\Samples" --tag malware --tag ransomware
```

Tag matching uses **OR** logic.

### Exclude files or directories

```powershell
python yara-scan.py "C:\YARA Rules" "C:\Samples" --exclude "*.log"
```

Multiple exclusion patterns can be used:

```powershell
python yara-scan.py "C:\YARA Rules" "C:\Samples" --exclude "*.log" --exclude temp
```

### JSON output

```powershell
python yara-scan.py "C:\YARA Rules" "C:\Samples" --json
```

Write the JSON report to a file:

```powershell
python yara-scan.py "C:\YARA Rules" "C:\Samples" --json --output report.json
```

### List loaded rules

```powershell
python yara-scan.py "C:\YARA Rules" --list-rules
```

### Quiet mode

```powershell
python yara-scan.py "C:\YARA Rules" "C:\Samples" --quiet
```

Exit codes:

```text
0 = Clean / no matches
1 = Scan error
2 = One or more matches found
```

---

# YARA Rules

The scanner does not require a specific YARA rule collection.

Any compatible `.yar` or `.yara` files can be supplied through the GUI or command line.

Rules using `include` statements are supported, with included rule files resolved relative to the rule file that references them.

For example:

```text
rules/
├── malware.yar
├── common.yar
└── includes/
    └── helpers.yar
```

A rule can reference another file using a normal YARA include:

```yara
include "includes/helpers.yar"
```

---

# JSON Reports

JSON reports contain information including:

* Scanner name and version
* Scan target
* Rule directory
* Applied tags
* Scan start time
* Scan duration
* Number of files found
* Number of files scanned
* Number of excluded files
* Number of matched files
* Number of triggered rules
* Number of failed scans
* Rule statistics
* Individual scan results
* SHA-256 hashes
* Rule metadata
* Matched strings and offsets

---

# Security / Safety

YARA Scanner is intended for **defensive security research, malware analysis, and educational use**.

When analyzing potentially malicious files:

* Use an isolated environment such as a dedicated VM.
* Avoid opening unknown samples directly on your primary system.
* Keep test environments separated from personal data.
* Take appropriate VM snapshots before analysis.
* Be careful when handling live malware samples.

The scanner itself performs static file analysis; it does not attempt to execute scanned samples.

---

# Project Structure

```text
Yara Scanner/
├── yara_scanner/
│   ├── __init__.py
│   ├── scanner.py
│   ├── rules.py
│   └── reporting.py
│
├── gui/
│   └── app.py
│
├── requirements.txt
├── yara-scan.py
└── README.md
```

The YARA rules themselves are **not required to be stored inside this project**. A rule directory can be selected/provided separately when running a scan.

---

# Project Status

This is an ongoing personal cybersecurity project.

Features, detection capabilities, reporting, and the GUI may change as the project develops.
