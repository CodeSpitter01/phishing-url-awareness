# EWB Phishing URL Awareness Checker

## Overview

Phishing uses misleading messages and links to trick people into sharing information such as passwords or payment details. This beginner-friendly Python command-line project inspects URL text for six visible warning signs and explains what it notices. It does not open the URL or send information over the internet.

## Features

- Checks for an `@` symbol in the URL text.
- Flags URLs longer than 100 characters.
- Flags IPv4 and IPv6 addresses used as the hostname.
- Flags hostnames with five or more dot-separated segments.
- Flags the `xn--` punycode marker in a hostname.
- Flags the HTTP scheme.
- Repeats checks until the user enters `q`, `quit` or `exit`.
- Prints a `REVIEW CAREFULLY` summary when warning signs are found.
- Handles blank input, missing hostnames and malformed URL formats without terminating unexpectedly.

## Requirements

- Python 3.10 or later.
- No third-party packages are required. The project uses Python's standard library.

## Project structure

```text
phishing-url-awareness/
├── phishing_checker.py
├── README.md
├── requirements.txt
├── tests/
│   ├── test_phishing_checker.py
│   └── test_samples.md
└── screenshots/
    └── README.md
```

## How to run

Open a terminal in the project folder.

**Mac/Linux**

```bash
python3 phishing_checker.py
```

**Windows**

```bash
python phishing_checker.py
```

Enter a sample URL when prompted. The program accepts another URL after each result. Type `q`, `quit` or `exit` to close it.

## Example output

```text
EWB Phishing URL Awareness Checker
Text checks only - this program does not open URLs.
Type q, quit or exit when you are finished.

Enter a sample URL (or type q to quit): http://192.0.2.10/account

Result:
- Uses an IP address instead of a familiar domain.
- Uses HTTP. HTTPS alone does not prove trust.

REVIEW CAREFULLY: 2 warning sign(s) found.
Never enter passwords from unexpected links.
```

## Testing

The five sample inputs prescribed by the workbook and their expected/observed findings are recorded in [`tests/test_samples.md`](tests/test_samples.md).

Run the additional automated test suite from the project root:

```bash
python3 -m unittest discover -s tests -v
```

On Windows, use `python` instead of `python3` if needed.

## Improvements made

1. **Repeat-and-quit mode:** the user can inspect several URLs in one run and exit with `q`, `quit` or `exit`.
2. **Review summary:** when one or more warning signs are detected, the program reports the number found and advises the user to review the URL carefully.
3. **Malformed-input handling:** malformed bracketed IPv6 and whitespace-containing input are handled with a clear message instead of an uncaught parsing error. Empty input and missing hostnames are also handled.
4. **More accurate IP detection:** Python's `ipaddress` standard-library module validates IPv4 and IPv6 literals rather than treating any four groups of digits as a valid IP address.

## Limitations

This is an educational URL-text checker, not a full phishing-detection or reputation service. It checks only the six listed indicators. It does not visit URLs, resolve DNS, inspect website content, scan for malware, query external services or prove that a URL is safe. A URL with no listed warning signs may still be malicious, and a legitimate URL may trigger a warning. HTTPS alone does not prove that a site is trustworthy.

## Ethical use

Use the reserved sample strings in the workbook or other harmless text examples. Do not open suspicious links to test them, collect credentials, send phishing messages or probe websites without written authorization. Do not upload passwords, API keys or confidential information to GitHub.

## Author

**Preet Kapoor**  
**Batch:** AI Powered Cybersecurity  
**GitHub:** [CodeSpitter01](https://github.com/CodeSpitter01)
