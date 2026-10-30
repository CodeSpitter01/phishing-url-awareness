# Test Results — EWB Phishing URL Awareness Checker

**Initial verification environment:** Python 3.13.5; Linux x86_64 container used for initial verification.  
**Date of initial verification:** 2026-10-30  
**Important:** These are the results from the initial automated/local verification of the delivered code. Re-run the five inputs on your own Mac before submission and update the environment details and actual-results column if anything differs.

| # | Input | Expected result | Actual result in initial verification | Pass/Fail |
|---|---|---|---|---|
| 1 | `https://www.example.com/login` | No listed warning signs | No listed warning signs found. This does NOT prove safety. | PASS |
| 2 | `http://192.0.2.10/account` | IP address + HTTP | Uses an IP address instead of a familiar domain.; Uses HTTP. HTTPS alone does not prove trust. | PASS |
| 3 | `http://example.com@sample.invalid/login` | @ symbol + HTTP | Contains an @ symbol; inspect carefully.; Uses HTTP. HTTPS alone does not prove trust. | PASS |
| 4 | `https://a.b.c.d.e.example.invalid/path` | Many hostname segments | Contains many hostname segments/subdomains. | PASS |
| 5 | `https://xn--example.invalid/` | Punycode-style hostname | Contains a punycode-style hostname. | PASS |

## Notes

The five workbook examples produce the expected findings. Additional automated checks cover blank input, missing schemes, malformed bracketed IPv6, whitespace, IPv6 literal hosts, missing hostnames, non-string input, warning classification and the repeat-until-quit interaction. The tool only parses text locally; it does not resolve domains or contact websites.

## Re-run the five workbook checks

From the project root, run `python3 phishing_checker.py` (Mac/Linux) or `python phishing_checker.py` (Windows). Enter each sample above separately, recording the exact output. Type `q` to quit.

## Run the automated test suite

```bash
python3 -m unittest discover -s tests -v
```

On Windows, use `python` instead of `python3` if that is the command configured on your system.
