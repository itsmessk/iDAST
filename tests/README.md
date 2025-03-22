# Security Scanner Tests

This directory contains individual test scripts for each security scanner component. Each script can be run independently to test specific scanner functionality.

## Running Individual Tests

### SQLMap Scanner Test
```bash
python test_sqlmap_scanner.py
```
Tests SQL injection scanning functionality using known vulnerable URLs.

### Dalfox Scanner Test
```bash
python test_dalfox_scanner.py
```
Tests XSS vulnerability scanning using sample URLs.

### CSRF Scanner Test
```bash
python test_csrf_scanner.py
```
Tests CSRF vulnerability detection on sample web forms.

### SSRF Scanner Test
```bash
python test_ssrf_scanner.py
```
Tests SSRF vulnerability detection using various URL patterns.

## Test URLs
The test scripts use sample URLs from known vulnerable test applications. You can modify the `test_urls` or `test_domains` lists in each script to test against your own targets.

## Logging
All test results are logged to both console and log files in the `logs` directory. Each scanner has its own log file for easy tracking and debugging.

## Important Notes
1. Make sure you have permission to scan the target URLs/domains
2. Some test URLs might be down or change over time
3. Always test against your own controlled environments first
4. Review the logs in the `logs` directory for detailed results
