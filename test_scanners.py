import argparse
import json
import sys
import os
from datetime import datetime
from urllib.parse import urlparse

# Import the scanners
from csrf_scanner import CSRFScanner
from ssrf_scanner import SSRFScanner

def test_csrf_scanner(url, verbose=False):
    """
    Test the CSRF scanner on a specific URL
    """
    print(f"\n[+] Testing CSRF Scanner on: {url}")
    
    # Parse domain from URL
    domain = urlparse(url).netloc
    
    # Initialize scanner
    csrf_scanner = CSRFScanner()
    
    try:
        # Run scan
        print(f"[*] Scanning for CSRF vulnerabilities...")
        results, report_file = csrf_scanner.scan_url(url, domain)
        
        # Print summary
        total_forms = len(results.get("forms", []))
        vulnerable_forms = sum(1 for form in results.get("forms", []) if form.get("is_vulnerable", False))
        
        print(f"\n[+] CSRF Scan Results:")
        print(f"    - Total forms found: {total_forms}")
        print(f"    - Vulnerable forms: {vulnerable_forms}")
        print(f"    - Report saved to: {os.path.join(csrf_scanner.results_dir, report_file)}")
        
        # Print detailed results if verbose
        if verbose and vulnerable_forms > 0:
            print("\n[+] Vulnerable Forms Details:")
            for i, form in enumerate([f for f in results.get("forms", []) if f.get("is_vulnerable", False)]):
                print(f"\n    Form #{i+1}:")
                print(f"    - Action: {form.get('action', 'N/A')}")
                print(f"    - Method: {form.get('method', 'N/A')}")
                print(f"    - Risk Level: {form.get('risk_level', 'N/A')}")
                print(f"    - Missing Protections:")
                if not form.get("csrf_protection", {}).get("has_token", False):
                    print(f"      * CSRF Token")
                if not form.get("csrf_protection", {}).get("has_samesite", False):
                    print(f"      * SameSite Cookie")
                if not form.get("csrf_protection", {}).get("has_secure_flag", False):
                    print(f"      * Secure Cookie Flag")
                print(f"    - Recommendations:")
                for rec in form.get("recommendations", []):
                    print(f"      * {rec}")
        
        return True
        
    except Exception as e:
        print(f"[!] Error testing CSRF scanner: {str(e)}")
        return False

def test_ssrf_scanner(url, verbose=False):
    """
    Test the SSRF scanner on a specific URL
    """
    print(f"\n[+] Testing SSRF Scanner on: {url}")
    
    # Parse domain from URL
    domain = urlparse(url).netloc
    
    # Initialize scanner
    ssrf_scanner = SSRFScanner()
    
    try:
        # Run scan
        print(f"[*] Scanning for SSRF vulnerabilities...")
        results, report_file = ssrf_scanner.scan_url(url, domain)
        
        # Print summary
        total_endpoints = results.get("statistics", {}).get("total_endpoints", 0)
        vulnerable_endpoints = results.get("statistics", {}).get("vulnerable_endpoints", 0)
        
        print(f"\n[+] SSRF Scan Results:")
        print(f"    - Total endpoints analyzed: {total_endpoints}")
        print(f"    - Vulnerable endpoints: {vulnerable_endpoints}")
        print(f"    - Report saved to: {os.path.join(ssrf_scanner.results_dir, report_file)}")
        
        # Print detailed results if verbose
        if verbose and vulnerable_endpoints > 0:
            print("\n[+] Vulnerable Endpoints Details:")
            for i, endpoint in enumerate([e for e in results.get("endpoints", []) if e.get("is_vulnerable", False)]):
                print(f"\n    Endpoint #{i+1}:")
                print(f"    - Parameter: {endpoint.get('parameter', 'N/A')}")
                print(f"    - Original Value: {endpoint.get('original_value', 'N/A')}")
                print(f"    - Risk Level: {endpoint.get('risk_level', 'N/A')}")
                print(f"    - Test Results:")
                for test in endpoint.get("test_results", []):
                    print(f"      * {test.get('test', 'N/A')}: {test.get('result', 'N/A')}")
                print(f"    - Recommendations:")
                for rec in endpoint.get("recommendations", []):
                    print(f"      * {rec}")
        
        return True
        
    except Exception as e:
        print(f"[!] Error testing SSRF scanner: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Test CSRF and SSRF scanners individually")
    parser.add_argument("--url", required=True, help="Target URL to scan")
    parser.add_argument("--scanner", choices=["csrf", "ssrf", "both"], default="both", 
                        help="Scanner to test (csrf, ssrf, or both)")
    parser.add_argument("--verbose", action="store_true", help="Show detailed results")
    
    args = parser.parse_args()
    
    print(f"[+] Starting scanner test at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    if args.scanner in ["csrf", "both"]:
        test_csrf_scanner(args.url, args.verbose)
    
    if args.scanner in ["ssrf", "both"]:
        test_ssrf_scanner(args.url, args.verbose)
    
    print(f"\n[+] Testing completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    main()
