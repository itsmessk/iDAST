import asyncio
import os
import json
import time
import signal
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
import pytz
import logging
import logging.handlers

from flask import Flask, jsonify, request
from flask_cors import CORS

# Import configuration and utility modules
from config import config
from logger import get_logger
from database import db
from utils import ensure_url_has_protocol, extract_domain_from_url, get_current_time, format_timestamp

# Import security scanner modules
from sqlmap_scanner import SQLMapScanner
from dalfox_scanner import DalfoxScanner
from csrf_scanner import CSRFScanner
from ssrf_scanner import SSRFScanner
from subdomain_scanner import subdomain_scanner
from http_security import http_security
from dns_email_security import dns_email_security
from website_health import website_health

# Initialize logger
logger = get_logger('app')

# Initialize Flask application
app = Flask(__name__)
CORS(app)

# Initialize timezones
SERVER_TZ = pytz.timezone(config.SERVER_TIMEZONE)
OUTPUT_TZ = pytz.timezone(config.OUTPUT_TIMEZONE)

class VulnerabilityScanner:
    """Class for orchestrating vulnerability scanning."""
    
    def __init__(self):
        """Initialize the vulnerability scanner with component scanners."""
        self.sqlmap_scanner = SQLMapScanner()
        self.ssrf_scanner = SSRFScanner()
        self.csrf_scanner = CSRFScanner()
        self.dalfox_scanner = DalfoxScanner()
        self.results_dir = config.RESULTS_DIR
        self.setup_folders()
        logger.info("VulnerabilityScanner initialized")
    
    def setup_folders(self):
        """Create necessary folders for scan results."""
        try:
            os.makedirs(self.results_dir, exist_ok=True)
            logger.debug(f"Created results directory: {self.results_dir}")
        except Exception as e:
            logger.error(f"Error creating results directory: {e}")
    
    async def scan(self, domain, paramspider_data, wayback_data):
        """
        Perform vulnerability scanning on a domain using multiple scanners.
        
        Args:
            domain (str): The target domain.
            paramspider_data (dict): Parameter data collected by Paramspider.
            wayback_data (dict): URL data collected by Wayback.
            
        Returns:
            dict: Vulnerability scan results.
        """
        logger.info(f"Starting vulnerability scan for {domain}")
        start_time = time.time()
        
        try:
            # Prepare vulnerability results structure
            vulnerability_results = {
                "data": {},
                "vulnerable": False,
                "scan_summary": {
                    "start_time": format_timestamp(),
                    "completed_scans": [],
                    "failed_scans": []
                }
            }
            
            # Collect all URLs for scanning
            all_urls = []
            
            # Add URLs from Paramspider data
            for subdomain, urls in paramspider_data.items():
                all_urls.extend(urls)
            
            # Add URLs from Wayback data
            for subdomain, urls in wayback_data.items():
                all_urls.extend(urls)
            
            # Remove duplicates
            all_urls = list(set(all_urls))
            logger.info(f"Collected {len(all_urls)} unique URLs for scanning")
            
            # Create tasks for parallel scanning
            sql_task = self._run_sqlmap_scan(all_urls)
            dalfox_task = self._run_dalfox_scan(all_urls)
            csrf_task = self._run_csrf_scan(domain)
            ssrf_task = self._run_ssrf_scan(all_urls)
            
            # Run all scans concurrently
            sql_results, dalfox_results, csrf_results, ssrf_results = await asyncio.gather(
                sql_task, dalfox_task, csrf_task, ssrf_task,
                return_exceptions=True
            )
            
            # Process SQL injection results
            sql_vulnerabilities = []
            if not isinstance(sql_results, Exception) and sql_results:
                for url, result in sql_results.items():
                    if result.get("vulnerable", False):
                        sql_vulnerabilities.append({
                            "url": url,
                            "injection_point": result.get("injection_point", ""),
                            "payload": result.get("payload", ""),
                            "database_type": result.get("database_type", ""),
                            "detection_time": format_timestamp(),
                            "severity": "high",
                            "recommendations": [
                                "Use parameterized queries or prepared statements",
                                "Implement input validation",
                                "Apply principle of least privilege for database users"
                            ]
                        })
                vulnerability_results["scan_summary"]["completed_scans"].append("sql_injection")
            else:
                if isinstance(sql_results, Exception):
                    logger.error(f"SQLMap scan failed: {sql_results}")
                    vulnerability_results["scan_summary"]["failed_scans"].append({
                        "scanner": "sql_injection",
                        "error": str(sql_results)
                    })
            
            # Process Dalfox results
            if not isinstance(dalfox_results, Exception) and dalfox_results:
                vulnerability_results["scan_summary"]["completed_scans"].append("xss")
                vulnerability_results["scan_summary"]["completed_scans"].append("open_redirect")
            else:
                if isinstance(dalfox_results, Exception):
                    logger.error(f"Dalfox scan failed: {dalfox_results}")
                    vulnerability_results["scan_summary"]["failed_scans"].append({
                        "scanner": "xss_open_redirect",
                        "error": str(dalfox_results)
                    })
            
            # Process CSRF results
            csrf_vulnerabilities = []
            if not isinstance(csrf_results, Exception) and csrf_results:
                for form_url, form_results in csrf_results.items():
                    if form_results.get("is_vulnerable", False):
                        csrf_vulnerabilities.append({
                            "url": form_url,
                            "form_action": form_results.get("action", ""),
                            "form_method": form_results.get("method", ""),
                            "missing_protections": form_results.get("missing_protections", []),
                            "detection_time": format_timestamp(),
                            "severity": form_results.get("risk_level", "medium"),
                            "recommendations": form_results.get("recommendations", [])
                        })
                vulnerability_results["scan_summary"]["completed_scans"].append("csrf")
            else:
                if isinstance(csrf_results, Exception):
                    logger.error(f"CSRF scan failed: {csrf_results}")
                    vulnerability_results["scan_summary"]["failed_scans"].append({
                        "scanner": "csrf",
                        "error": str(csrf_results)
                    })
            
            # Process SSRF results
            ssrf_vulnerabilities = []
            if not isinstance(ssrf_results, Exception) and ssrf_results:
                for endpoint in ssrf_results:
                    if endpoint.get("is_vulnerable", False):
                        ssrf_vulnerabilities.append({
                            "url": endpoint.get("url", ""),
                            "parameter": endpoint.get("parameter", ""),
                            "original_value": endpoint.get("original_value", ""),
                            "test_results": endpoint.get("test_results", []),
                            "detection_time": format_timestamp(),
                            "severity": endpoint.get("risk_level", "high"),
                            "recommendations": endpoint.get("recommendations", [])
                        })
                vulnerability_results["scan_summary"]["completed_scans"].append("ssrf")
            else:
                if isinstance(ssrf_results, Exception):
                    logger.error(f"SSRF scan failed: {ssrf_results}")
                    vulnerability_results["scan_summary"]["failed_scans"].append({
                        "scanner": "ssrf",
                        "error": str(ssrf_results)
                    })
            
            # Add results to final output
            if sql_vulnerabilities:
                vulnerability_results["data"]["sql_injection"] = {
                    "status": "Vulnerable",
                    "severity": "high",
                    "details": {
                        "vulnerable_urls": sql_vulnerabilities,
                        "count": len(sql_vulnerabilities)
                    }
                }
                vulnerability_results["vulnerable"] = True
            
            if isinstance(dalfox_results, dict):
                if dalfox_results.get("vulnerabilities", {}).get("xss", []):
                    xss_vulns = dalfox_results["vulnerabilities"]["xss"]
                    vulnerability_results["data"]["xss"] = {
                        "status": "Vulnerable",
                        "severity": "high",
                        "details": {
                            "vulnerable_urls": xss_vulns,
                            "count": len(xss_vulns)
                        }
                    }
                    vulnerability_results["vulnerable"] = True
                
                if dalfox_results.get("vulnerabilities", {}).get("open_redirect", []):
                    redirect_vulns = dalfox_results["vulnerabilities"]["open_redirect"]
                    vulnerability_results["data"]["open_redirect"] = {
                        "status": "Vulnerable",
                        "severity": "medium",
                        "details": {
                            "vulnerable_urls": redirect_vulns,
                            "count": len(redirect_vulns)
                        }
                    }
                    vulnerability_results["vulnerable"] = True
            
            if csrf_vulnerabilities:
                vulnerability_results["data"]["csrf"] = {
                    "status": "Vulnerable",
                    "severity": "high",
                    "details": {
                        "vulnerable_urls": csrf_vulnerabilities,
                        "count": len(csrf_vulnerabilities)
                    }
                }
                vulnerability_results["vulnerable"] = True
            
            if ssrf_vulnerabilities:
                vulnerability_results["data"]["ssrf"] = {
                    "status": "Vulnerable",
                    "severity": "high",
                    "details": {
                        "vulnerable_urls": ssrf_vulnerabilities,
                        "count": len(ssrf_vulnerabilities)
                    }
                }
                vulnerability_results["vulnerable"] = True
            
            # Add scan completion time
            scan_time = time.time() - start_time
            vulnerability_results["scan_summary"]["end_time"] = format_timestamp()
            vulnerability_results["scan_summary"]["duration_seconds"] = round(scan_time, 2)
            
            logger.info(f"Vulnerability scan completed for {domain} in {scan_time:.2f} seconds")
            return vulnerability_results
            
        except Exception as e:
            logger.error(f"Error in vulnerability scanning: {e}")
            return {
                "data": {},
                "vulnerable": False,
                "error": str(e),
                "scan_summary": {
                    "start_time": format_timestamp(),
                    "end_time": format_timestamp(),
                    "duration_seconds": round(time.time() - start_time, 2),
                    "completed_scans": [],
                    "failed_scans": [{"scanner": "all", "error": str(e)}]
                }
            }
    
    async def _run_sqlmap_scan(self, urls):
        """
        Run SQLMap scan on URLs.
        
        Args:
            urls (list): List of URLs to scan.
            
        Returns:
            dict: SQLMap scan results.
        """
        try:
            logger.info(f"Starting SQLMap scan on {len(urls)} URLs")
            return await self.sqlmap_scanner.scan_urls(urls)
        except Exception as e:
            logger.error(f"Error in SQLMap scan: {e}")
            raise
    
    async def _run_dalfox_scan(self, urls):
        """
        Run Dalfox scan on URLs.
        
        Args:
            urls (list): List of URLs to scan.
            
        Returns:
            dict: Dalfox scan results.
        """
        try:
            logger.info(f"Starting Dalfox scan on {len(urls)} URLs")
            # Extract domain from the first URL for Dalfox scanner
            domain = extract_domain_from_url(urls[0]) if urls else "unknown_domain"
            return await self.dalfox_scanner.scan_urls(urls, domain)
        except Exception as e:
            logger.error(f"Error in Dalfox scan: {e}")
            raise
    
    async def _run_csrf_scan(self, domain):
        """
        Run CSRF scan on domain.
        
        Args:
            domain (str): Domain to scan.
            
        Returns:
            dict: CSRF scan results.
        """
        try:
            logger.info(f"Starting CSRF scan on {domain}")
            return await self.csrf_scanner.scan(domain)
        except Exception as e:
            logger.error(f"Error in CSRF scan: {e}")
            raise
    
    async def _run_ssrf_scan(self, urls):
        """
        Run SSRF scan on URLs.
        
        Args:
            urls (list): List of URLs to scan.
            
        Returns:
            list: SSRF scan results.
        """
        try:
            logger.info(f"Starting SSRF scan on {len(urls)} URLs")
            return await self.ssrf_scanner.scan_urls(urls)
        except Exception as e:
            logger.error(f"Error in SSRF scan: {e}")
            raise

# Create a global vulnerability scanner instance
vulnerability_scanner = VulnerabilityScanner()

@app.route('/health')
def health_check():
    """API health check endpoint."""
    return 'OK', 200

@app.route('/scan', methods=['POST'])
async def scan_domain():
    """
    API endpoint to scan a domain for security vulnerabilities.
    
    Expects JSON payload with:
    - domain: Target domain/URL to scan
    - userid: User ID for authentication
    - targetid: Target ID for tracking
    - scan_type: Type of scan (quick or full)
    
    Returns:
    - JSON with scan results
    """
    try:
        # Get request data
        data = request.json
        domain = data.get('domain')
        userid = data.get('userid')
        targetid = data.get('targetid')
        scan_type = data.get('scan_type', 'quick')
        
        if not domain:
            return jsonify({"error": "Domain is required"}), 400
        
        # Process domain/URL
        parsed_url = urlparse(domain)
        domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path
        
        logger.info(f"Starting {scan_type} scan for {domain} (User: {userid}, Target: {targetid})")
        
        # Authentication check (optional based on config)
        if config.ENABLE_AUTH:
            if not userid:
                return jsonify({"error": "User ID is required for authentication"}), 400
                
            user_entry = db.find_user({"userId": userid})
            if not user_entry:
                logger.warning(f"Unauthorized scan attempt by user {userid}")
                return jsonify({"error": "Unauthorized user"}), 403
            
            # Target validation can be added here if needed
        
        # Check for existing target
        if targetid:
            existing_target = db.scan_collection.find_one({'targetId': targetid})
            if existing_target:
                logger.info(f"Target ID {targetid} already exists, will update results")
        
        # Record scan start time
        start_time = get_current_time()
        
        # Initialize scan results structure
        scan_results = {
            "domain": domain,
            "scan_type": scan_type,
            "scan_start_time": format_timestamp(start_time),
            "scan_status": "in_progress",
            "total_subdomains": 0,
            "total_valid_subdomains": 0
        }
        
        # Step 1: Find subdomains (if enabled)
        subdomains = []
        subdomains_with_status = []
        if config.ENABLE_SUBDOMAIN_SCAN:
            subdomains = await subdomain_scanner.find_subdomains(domain)
            logger.info(f"Found {len(subdomains)} subdomains for {domain}")
            
            # Step 2: Check subdomain status
            subdomains_with_status = await subdomain_scanner.check_subdomain_status(subdomains)
            logger.info(f"Validated {len(subdomains_with_status)} active subdomains")
            
            scan_results["total_subdomains"] = len(subdomains)
            scan_results["total_valid_subdomains"] = len(subdomains_with_status)
        
        # Step 3: Fetch URLs (Wayback, Paramspider)
        wayback_data = {}
        paramspider_data = {}
        if subdomains_with_status:
            wayback_data, paramspider_data = await subdomain_scanner.fetch_urls(subdomains_with_status)
            logger.info(f"Collected URLs from {len(wayback_data)} subdomains (Wayback) and {len(paramspider_data)} subdomains (Paramspider)")
        
        # Step 4: Website health check
        health_data = await website_health.check_website_health(f"http://{domain}")
        logger.info(f"Completed health check for {domain}: {health_data.get('overall_status', 'Unknown')}")
        
        # Step 5: Run security checks concurrently
        header_check_task = http_security.check_http_headers(domain)
        client_access_task = http_security.check_client_access_policies(domain)
        security_txt_task = http_security.check_security_txt(domain)
        robots_txt_task = http_security.check_robots_txt(domain)
        email_security_task = dns_email_security.check_email_security(domain)
        csp_check_task = http_security.check_and_store_csp(domain)
        cookie_check_task = http_security.get_cookie_details(domain)
        clickjacking_task = http_security.check_clickjacking_vulnerability(f"http://{domain}")
        accessibility_task = website_health.check_website_accessibility(f"http://{domain}")
        
        # Gather security check results
        (
            header_status_data,
            client_access_policy_status_data,
            security_header_data,
            robots_header_data,
            email_security_data,
            csp_status,
            cookie_details,
            clickjacking_result,
            website_accessibility
        ) = await asyncio.gather(
            header_check_task,
            client_access_task,
            security_txt_task,
            robots_txt_task,
            email_security_task,
            csp_check_task,
            cookie_check_task,
            clickjacking_task,
            accessibility_task
        )
        
        logger.info(f"Completed security checks for {domain}")
        
        # Step 6: Run vulnerability scans (if enabled)
        vulnerability_results = {
            "data": {},
            "vulnerable": False,
            "scan_summary": {
                "start_time": format_timestamp(),
                "completed_scans": [],
                "failed_scans": []
            }
        }
        
        if config.ENABLE_VULNERABILITY_SCAN:
            vulnerability_results = await vulnerability_scanner.scan(domain, paramspider_data, wayback_data)
            logger.info(f"Completed vulnerability scan for {domain}: {'Vulnerable' if vulnerability_results.get('vulnerable', False) else 'Not Vulnerable'}")
        
        # Structure the final output for the JSON
        all_data = {
            "domain": domain,
            "scan_type": scan_type,
            "scan_start_time": format_timestamp(start_time),
            "scan_end_time": format_timestamp(),
            "scan_duration_seconds": (get_current_time() - start_time).total_seconds(),
            "scan_status": "completed",
            "total_subdomains": scan_results["total_subdomains"],
            "total_valid_subdomains": scan_results["total_valid_subdomains"],
            "subdomains": subdomains_with_status,
            "wayback_data": wayback_data,
            "paramspider_data": paramspider_data,
            "website_health": {
                "data": health_data,
                "severity": "info"
            },
            "header_status_data": {
                "data": header_status_data,
                "severity": header_status_data.get("severity", "info")
            },
            "client_access_policy": {
                "data": client_access_policy_status_data,
                "severity": client_access_policy_status_data.get("severity", "info")
            },
            "security_txt": {
                "data": security_header_data,
                "severity": security_header_data.get("severity", "info")
            },
            "robots_txt": {
                "data": robots_header_data,
                "severity": robots_header_data.get("severity", "info")
            },
            "email_security": {
                "data": email_security_data,
                "severity": email_security_data.get("severity", "info")
            },
            "content_security_policy": {
                "data": csp_status,
                "severity": csp_status.get("severity", "info")
            },
            "cookie_security": {
                "data": cookie_details,
                "severity": cookie_details.get("severity", "info")
            },
            "clickjacking": {
                "data": clickjacking_result,
                "severity": clickjacking_result.get("severity", "info")
            },
            "website_accessibility": {
                "data": website_accessibility,
                "severity": "info"
            },
            "vulnerabilities": vulnerability_results
        }
        
        # Store results in database if targetid is provided
        if targetid:
            db_entry = {
                "targetId": targetid,
                "userId": userid,
                "domain": domain,
                "scanType": scan_type,
                "scanDate": format_timestamp(),
                "scanResults": all_data
            }
            
            try:
                # Update or insert scan results
                if existing_target:
                    db.scan_collection.update_one({"targetId": targetid}, {"$set": db_entry})
                    logger.info(f"Updated scan results for target {targetid}")
                else:
                    db.scan_collection.insert_one(db_entry)
                    logger.info(f"Inserted scan results for target {targetid}")
            except Exception as e:
                logger.error(f"Error storing scan results in database: {e}")
        
        logger.info(f"Scan completed for {domain}")
        return jsonify(all_data)
    
    except Exception as e:
        logger.error(f"Error in scan_domain: {e}")
        return jsonify({
            "error": "An error occurred during scanning",
            "details": str(e)
        }), 500

@app.route('/fetch', methods=['POST'])
def fetch_data():
    """
    Fetch scan results for a specific target and user.
    
    Expects JSON payload with:
    - userid: User ID
    - targetid: Target ID
    
    Returns:
    - JSON with scan results
    """
    try:
        data = request.json
        userid = data.get('userid')
        targetid = data.get('targetid')
        
        if not userid or not targetid:
            return jsonify({"error": "User ID and Target ID are required"}), 400
        
        # Find the scan result
        scan_result = db.scan_collection.find_one({
            "userId": userid,
            "targetId": targetid
        })
        
        if not scan_result:
            return jsonify({"error": "Scan result not found"}), 404
        
        # Convert ObjectId to string for JSON serialization
        if '_id' in scan_result:
            scan_result['_id'] = str(scan_result['_id'])
        
        logger.info(f"Fetched scan results for user {userid}, target {targetid}")
        return jsonify(scan_result)
    
    except Exception as e:
        logger.error(f"Error in fetch_data: {e}")
        return jsonify({
            "error": "An error occurred while fetching data",
            "details": str(e)
        }), 500

@app.route('/user', methods=['POST'])
def fetch_user():
    """
    Fetch all scan results for a specific user.
    
    Expects JSON payload with:
    - userid: User ID
    
    Returns:
    - JSON with all user's scan results
    """
    try:
        data = request.json
        userid = data.get('userid')
        
        if not userid:
            return jsonify({"error": "User ID is required"}), 400
        
        # Find all scan results for the user
        scan_results = list(db.scan_collection.find({"userId": userid}))
        
        # Convert ObjectId to string for JSON serialization
        for result in scan_results:
            if '_id' in result:
                result['_id'] = str(result['_id'])
        
        logger.info(f"Fetched {len(scan_results)} scan results for user {userid}")
        return jsonify({"results": scan_results})
    
    except Exception as e:
        logger.error(f"Error in fetch_user: {e}")
        return jsonify({
            "error": "An error occurred while fetching user data",
            "details": str(e)
        }), 500

@app.route('/delete', methods=['DELETE'])
def delete_data():
    """
    Delete scan results for a specific user and target.
    
    Expects JSON payload with:
    - userid: User ID
    - targetid: Target ID
    
    Returns:
    - JSON with deletion status
    """
    try:
        data = request.json
        userid = data.get('userid')
        targetid = data.get('targetid')
        
        if not userid or not targetid:
            return jsonify({"error": "User ID and Target ID are required"}), 400
        
        # Delete the scan result
        result = db.scan_collection.delete_one({
            "userId": userid,
            "targetId": targetid
        })
        
        if result.deleted_count == 0:
            return jsonify({"error": "Scan result not found"}), 404
        
        logger.info(f"Deleted scan result for user {userid}, target {targetid}")
        return jsonify({"success": True, "message": "Scan result deleted successfully"})
    
    except Exception as e:
        logger.error(f"Error in delete_data: {e}")
        return jsonify({
            "error": "An error occurred while deleting data",
            "details": str(e)
        }), 500

@app.route('/delete-bulk', methods=['DELETE'])
def delete_bulk_targets():
    """
    Delete multiple scan results for a specific user.
    
    Expects JSON payload with:
    - userid: User ID
    - targets: Array of target IDs
    
    Returns:
    - JSON with deletion status
    """
    try:
        data = request.json
        userid = data.get('userid')
        targets = data.get('targets', [])
        
        if not userid or not targets:
            return jsonify({"error": "User ID and targets array are required"}), 400
        
        # Delete the scan results
        result = db.scan_collection.delete_many({
            "userId": userid,
            "targetId": {"$in": targets}
        })
        
        logger.info(f"Deleted {result.deleted_count} scan results for user {userid}")
        return jsonify({
            "success": True,
            "message": f"Deleted {result.deleted_count} scan results",
            "deleted_count": result.deleted_count
        })
    
    except Exception as e:
        logger.error(f"Error in delete_bulk_targets: {e}")
        return jsonify({
            "error": "An error occurred while deleting data",
            "details": str(e)
        }), 500

def signal_handler(sig, frame):
    """Handle graceful shutdown on SIGINT/SIGTERM"""
    logger.info("Received shutdown signal. Cleaning up...")
    # Close database connection
    if 'db' in globals():
        db.client.close()
    # Close any open file handles
    sys.stderr.close()
    sys.stdout.close()
    logger.info("Cleanup complete. Shutting down.")
    sys.exit(0)

if __name__ == "__main__":
    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Configure logging with rotation
    log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    log_file = 'logs/security_api.log'
    os.makedirs('logs', exist_ok=True)
    
    # Rotate logs when they reach 10MB, keep 5 backup files
    handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=10*1024*1024, backupCount=5
    )
    handler.setFormatter(log_formatter)
    logger.addHandler(handler)
    
    # Also log to console
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(log_formatter)
    logger.addHandler(console_handler)
    
    logger.setLevel(logging.INFO)
    logger.info("Starting Security Scanner API...")
    
    try:
        app.run(host='0.0.0.0', port=3000, debug=False)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)
