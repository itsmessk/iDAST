import os
import subprocess
import json
import urllib.parse
import re
import logging
import time
from datetime import datetime

class SQLMapScanner:
    def __init__(self):
        self.results_dir = "results"
        if not os.path.exists(self.results_dir):
            os.makedirs(self.results_dir)
            logging.info("Created results folder")

    def extract_sqlmap_details(self, log):
        """Extract and parse SQLMap scan details from log."""
        summary = {
            "parameters": [],
            "waf_detected": False,
            "end_results": {
                "dbms": None,
                "server_os": None,
                "web_technology": None,
                "injection_details": []
            }
        }

        # Regular expressions for parsing
        patterns = {
            "dbms": re.compile(r"back-end DBMS: (.+)"),
            "os": re.compile(r"web server operating system: (.+)"),
            "tech": re.compile(r"web application technology: (.+)"),
            "parameter": re.compile(r"Parameter: (\w+) $$GET$$\n(.+?)(?=---|\Z)", re.S),
            "injection": re.compile(r"Type: (.+?)\n.+?Payload: (.+?)\n", re.S)
        }

        log_str = "\n".join(log)

        # Check for WAF
        if "detected that the target is protected by" in log_str:
            summary["waf_detected"] = True

        # Extract DBMS, OS, and Technology info
        for line in log:
            dbms_match = patterns["dbms"].search(line)
            os_match = patterns["os"].search(line)
            tech_match = patterns["tech"].search(line)

            if dbms_match:
                summary["end_results"]["dbms"] = dbms_match.group(1)
            if os_match:
                summary["end_results"]["server_os"] = os_match.group(1)
            if tech_match:
                summary["end_results"]["web_technology"] = tech_match.group(1)

        # Extract parameter and injection details
        for param_match in patterns["parameter"].finditer(log_str):
            parameter = param_match.group(1)
            injection_block = param_match.group(2)
            injections = []

            for injection_match in patterns["injection"].finditer(injection_block):
                injection_type = injection_match.group(1).strip()
                payload = injection_match.group(2).strip()
                injections.append({
                    "type": injection_type,
                    "payload": payload
                })

            if injections:  # Only add if injections were found
                summary["end_results"]["injection_details"].append({
                    "parameter": parameter,
                    "injections": injections
                })

            if parameter not in summary["parameters"]:
                summary["parameters"].append(parameter)

        return summary

    def parse_injection_types(self, log_lines):
        """Extract injection types and their payloads from SQLMap output"""
        injection_types = []
        payloads = []
        current_type = None
        
        for line in log_lines:
            if "Type: " in line:
                current_type = line.split("Type: ")[1].strip()
                if current_type and current_type not in injection_types:
                    injection_types.append(current_type)
            
            if "Payload: " in line and current_type:
                payload = line.split("Payload: ")[1].strip()
                payloads.append({
                    "type": current_type,
                    "payload": payload
                })

        return injection_types, payloads

    def determine_risk_level(self, injection_types):
        """Determine risk level based on injection types found"""
        high_risk_types = [
            "UNION query SQL injection",
            "Stacked queries SQL injection",
            "Time-based blind SQL injection",
            "Error-based SQL injection"
        ]
        
        for injection_type in injection_types:
            if any(risk_type.lower() in injection_type.lower() for risk_type in high_risk_types):
                return "High"
        return "Medium"

    def format_vulnerability_report(self, log_lines, summary):
        """Format the vulnerability findings into a structured report"""
        injection_types, payloads = self.parse_injection_types(log_lines)
        risk_level = self.determine_risk_level(injection_types)

        report = {
            "vulnerability_overview": {
                "vulnerability_type": "SQL Injection",
                "affected_parameters": summary.get("parameters", []),
                "risk_level": risk_level,
                "detected_techniques": injection_types
            },
            "proof_of_vulnerability": {
                "payloads": payloads,
                "database_details": {
                    "type": summary["end_results"].get("dbms", "Unknown"),
                    "version": self.extract_dbms_version(log_lines)
                }
            },
            "impact_analysis": {
                "environment_details": {
                    "database": summary["end_results"].get("dbms", "Unknown"),
                    "operating_system": summary["end_results"].get("server_os", "Unknown"),
                    "web_technology": summary["end_results"].get("web_technology", "Unknown")
                },
                "waf_detected": summary.get("waf_detected", False),
                "potential_impacts": self.generate_impact_analysis(injection_types)
            },
            "recommendations": self.generate_recommendations(summary)
        }

        return report

    def extract_dbms_version(self, log_lines):
        """Extract specific DBMS version from SQLMap output"""
        for line in log_lines:
            if "back-end DBMS:" in line:
                return line.split("back-end DBMS:")[1].strip()
        return "Version unknown"

    def generate_impact_analysis(self, injection_types):
        """Generate impact analysis based on detected injection types"""
        impacts = []
        
        impact_mapping = {
            "boolean-based blind": [
                "Ability to extract data through true/false questions",
                "Potential for data enumeration"
            ],
            "time-based blind": [
                "Ability to extract data through time delays",
                "Potential for slower data extraction"
            ],
            "error-based": [
                "Direct data extraction through error messages",
                "Potential for rapid data enumeration"
            ],
            "UNION query": [
                "Direct data extraction through UNION queries",
                "Ability to read arbitrary tables and columns"
            ],
            "stacked queries": [
                "Ability to execute multiple SQL statements",
                "Potential for database modification"
            ]
        }

        for injection_type in injection_types:
            for impact_type, impact_list in impact_mapping.items():
                if impact_type.lower() in injection_type.lower():
                    impacts.extend(impact_list)

        impacts.extend([
            "Unauthorized access to database content",
            "Potential for data theft or manipulation",
            "Possible escalation to system compromise"
        ])

        return list(set(impacts))

    def generate_recommendations(self, summary):
        """Generate specific recommendations based on scan findings"""
        recommendations = {
            "immediate_actions": [
                {
                    "action": "Input Validation",
                    "details": "Implement proper input validation and sanitization"
                },
                {
                    "action": "Prepared Statements",
                    "details": "Use parameterized queries to prevent SQL injection"
                }
            ],
            "additional_measures": []
        }

        if not summary.get("waf_detected"):
            recommendations["additional_measures"].append({
                "action": "Implement WAF",
                "details": "Deploy a Web Application Firewall for additional protection"
            })

        if summary["end_results"].get("dbms"):
            recommendations["immediate_actions"].append({
                "action": f"Secure {summary['end_results']['dbms']} Configuration",
                "details": "Review and harden database security settings"
            })

        return recommendations

    def scan_url(self, url):
        try:
            if not url:
                return {"status": "error", "message": "URL is required"}, 400

            logging.info(f"Scanning URL: {url}")
            if not url.startswith(("http://", "https://")):
                url = "http://" + url

            parsed_url = urllib.parse.urlparse(url)
            domain = parsed_url.netloc.replace(":", "_")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            result_filename = f"sqlmap_{domain}_{timestamp}.json"
            result_filepath = os.path.join(self.results_dir, result_filename)

            start_time = time.time()

            sqlmap_command = [
                "sqlmap",
                "-u", url,
                "--batch",
                "--random-agent",
                "--output-dir", self.results_dir,
                "--answers", "Y",
                "--timeout", "10"
            ]

            logging.info("Starting SQLMap scan...")
            log = []
            
            process = subprocess.Popen(
                " ".join(sqlmap_command),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True,
                text=True
            )

            while True:
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                if line:
                    log_line = line.strip()
                    logging.info(log_line)
                    log.append(log_line)

            summary = self.extract_sqlmap_details(log)
            vulnerability_report = self.format_vulnerability_report(log, summary)

            if process.returncode == 0:
                output_data = {
                    "scan_metadata": {
                        "url": url,
                        "scan_time": timestamp,
                        "status": "success",
                        "scan_duration": f"{time.time() - start_time:.2f} seconds"
                    },
                    "vulnerability_report": vulnerability_report,
                    "raw_logs": log
                }
                status_code = 200
            else:
                output_data = {
                    "scan_metadata": {
                        "url": url,
                        "scan_time": timestamp,
                        "status": "failure",
                        "scan_duration": f"{time.time() - start_time:.2f} seconds"
                    },
                    "error": "SQLMap scan failed",
                    "raw_logs": log
                }
                status_code = 500

            with open(result_filepath, 'w') as f:
                json.dump(output_data, f, indent=4)

            return output_data, status_code

        except Exception as e:
            logging.error(f"Error during scan: {str(e)}")
            return {
                "status": "error",
                "message": str(e),
                "scan_time": datetime.now().strftime("%Y%m%d_%H%M%S")
            }, 500

    async def scan_urls(self, urls):
        """
        Scan multiple URLs for SQL injection vulnerabilities.
        
        Args:
            urls (list): List of URLs to scan.
            
        Returns:
            dict: Results of the scan with URL as key and scan result as value.
        """
        results = {}
        for url in urls[:10]:  # Limit to first 10 URLs for performance
            try:
                scan_result, _ = self.scan_url(url)
                if scan_result.get("vulnerability_report", {}).get("vulnerability_overview", {}).get("affected_parameters"):
                    # SQL injection found
                    results[url] = {
                        "vulnerable": True,
                        "injection_point": scan_result.get("vulnerability_report", {}).get("vulnerability_overview", {}).get("affected_parameters", ["unknown"])[0],
                        "payload": scan_result.get("vulnerability_report", {}).get("proof_of_vulnerability", {}).get("payloads", [{}])[0].get("payload", ""),
                        "database_type": scan_result.get("vulnerability_report", {}).get("proof_of_vulnerability", {}).get("database_details", {}).get("type", "unknown"),
                        "risk_level": scan_result.get("vulnerability_report", {}).get("vulnerability_overview", {}).get("risk_level", "Medium")
                    }
                else:
                    # No SQL injection found
                    results[url] = {
                        "vulnerable": False
                    }
            except Exception as e:
                results[url] = {
                    "vulnerable": False,
                    "error": str(e)
                }
        
        return results