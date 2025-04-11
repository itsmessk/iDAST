import os
import json
import asyncio
from datetime import datetime
from logger import get_logger

logger = get_logger(__name__)

class DalfoxScanner:
    def __init__(self):
        self.results_dir = "dalfox_results"
        if not os.path.exists(self.results_dir):
            os.makedirs(self.results_dir)

    async def scan(self, url, session):
        """
        Main entry point for XSS scanning. This method is called from app.py.
        
        Args:
            url (str): The main URL/domain to scan
            session (aiohttp.ClientSession): The session to use for HTTP requests
            
        Returns:
            dict: Results of the XSS scan
        """
        try:
            logger.info(f"Starting XSS scan for {url}")
            
            # Check if subdomain scan results are available
            from subdomain_scanner import subdomain_scan_results
            
            if subdomain_scan_results and subdomain_scan_results.get("all_urls"):
                # Use URLs from subdomain scan
                urls_to_scan = subdomain_scan_results.get("all_urls", [])
                logger.info(f"Using {len(urls_to_scan)} URLs from subdomain scan for XSS testing")
            else:
                # Fallback to just the provided URL
                logger.warning("No subdomain scan results available, using only the provided URL")
                urls_to_scan = [url]
            
            # Filter URLs to those with parameters (more likely to be vulnerable to XSS)
            param_urls = [u for u in urls_to_scan if '?' in u]
            
            if param_urls:
                logger.info(f"Found {len(param_urls)} URLs with parameters for XSS testing")
                # Extract domain for reporting
                domain = url.split('//')[1].split('/')[0] if '//' in url else url.split('/')[0]
                # Limit to 50 URLs for performance
                scan_results = await self.scan_urls(param_urls[:50], domain)
            else:
                logger.warning("No URLs with parameters found for XSS testing")
                scan_results = {
                    'domain': url,
                    'timestamp': datetime.now().isoformat(),
                    'vulnerabilities': [],
                    'recommendations': []
                }
            
            # Format the results
            vulnerabilities = scan_results.get('vulnerabilities', [])
            
            return {
                "xss_scan": {
                    "status": "completed",
                    "urls_scanned": len(param_urls[:50]) if param_urls else 0,
                    "vulnerabilities_found": len(vulnerabilities),
                    "vulnerabilities": vulnerabilities,
                    "recommendations": scan_results.get('recommendations', []) if vulnerabilities else []
                }
            }
            
        except Exception as e:
            logger.error(f"Error in XSS scan: {e}")
            return {
                "xss_scan": {
                    "status": "error",
                    "error": str(e)
                }
            }

    async def scan_urls(self, urls, domain):
        """Scan multiple URLs for XSS vulnerabilities using Dalfox"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            results_file = os.path.join(self.results_dir, f'urls_{domain}_{timestamp}.txt')
            output_file = os.path.join(self.results_dir, f'dalfox_{domain}_{timestamp}.txt')
            
            # Write URLs to file
            with open(results_file, 'w') as f:
                for url in urls:
                    f.write(f"{url}\n")
            
            # Run Dalfox with optimized XSS scanning settings
            cmd = [
                'dalfox', 'file',
                results_file,
                '--format', 'json',
                '--output', output_file,
                '--follow-redirects',
                '--mining-dict',
                '--mining-dom',
                '--silence',
                '--mass'
            ]
            
            logger.info(f"Starting Dalfox XSS scan with command: {' '.join(cmd)}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if stdout:
                logger.info(f"Dalfox stdout: {stdout.decode()}")
            if stderr:
                logger.error(f"Dalfox stderr: {stderr.decode()}")
            
            return await self._process_results(output_file, domain)
            
        except Exception as e:
            logger.error(f"Error in Dalfox scan: {e}")
            return {}

    async def _process_results(self, output_file, domain):
        """Process and format XSS scan results"""
        try:
            results = {
                'domain': domain,
                'timestamp': datetime.now().isoformat(),
                'vulnerabilities': [],
                'recommendations': [
                    "Implement proper input validation and output encoding",
                    "Use Content Security Policy (CSP) headers",
                    "Sanitize user input before rendering",
                    "Use security frameworks or libraries for XSS protection",
                    "Implement proper HTML escaping for dynamic content"
                ]
            }
            
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                with open(output_file, 'r') as f:
                    try:
                        findings = json.load(f)
                        
                        for finding in findings:
                            if not finding:  # Skip empty findings
                                continue
                                
                            # Extract useful information from the finding
                            url = finding.get('url', '')
                            param = finding.get('param', '')
                            poc = finding.get('poc', '')
                            
                            # Create a detailed vulnerability entry
                            vuln = {
                                'type': 'XSS',
                                'url': url,
                                'parameter': param,
                                'severity': 'High',
                                'payload': poc,
                                'proof': poc,
                                'details': {
                                    'description': f"Cross-Site Scripting vulnerability found in parameter '{param}'",
                                    'impact': "This vulnerability allows attackers to inject malicious scripts that can steal user data, hijack sessions, or deface the website.",
                                    'mitigation': [
                                        f"1. Sanitize input for parameter '{param}'",
                                        "2. Implement Content Security Policy (CSP)",
                                        "3. Use HTML encoding for dynamic content",
                                        "4. Validate input against whitelist"
                                    ]
                                }
                            }
                            
                            results['vulnerabilities'].append(vuln)
                            
                    except json.JSONDecodeError as e:
                        logger.error(f"Error decoding JSON: {e}")
                        f.seek(0)
                        content = f.read()
                        logger.info(f"Raw file content: {content}")
            
            return results
            
        except Exception as e:
            logger.error(f"Error processing Dalfox results: {e}")
            return {}
