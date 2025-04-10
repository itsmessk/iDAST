import os
import json
import asyncio
import aiohttp
import subprocess
from urllib.parse import urlparse
from logger import get_logger

logger = get_logger(__name__)

class RetireJSScanner:
    def __init__(self):
        self.results_dir = "retirejs_results"
        os.makedirs(self.results_dir, exist_ok=True)
        self.npm_package = "@retire/node"
        self._ensure_retire_js_installed()

    def _ensure_retire_js_installed(self):
        """Ensure retire.js is installed globally"""
        try:
            subprocess.run(['retire', '--version'], capture_output=True)
        except FileNotFoundError:
            logger.info("Installing retire.js...")
            subprocess.run(['npm', 'install', '-g', self.npm_package], check=True)

    async def scan_urls(self, urls):
        """
        Scan multiple URLs for vulnerable JavaScript libraries
        """
        try:
            logger.info(f"Starting Retire.js scan for {len(urls)} URLs")
            results = {}
            
            async with aiohttp.ClientSession() as session:
                for url in urls:
                    result = await self._scan_url(session, url)
                    if result:
                        results[url] = result
            
            return results
        except Exception as e:
            logger.error(f"Error in Retire.js scan: {e}")
            return {}

    async def _scan_url(self, session, url):
        """
        Scan a single URL for vulnerable JavaScript libraries
        """
        try:
            # First, download and save all JavaScript files
            js_files = await self._download_js_files(session, url)
            if not js_files:
                return None

            vulnerabilities = []
            
            # Run retire.js on each downloaded file
            for js_file in js_files:
                try:
                    result = subprocess.run(
                        ['retire', '--path', js_file, '--outputformat', 'json'],
                        capture_output=True,
                        text=True
                    )
                    
                    if result.stdout:
                        findings = json.loads(result.stdout)
                        if findings and isinstance(findings, list):
                            for finding in findings:
                                if 'results' in finding:
                                    for vuln in finding['results']:
                                        vulnerabilities.append({
                                            'library': vuln.get('component', 'Unknown'),
                                            'version': vuln.get('version', 'Unknown'),
                                            'vulnerabilities': [
                                                {
                                                    'info': v.get('info', []),
                                                    'severity': v.get('severity', 'medium'),
                                                    'identifiers': v.get('identifiers', {}),
                                                }
                                                for v in vuln.get('vulnerabilities', [])
                                            ],
                                            'file': finding.get('file', js_file)
                                        })
                
                except Exception as e:
                    logger.error(f"Error scanning file {js_file}: {e}")
                
                # Clean up downloaded file
                try:
                    os.remove(js_file)
                except:
                    pass

            if vulnerabilities:
                return {
                    'is_vulnerable': True,
                    'vulnerabilities': vulnerabilities,
                    'recommendations': [
                        "Update vulnerable JavaScript libraries to their latest secure versions",
                        "Implement Subresource Integrity (SRI) for third-party scripts",
                        "Regular security audits of JavaScript dependencies",
                        "Consider using automated dependency updates",
                        "Implement Content Security Policy (CSP)",
                        "Monitor security advisories for used libraries"
                    ],
                    'risk_level': self._determine_risk_level(vulnerabilities)
                }

            return None

        except Exception as e:
            logger.error(f"Error scanning URL {url}: {e}")
            return None

    async def _download_js_files(self, session, url):
        """
        Download all JavaScript files from a webpage
        """
        js_files = []
        try:
            async with session.get(url) as response:
                html = await response.text()
                
                # Extract JavaScript file URLs
                js_urls = set()
                for line in html.split('\n'):
                    if 'src=' in line and '.js' in line:
                        # Basic extraction - could be improved with proper HTML parsing
                        start = line.find('src=') + 5
                        end = line.find('"', start) if '"' in line[start:] else line.find("'", start)
                        if end > start:
                            js_url = line[start:end]
                            if js_url.endswith('.js'):
                                if not js_url.startswith(('http://', 'https://')):
                                    base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
                                    js_url = f"{base_url}/{js_url.lstrip('/')}"
                                js_urls.add(js_url)

            # Download each JavaScript file
            for js_url in js_urls:
                try:
                    async with session.get(js_url) as js_response:
                        if js_response.status == 200:
                            content = await js_response.text()
                            filename = os.path.join(
                                self.results_dir,
                                f"temp_{hash(js_url)}.js"
                            )
                            with open(filename, 'w', encoding='utf-8') as f:
                                f.write(content)
                            js_files.append(filename)
                except Exception as e:
                    logger.error(f"Error downloading {js_url}: {e}")

        except Exception as e:
            logger.error(f"Error fetching JavaScript files from {url}: {e}")

        return js_files

    def _determine_risk_level(self, vulnerabilities):
        """
        Determine overall risk level based on vulnerabilities
        """
        has_critical = any(
            any(v['severity'] == 'critical' for v in vuln['vulnerabilities'])
            for vuln in vulnerabilities
        )
        has_high = any(
            any(v['severity'] == 'high' for v in vuln['vulnerabilities'])
            for vuln in vulnerabilities
        )
        
        if has_critical:
            return 'Critical'
        elif has_high:
            return 'High'
        return 'Medium'