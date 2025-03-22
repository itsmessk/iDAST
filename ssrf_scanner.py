import os
import json
import asyncio
import aiohttp
from urllib.parse import urlparse, urljoin
from logger import get_logger

logger = get_logger(__name__)

class SSRFScanner:
    def __init__(self):
        self.results_dir = os.path.join('tests', 'ssrf_results')
        os.makedirs(self.results_dir, exist_ok=True)
        self.payloads = [
            'http://127.0.0.1',
            'http://localhost',
            'http://[::1]',
            'http://0.0.0.0',
            'file:///etc/passwd',
            'dict://127.0.0.1:11211',
            'gopher://127.0.0.1:11211/_',
            'http://169.254.169.254/latest/meta-data/',  # AWS metadata
            'http://metadata.google.internal',  # GCP metadata
            'http://169.254.169.254/metadata/v1',  # DigitalOcean metadata
        ]

    async def scan_urls(self, urls):
        """
        Scan multiple URLs for SSRF vulnerabilities
        """
        try:
            logger.info(f"Starting SSRF scan for {len(urls)} URLs")
            results = {}
            
            async with aiohttp.ClientSession() as session:
                for url in urls:
                    result = await self._scan_url(session, url)
                    if result:
                        results[url] = result
            
            return results
        except Exception as e:
            logger.error(f"Error in SSRF scan: {e}")
            return {}

    async def _scan_url(self, session, url):
        """
        Scan a single URL for SSRF vulnerabilities
        """
        try:
            parsed_url = urlparse(url)
            params = self._extract_parameters(parsed_url.query)
            vulnerabilities = []

            for param_name, param_value in params.items():
                param_vulns = await self._test_parameter(session, url, param_name)
                if param_vulns:
                    vulnerabilities.extend(param_vulns)

            if vulnerabilities:
                return {
                    'is_vulnerable': True,
                    'vulnerabilities': vulnerabilities,
                    'recommendations': [
                        "Implement strict URL validation",
                        "Use allowlist for allowed domains/IPs",
                        "Disable internal network access",
                        "Use a proxy for external requests",
                        "Implement rate limiting",
                        "Monitor outbound connections"
                    ],
                    'risk_level': 'High',
                    'cwe': 'CWE-918'
                }

            return None

        except Exception as e:
            logger.error(f"Error scanning URL {url}: {e}")
            return None

    def _extract_parameters(self, query_string):
        """Extract parameters from URL query string"""
        params = {}
        if query_string:
            for param in query_string.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    params[key] = value
        return params

    async def _test_parameter(self, session, url, param_name):
        """Test a parameter for SSRF vulnerability"""
        vulnerabilities = []
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"

        for payload in self.payloads:
            try:
                test_url = f"{base_url}?{param_name}={payload}"
                async with session.get(test_url, allow_redirects=True, timeout=5) as response:
                    response_text = await response.text()
                    
                    # Check for successful SSRF indicators
                    if any(indicator in response_text.lower() for indicator in [
                        'internal server error',
                        'connection refused',
                        'network is unreachable',
                        'root:x:0:0',  # /etc/passwd content
                        'ami-id',  # AWS metadata
                        'instance-id',  # Cloud metadata
                        'project-id'  # GCP metadata
                    ]):
                        vulnerabilities.append({
                            'parameter': param_name,
                            'payload': payload,
                            'response_code': response.status,
                            'evidence': 'Potential SSRF vulnerability detected',
                            'test_url': test_url,
                            'test_results': [
                                {
                                    'test': 'Response indicators',
                                    'result': 'Found suspicious response patterns'
                                },
                                {
                                    'test': 'Status code',
                                    'result': f'Received status {response.status}'
                                }
                            ]
                        })

            except aiohttp.ClientError as e:
                # Some errors might indicate successful SSRF
                if any(indicator in str(e).lower() for indicator in [
                    'connection refused',
                    'network unreachable',
                    'timeout'
                ]):
                    vulnerabilities.append({
                        'parameter': param_name,
                        'payload': payload,
                        'evidence': f'Connection error: {str(e)}',
                        'test_url': test_url,
                        'test_results': [
                            {
                                'test': 'Connection behavior',
                                'result': 'Received expected error indicating potential SSRF'
                            }
                        ]
                    })

        return vulnerabilities
