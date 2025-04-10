import os
import json
import asyncio
import aiohttp
import time
from collections import defaultdict
from urllib.parse import urlparse, parse_qs, urlencode
from logger import get_logger

logger = get_logger(__name__)

class RateLimitScanner:
    def __init__(self):
        self.results_dir = "ratelimit_results"
        os.makedirs(self.results_dir, exist_ok=True)
        self.bypass_techniques = [
            {
                'name': 'IP-based Bypass',
                'headers': {
                    'X-Forwarded-For': ['1.2.3.4', '2.3.4.5'],
                    'X-Real-IP': ['1.2.3.4', '2.3.4.5'],
                    'X-Client-IP': ['1.2.3.4', '2.3.4.5']
                }
            },
            {
                'name': 'User-Agent Rotation',
                'headers': {
                    'User-Agent': [
                        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                        'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15',
                        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
                    ]
                }
            },
            {
                'name': 'Cache Bypass',
                'headers': {
                    'Cache-Control': 'no-cache',
                    'Pragma': 'no-cache'
                },
                'params': {
                    '_': int(time.time())
                }
            }
        ]

    async def scan_urls(self, urls):
        """
        Scan multiple URLs for rate limiting vulnerabilities
        """
        try:
            logger.info(f"Starting Rate Limit scan for {len(urls)} URLs")
            results = {}
            
            async with aiohttp.ClientSession() as session:
                for url in urls:
                    result = await self._scan_url(session, url)
                    if result:
                        results[url] = result
            
            return results
        except Exception as e:
            logger.error(f"Error in Rate Limit scan: {e}")
            return {}

    async def _scan_url(self, session, url):
        """
        Test a single URL for rate limiting vulnerabilities
        """
        try:
            vulnerabilities = []
            
            # First, detect if rate limiting is present
            rate_limit_info = await self._detect_rate_limiting(session, url)
            if not rate_limit_info['has_rate_limit']:
                vulnerabilities.append({
                    'type': 'Missing Rate Limiting',
                    'evidence': 'No rate limiting detected after high-frequency requests',
                    'severity': 'High'
                })
                return self._create_result(vulnerabilities)

            # Test each bypass technique
            for technique in self.bypass_techniques:
                bypass_result = await self._test_bypass_technique(
                    session, url, technique, rate_limit_info
                )
                if bypass_result:
                    vulnerabilities.append(bypass_result)

            if vulnerabilities:
                return self._create_result(vulnerabilities)

            return None

        except Exception as e:
            logger.error(f"Error scanning URL {url}: {e}")
            return None

    async def _detect_rate_limiting(self, session, url):
        """
        Detect if rate limiting is implemented
        """
        results = {
            'has_rate_limit': False,
            'threshold': 0,
            'window': 0
        }
        
        try:
            # Send requests with increasing frequency
            rates = [10, 30, 50, 100]  # requests per window
            window = 10  # seconds
            
            for rate in rates:
                responses = []
                start_time = time.time()
                
                # Send burst of requests
                tasks = []
                for _ in range(rate):
                    tasks.append(self._send_request(session, url))
                
                responses = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Analyze responses
                status_codes = defaultdict(int)
                for resp in responses:
                    if isinstance(resp, dict):
                        status_codes[resp['status']] += 1
                
                # Check for rate limit indicators
                if (429 in status_codes or  # Too Many Requests
                    503 in status_codes):   # Service Unavailable
                    results['has_rate_limit'] = True
                    results['threshold'] = rate
                    results['window'] = window
                    break
            
            return results

        except Exception as e:
            logger.error(f"Error detecting rate limiting: {e}")
            return results

    async def _test_bypass_technique(self, session, url, technique, rate_limit_info):
        """
        Test a specific rate limit bypass technique
        """
        try:
            if not rate_limit_info['threshold']:
                return None

            # Send requests using the bypass technique
            responses = []
            requests_count = rate_limit_info['threshold'] + 10  # Try to exceed the limit
            
            tasks = []
            for _ in range(requests_count):
                headers = {}
                params = {}
                
                # Apply technique headers
                for header, values in technique.get('headers', {}).items():
                    if isinstance(values, list):
                        headers[header] = values[_ % len(values)]
                    else:
                        headers[header] = values
                
                # Apply technique parameters
                params.update(technique.get('params', {}))
                
                tasks.append(self._send_request(session, url, headers, params))
            
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Analyze if bypass was successful
            success_count = sum(
                1 for resp in responses
                if isinstance(resp, dict) and resp['status'] in [200, 201, 202]
            )
            
            if success_count > rate_limit_info['threshold']:
                return {
                    'type': 'Rate Limit Bypass',
                    'technique': technique['name'],
                    'evidence': f'Successfully bypassed rate limit ({success_count} successful requests)',
                    'headers_used': technique.get('headers', {}),
                    'params_used': technique.get('params', {}),
                    'severity': 'High'
                }
            
            return None

        except Exception as e:
            logger.error(f"Error testing bypass technique: {e}")
            return None

    async def _send_request(self, session, url, headers=None, params=None):
        """
        Send a single request with optional headers and parameters
        """
        try:
            # Merge URL parameters with provided parameters
            parsed_url = urlparse(url)
            existing_params = parse_qs(parsed_url.query)
            merged_params = {**existing_params, **(params or {})}
            
            # Reconstruct URL with merged parameters
            url_parts = list(parsed_url)
            url_parts[4] = urlencode(merged_params, doseq=True)
            final_url = urlparse.urlunparse(url_parts)
            
            async with session.get(
                final_url,
                headers=headers,
                timeout=5,
                allow_redirects=True
            ) as response:
                return {
                    'status': response.status,
                    'headers': dict(response.headers)
                }
        except Exception as e:
            return {'error': str(e)}

    def _create_result(self, vulnerabilities):
        """
        Create a structured result from vulnerabilities
        """
        return {
            'is_vulnerable': True,
            'vulnerabilities': vulnerabilities,
            'recommendations': [
                "Implement consistent rate limiting across all endpoints",
                "Use token bucket or leaky bucket algorithms",
                "Consider rate limiting by multiple factors (IP, user, endpoint)",
                "Implement proper handling of X-Forwarded-For headers",
                "Use secure session management",
                "Monitor for unusual request patterns",
                "Implement progressive delays for repeated violations"
            ],
            'risk_level': 'High' if any(v['severity'] == 'High' for v in vulnerabilities) else 'Medium'
        }