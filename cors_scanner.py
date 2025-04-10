import os
import json
import asyncio
import aiohttp
from urllib.parse import urlparse
from datetime import datetime
from aiohttp import ClientTimeout, TCPConnector
from logger import get_logger

logger = get_logger(__name__)

class CORSScanner:
    """Scanner for detecting CORS (Cross-Origin Resource Sharing) misconfigurations."""
    
    def __init__(self):
        """Initialize the CORS scanner with configuration and resources."""
        self.results_dir = "cors_results"
        os.makedirs(self.results_dir, exist_ok=True)
        
        # Test origins for CORS checks
        self.test_origins = [
            '*',
            'null',
            'https://attacker.com',
            'https://evil.attacker.com',
            'attacker.com',
            'https://{target_domain}.attacker.com',
            'https://attacker.{target_domain}',
            'https://{target_domain}.attacker.com:123',
        ]
        
        # Scanner configuration
        self.timeout = ClientTimeout(total=30)  # 30 seconds timeout
        self.max_retries = 3
        self.concurrent_limit = 20
        self.session = None
        self.semaphore = None

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
        Scan multiple URLs for CORS misconfigurations.
        
        Args:
            urls (list): List of URLs to scan.
            
        Returns:
            dict: Scan results for each URL.
        """
        try:
            logger.info(f"Starting CORS scan for {len(urls)} URLs")
            await self.initialize()
            
            results = {}
            tasks = []
            
            # Create scanning tasks with rate limiting
            for url in urls:
                task = asyncio.create_task(self._scan_url_with_retry(url))
                tasks.append(task)
            
            # Execute tasks in batches to prevent overwhelming the target
            for batch in self._batch_tasks(tasks, batch_size=10):
                batch_results = await asyncio.gather(*batch, return_exceptions=True)
                for url, result in zip(urls, batch_results):
                    if isinstance(result, Exception):
                        logger.error(f"Error scanning {url}: {result}")
                    elif result:
                        results[url] = result
            
            return results
            
        except Exception as e:
            logger.error(f"Error in CORS scan: {e}")
            return {}
        finally:
            await self.cleanup()

    def _batch_tasks(self, tasks, batch_size):
        """Split tasks into batches."""
        for i in range(0, len(tasks), batch_size):
            yield tasks[i:i + batch_size]

    async def _scan_url_with_retry(self, url):
        """
        Scan a URL with retry mechanism.
        
        Args:
            url (str): URL to scan.
            
        Returns:
            dict: Scan results for the URL.
        """
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
        """
        Test a single URL for CORS misconfigurations.
        
        Args:
            url (str): URL to test.
            
        Returns:
            dict: Vulnerability details if found, None otherwise.
        """
        try:
            parsed_url = urlparse(url)
            target_domain = parsed_url.netloc
            vulnerabilities = []
            
            for test_origin in self.test_origins:
                # Replace placeholder with actual domain
                origin = test_origin.replace('{target_domain}', target_domain)
                
                try:
                    # Test CORS configuration
                    async with self.session.get(
                        url,
                        headers={'Origin': origin},
                        allow_redirects=False
                    ) as response:
                        acao = response.headers.get('Access-Control-Allow-Origin')
                        acac = response.headers.get('Access-Control-Allow-Credentials')
                        
                        if acao:
                            vuln = self._analyze_cors_headers(origin, acao, acac)
                            if vuln:
                                vulnerabilities.append(vuln)
                
                except asyncio.TimeoutError:
                    logger.warning(f"Timeout testing origin {origin} for {url}")
                    continue
                except Exception as e:
                    logger.error(f"Error testing origin {origin} for {url}: {e}")
                    continue

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

    def _analyze_cors_headers(self, origin, acao, acac):
        """Analyze CORS headers for vulnerabilities."""
        if acao == '*' and acac == 'true':
            return {
                'type': 'Wildcard with Credentials',
                'origin': origin,
                'acao': acao,
                'acac': acac,
                'severity': 'High',
                'description': 'Wildcard origin with credentials allowed, enabling any domain to access sensitive data'
            }
        elif acao == 'null':
            return {
                'type': 'Null Origin Allowed',
                'origin': origin,
                'acao': acao,
                'acac': acac,
                'severity': 'High',
                'description': 'Null origin allowed, potentially enabling sandbox bypass attacks'
            }
        elif origin in acao and '.attacker.com' in origin:
            return {
                'type': 'Dangerous Origin Allowed',
                'origin': origin,
                'acao': acao,
                'acac': acac,
                'severity': 'High',
                'description': 'Potentially dangerous origin allowed due to misconfiguration'
            }
        elif origin == acao and acac == 'true':
            return {
                'type': 'Origin Reflection with Credentials',
                'origin': origin,
                'acao': acao,
                'acac': acac,
                'severity': 'Medium',
                'description': 'Origin header is reflected with credentials, potential for DNS rebinding attacks'
            }
        return None

    def _calculate_risk_level(self, vulnerabilities):
        """Calculate overall risk level based on vulnerabilities."""
        if any(v['severity'] == 'High' for v in vulnerabilities):
            return 'High'
        elif any(v['severity'] == 'Medium' for v in vulnerabilities):
            return 'Medium'
        return 'Low'

    def _get_recommendations(self, vulnerabilities):
        """Get specific recommendations based on found vulnerabilities."""
        recommendations = set()
        
        for vuln in vulnerabilities:
            if vuln['type'] == 'Wildcard with Credentials':
                recommendations.update([
                    "Remove wildcard (*) from Access-Control-Allow-Origin when using credentials",
                    "Implement strict origin validation",
                    "Use specific allowed origins instead of wildcards"
                ])
            elif vuln['type'] == 'Null Origin Allowed':
                recommendations.update([
                    "Remove 'null' from allowed origins",
                    "Implement proper origin validation",
                    "Use specific allowed origins"
                ])
            elif vuln['type'] == 'Dangerous Origin Allowed':
                recommendations.update([
                    "Implement strict origin validation",
                    "Review and update CORS policy",
                    "Use a whitelist of allowed origins"
                ])
            elif vuln['type'] == 'Origin Reflection with Credentials':
                recommendations.update([
                    "Implement proper origin validation",
                    "Avoid reflecting Origin header",
                    "Use a predefined list of allowed origins"
                ])
        
        return list(recommendations)

    def _save_results(self, url, result):
        """Save detailed scan results to file."""
        try:
            filename = os.path.join(
                self.results_dir,
                f"cors_scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
            )
            with open(filename, 'w') as f:
                json.dump({
                    'url': url,
                    'scan_result': result,
                    'timestamp': datetime.utcnow().isoformat()
                }, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving results: {e}")