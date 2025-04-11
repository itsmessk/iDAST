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

    async def scan(self, url, session):
        """
        Main entry point for CORS scanning. This method is called from app.py.
        
        Args:
            url (str): The main URL/domain to scan
            session (aiohttp.ClientSession): The session to use for HTTP requests
            
        Returns:
            dict: Results of the CORS scan
        """
        try:
            logger.info(f"Starting CORS scan for {url}")
            
            # Check if subdomain scan results are available
            from subdomain_scanner import subdomain_scan_results
            
            urls_to_scan = []
            
            if subdomain_scan_results:
                # First, add all discovered subdomains as URLs to scan
                if subdomain_scan_results.get("subdomains"):
                    urls_to_scan.extend(subdomain_scan_results.get("subdomains", []))
                
                # Next, add URLs from wayback data
                if subdomain_scan_results.get("wayback_urls"):
                    for subdomain, wayback_urls in subdomain_scan_results.get("wayback_urls", {}).items():
                        urls_to_scan.extend(wayback_urls)
                
                # Finally, add URLs with parameters from paramspider data
                if subdomain_scan_results.get("paramspider_urls"):
                    for subdomain, param_urls in subdomain_scan_results.get("paramspider_urls", {}).items():
                        urls_to_scan.extend(param_urls)
                
                # Add all URLs from the combined list
                if subdomain_scan_results.get("all_urls"):
                    urls_to_scan.extend(subdomain_scan_results.get("all_urls", []))
                
                logger.info(f"Using {len(urls_to_scan)} URLs from subdomain scan for CORS testing")
            
            # If no URLs from subdomain scan, use the provided URL
            if not urls_to_scan:
                logger.warning("No subdomain scan results available, using only the provided URL")
                urls_to_scan = [url]
            
            # Remove duplicates
            urls_to_scan = list(set(urls_to_scan))
            
            # Limit the number of URLs to scan for performance
            max_urls = 100
            if len(urls_to_scan) > max_urls:
                logger.info(f"Limiting CORS scan to {max_urls} URLs")
                urls_to_scan = urls_to_scan[:max_urls]
            
            # Use the provided session if available, otherwise initialize our own
            if session:
                self.session = session
            else:
                await self.initialize()
            
            # Scan the URLs
            scan_results = await self.scan_urls(urls_to_scan)
            
            # Format the results
            vulnerabilities = []
            for url, result in scan_results.items():
                if result and result.get('is_vulnerable'):
                    for vuln in result.get('vulnerabilities', []):
                        vulnerabilities.append({
                            'url': url,
                            'type': vuln.get('type', 'CORS Misconfiguration'),
                            'origin': vuln.get('origin', ''),
                            'acao': vuln.get('acao', ''),
                            'acac': vuln.get('acac', ''),
                            'severity': vuln.get('severity', 'Medium'),
                            'description': vuln.get('description', '')
                        })
            
            # Get unique recommendations
            recommendations = set()
            for _, result in scan_results.items():
                if result and result.get('is_vulnerable'):
                    recommendations.update(result.get('recommendations', []))
            
            return {
                "cors_scan": {
                    "status": "completed",
                    "urls_scanned": len(urls_to_scan),
                    "vulnerabilities_found": len(vulnerabilities),
                    "vulnerabilities": vulnerabilities,
                    "recommendations": list(recommendations) if vulnerabilities else []
                }
            }
            
        except Exception as e:
            logger.error(f"Error in CORS scan: {e}")
            return {
                "cors_scan": {
                    "status": "error",
                    "error": str(e)
                }
            }
        finally:
            # Only close the session if we created it
            if session is None and self.session:
                await self.cleanup()

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
            
            results = {}
            tasks = []
            
            # Create scanning tasks with rate limiting
            for url in urls:
                task = asyncio.create_task(self._scan_url_with_retry(url))
                tasks.append(task)
            
            # Execute tasks in batches to prevent overwhelming the target
            for i, batch in enumerate(self._batch_tasks(tasks, batch_size=10)):
                logger.info(f"Processing CORS scan batch {i+1}/{(len(tasks) + 9) // 10}")
                batch_results = await asyncio.gather(*batch, return_exceptions=True)
                for url, result in zip(urls[i*10:i*10+len(batch)], batch_results):
                    if isinstance(result, Exception):
                        logger.error(f"Error scanning {url}: {result}")
                    elif result:
                        results[url] = result
            
            return results
            
        except Exception as e:
            logger.error(f"Error in CORS scan: {e}")
            return {}

    def _batch_tasks(self, tasks, batch_size):
        """Split tasks into batches."""
        for i in range(0, len(tasks), batch_size):
            yield tasks[i:i + batch_size]

    async def _scan_url_with_retry(self, url):
        """
        Scan a URL with retry mechanism.
        
        Args:
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