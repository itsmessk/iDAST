import os
import json
import asyncio
import aiohttp
import dns.resolver
from urllib.parse import urlparse
from logger import get_logger

logger = get_logger(__name__)

class AutoPoisoningScanner:
    def __init__(self):
        self.results_dir = "autopoisoning_results"
        os.makedirs(self.results_dir, exist_ok=True)
        self.fingerprints = {
            'GitHub Pages': {
                'cname': ['github.io'],
                'response': ['There isn\'t a GitHub Pages site here.']
            },
            'Heroku': {
                'cname': ['herokuapp.com'],
                'response': ['No such app', 'herokucdn.com/error-pages/no-such-app.html']
            },
            'Amazon S3': {
                'cname': ['s3.amazonaws.com'],
                'response': ['NoSuchBucket', 'The specified bucket does not exist']
            },
            'Shopify': {
                'cname': ['myshopify.com'],
                'response': ['Sorry, this shop is currently unavailable.']
            },
            'Azure': {
                'cname': ['azurewebsites.net'],
                'response': ['This web app is stopped.', 'This webpage is not available']
            },
            'Fastly': {
                'cname': ['fastly.net'],
                'response': ['Fastly error: unknown domain']
            },
            'Pantheon': {
                'cname': ['pantheonsite.io'],
                'response': ['The gods are wise', 'pantheonsite.io/404']
            },
            'Tumblr': {
                'cname': ['tumblr.com'],
                'response': ['There\'s nothing here.', 'Whatever you were looking for doesn\'t currently exist at this address']
            }
        }

    async def scan_domains(self, domains):
        """
        Scan multiple domains for subdomain takeover vulnerabilities
        """
        try:
            logger.info(f"Starting AutoPoisoning scan for {len(domains)} domains")
            results = {}
            
            async with aiohttp.ClientSession() as session:
                for domain in domains:
                    result = await self._scan_domain(session, domain)
                    if result:
                        results[domain] = result
            
            return results
        except Exception as e:
            logger.error(f"Error in AutoPoisoning scan: {e}")
            return {}

    async def _scan_domain(self, session, domain):
        """
        Scan a single domain for subdomain takeover vulnerabilities
        """
        try:
            vulnerabilities = []
            
            # Get CNAME records
            cname_records = await self._get_cname_records(domain)
            
            for cname in cname_records:
                # Check each service's fingerprint
                for service, fingerprint in self.fingerprints.items():
                    if any(fp in cname.lower() for fp in fingerprint['cname']):
                        # Check if the domain is vulnerable
                        is_vulnerable = await self._check_takeover_vulnerability(
                            session, domain, service, fingerprint['response']
                        )
                        
                        if is_vulnerable:
                            vulnerabilities.append({
                                'type': 'Subdomain Takeover',
                                'service': service,
                                'cname': cname,
                                'evidence': 'Service fingerprint matched and domain is unclaimed',
                                'severity': 'Critical'
                            })

            if vulnerabilities:
                return {
                    'is_vulnerable': True,
                    'vulnerabilities': vulnerabilities,
                    'recommendations': [
                        "Remove or update DNS records pointing to discontinued services",
                        "Regularly audit DNS records and unused subdomains",
                        "Implement proper deprovisioning procedures",
                        "Monitor for new subdomain takeover opportunities",
                        "Consider using DNS monitoring services",
                        "Implement DNSSEC where possible"
                    ],
                    'risk_level': 'Critical'
                }

            return None

        except Exception as e:
            logger.error(f"Error scanning domain {domain}: {e}")
            return None

    async def _get_cname_records(self, domain):
        """
        Get CNAME records for a domain using dns.resolver
        """
        try:
            resolver = dns.resolver.Resolver()
            answers = resolver.resolve(domain, 'CNAME')
            return [str(rdata.target) for rdata in answers]
        except:
            return []

    async def _check_takeover_vulnerability(self, session, domain, service, response_patterns):
        """
        Check if a domain is vulnerable to takeover by checking response patterns
        """
        try:
            urls = [
                f"http://{domain}",
                f"https://{domain}"
            ]
            
            for url in urls:
                try:
                    async with session.get(url, timeout=10) as response:
                        content = await response.text()
                        
                        # Check if response matches service fingerprint
                        if any(pattern.lower() in content.lower() for pattern in response_patterns):
                            return True
                except:
                    continue
            
            return False
        except Exception as e:
            logger.error(f"Error checking takeover vulnerability for {domain}: {e}")
            return False

    def _validate_domain(self, domain):
        """
        Validate domain format
        """
        try:
            parsed = urlparse(f"http://{domain}")
            return bool(parsed.netloc and "." in parsed.netloc)
        except:
            return False