import os
import json
import asyncio
import aiohttp
import socket
import dns.resolver
from datetime import datetime, timedelta
from urllib.parse import urlparse
from logger import get_logger
from external_tools import tool_manager
from config import config
from database import db

logger = get_logger(__name__)

class SubdomainScanner:
    def __init__(self):
        self.results_dir = os.path.join(config.RESULTS_DIR, "subdomains")
        self.cache_duration = timedelta(hours=24)
        self.setup_directories()

    def setup_directories(self):
        """Create necessary directories with proper permissions"""
        try:
            os.makedirs(self.results_dir, mode=0o750, exist_ok=True)
            os.makedirs("wordlists", mode=0o750, exist_ok=True)
            logger.info(f"Created directories: {self.results_dir}, wordlists")
        except Exception as e:
            logger.error(f"Error creating directories: {e}")
            raise

    async def find_subdomains(self, domain):
        """Find subdomains using multiple tools and techniques with caching"""
        try:
            # Check cache first
            cached_results = await self._get_cached_results(domain)
            if cached_results:
                logger.info(f"Using cached results for {domain}")
                return cached_results

            logger.info(f"Starting comprehensive subdomain enumeration for {domain}")
            all_subdomains = set()

            # Run initial discovery tasks concurrently with timeout
            initial_tasks = [
                self._run_with_timeout(self._run_subfinder(domain)),
                self._run_with_timeout(self._run_amass(domain)),
                self._run_with_timeout(self._run_assetfinder(domain)),
                self._run_with_timeout(self._run_certificate_search(domain)),
                self._run_with_timeout(self._run_wayback_search(domain)),
                self._run_with_timeout(self._run_dns_brute(domain))
            ]

            results = await asyncio.gather(*initial_tasks, return_exceptions=True)
            
            # Process initial results
            for result in results:
                if isinstance(result, list):
                    all_subdomains.update(result)
                elif isinstance(result, Exception):
                    logger.error(f"Error in subdomain discovery: {result}")

            # Clean and validate initial subdomains
            valid_subdomains = [
                subdomain for subdomain in all_subdomains
                if self._is_valid_subdomain(subdomain, domain)
            ]

            if valid_subdomains:
                # Generate permutations with rate limiting
                permutations = await self._run_with_timeout(
                    self._generate_permutations(valid_subdomains, domain),
                    timeout=config.SCAN_TIMEOUT
                )
                
                # Resolve all subdomains using massdns with rate limiting
                all_to_resolve = valid_subdomains + permutations
                resolved = await self._run_with_rate_limit(
                    tool_manager.run_massdns(all_to_resolve),
                    rate_limit=config.RATE_LIMIT_PER_MINUTE
                )
                
                # Get additional DNS records using dnsx
                if resolved:
                    dns_results = await self._run_with_timeout(
                        tool_manager.run_dnsx(resolved),
                        timeout=config.SCAN_TIMEOUT
                    )
                    # Extract additional subdomains from DNS records
                    for result in dns_results:
                        if isinstance(result, dict) and 'cname' in result:
                            cname = result['cname']
                            if cname.endswith(domain):
                                resolved.append(cname)

                # Update valid subdomains with resolved ones
                valid_subdomains = [
                    subdomain for subdomain in resolved
                    if self._is_valid_subdomain(subdomain, domain)
                ]

            # Store results in cache
            await self._cache_results(domain, valid_subdomains)

            logger.info(f"Found {len(valid_subdomains)} unique subdomains for {domain}")
            return list(set(valid_subdomains))

        except Exception as e:
            logger.error(f"Error in subdomain enumeration: {e}")
            return []
        finally:
            # Cleanup any temporary files
            self._cleanup_temp_files()

    async def _run_with_timeout(self, coro, timeout=None):
        """Run coroutine with timeout"""
        try:
            return await asyncio.wait_for(coro, timeout or config.SCAN_TIMEOUT)
        except asyncio.TimeoutError:
            logger.warning(f"Operation timed out after {timeout or config.SCAN_TIMEOUT} seconds")
            return []

    async def _run_with_rate_limit(self, coro, rate_limit=None):
        """Run coroutine with rate limiting"""
        await asyncio.sleep(1.0 / (rate_limit or config.RATE_LIMIT_PER_MINUTE))
        return await coro

    async def _get_cached_results(self, domain):
        """Get cached subdomain results from database"""
        try:
            cache_key = f"subdomains:{domain}"
            cached = await db.find_user({"cache_key": cache_key})
            
            if cached:
                cache_time = cached.get('timestamp')
                if cache_time and datetime.utcnow() - cache_time < self.cache_duration:
                    return cached.get('subdomains', [])
            return None
        except Exception as e:
            logger.error(f"Error getting cached results: {e}")
            return None

    async def _cache_results(self, domain, subdomains):
        """Cache subdomain results in database"""
        try:
            cache_key = f"subdomains:{domain}"
            await db.async_db[config.MONGO_SCAN_COLLECTION].update_one(
                {"cache_key": cache_key},
                {
                    "$set": {
                        "subdomains": subdomains,
                        "timestamp": datetime.utcnow()
                    }
                },
                upsert=True
            )
        except Exception as e:
            logger.error(f"Error caching results: {e}")

    def _cleanup_temp_files(self):
        """Clean up temporary files"""
        try:
            temp_files = ['domains.txt', 'massdns_results.json', 'temp_urls.txt']
            for file in temp_files:
                if os.path.exists(file):
                    os.remove(file)
        except Exception as e:
            logger.error(f"Error cleaning up temporary files: {e}")

    async def _run_subfinder(self, domain):
        """Use subfinder tool for subdomain discovery"""
        return await tool_manager.run_subfinder(domain)

    async def _run_amass(self, domain):
        """Use amass tool for subdomain discovery"""
        return await tool_manager.run_amass(domain)

    async def _run_assetfinder(self, domain):
        """Use assetfinder tool for subdomain discovery"""
        return await tool_manager.run_assetfinder(domain)

    def _generate_permutations(self, subdomains, domain):
        """Generate subdomain permutations"""
        permutations = set()
        prefixes = ['dev', 'stage', 'test', 'prod', 'uat', 'qa', 'api', 'admin',
                   'portal', 'beta', 'demo', 'lab', 'internal', 'staging', 'development']
        
        for subdomain in subdomains:
            # Extract the subdomain part without the main domain
            parts = subdomain.replace(f".{domain}", "").split('.')
            
            # Generate variations
            for part in parts:
                # Add number suffixes
                for i in range(10):
                    permutations.add(f"{part}{i}.{domain}")
                
                # Add common prefixes
                for prefix in prefixes:
                    permutations.add(f"{prefix}-{part}.{domain}")
                    permutations.add(f"{prefix}.{part}.{domain}")
                    
                # Add common environment names
                for env in ['dev', 'staging', 'test']:
                    permutations.add(f"{part}-{env}.{domain}")
                    permutations.add(f"{env}-{part}.{domain}")
            
            # Generate combinations of existing parts
            if len(parts) > 1:
                for i in range(len(parts)):
                    for j in range(i + 1, len(parts)):
                        permutations.add(f"{parts[i]}-{parts[j]}.{domain}")
                        permutations.add(f"{parts[j]}-{parts[i]}.{domain}")
        
        return list(permutations)

    async def _run_certificate_search(self, domain):
        """Search SSL/TLS certificates for subdomains"""
        try:
            subdomains = set()
            async with aiohttp.ClientSession() as session:
                # Search crt.sh
                url = f"https://crt.sh/?q=%.{domain}&output=json"
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        for entry in data:
                            name_value = entry.get('name_value', '')
                            if name_value:
                                subdomains.update(name_value.split('\n'))

                # Search Certificate Transparency logs
                url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        for cert in data:
                            subdomains.update(cert.get('dns_names', []))

            return list(subdomains)
        except Exception as e:
            logger.error(f"Error in certificate search: {e}")
            return []

    async def _run_wayback_search(self, domain):
        """Use wayback machine data for subdomain discovery"""
        try:
            subdomains = set()
            urls = await tool_manager.run_gau(domain)
            
            for url_data in urls:
                try:
                    parsed = urlparse(url_data.get('url', ''))
                    if parsed.netloc and parsed.netloc.endswith(domain):
                        subdomains.add(parsed.netloc)
                except:
                    continue

            return list(subdomains)
        except Exception as e:
            logger.error(f"Error in wayback search: {e}")
            return []

    async def _run_dns_brute(self, domain):
        """Perform DNS bruteforce with rate limiting and chunking"""
        try:
            subdomains = set()
            wordlist = self._load_wordlist()
            
            # Process in chunks to avoid overwhelming the DNS servers
            chunk_size = 100
            rate_limit = 50  # requests per second
            delay = 1.0 / rate_limit
            
            async with aiohttp.ClientSession() as session:
                for i in range(0, len(wordlist), chunk_size):
                    chunk = wordlist[i:i + chunk_size]
                    tasks = []
                    
                    for word in chunk:
                        subdomain = f"{word}.{domain}"
                        tasks.append(self._check_dns(session, subdomain))
                        await asyncio.sleep(delay)  # Rate limiting
                    
                    if tasks:
                        results = await asyncio.gather(*tasks, return_exceptions=True)
                        valid_results = [r for r in results if r and isinstance(r, str)]
                        subdomains.update(valid_results)
                        
                        # Log progress
                        logger.info(f"DNS bruteforce progress: {i + len(chunk)}/{len(wordlist)} words processed")
                        
                        # Add small delay between chunks
                        await asyncio.sleep(1)

            return list(subdomains)
        except Exception as e:
            logger.error(f"Error in DNS bruteforce: {e}")
            return []

    def _load_wordlist(self):
        """Load subdomain wordlist with enhanced sources"""
        wordlist = set()
        try:
            # Common subdomain prefixes
            common = [
                # Basic services
                'www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'dns', 'ns1', 'ns2', 'ns3', 'ns4',
                'webmail', 'email', 'mx', 'pop3', 'smtp', 'autodiscover', 'autoconfig',
                
                # Web services
                'web', 'www2', 'www3', 'webdisk', 'webapi', 'webservices', 'websocket', 'webhook',
                'portal', 'api', 'api-docs', 'docs', 'documentation', 'developer', 'developers',
                
                # Admin and management
                'cpanel', 'whm', 'admin', 'administrator', 'admins', 'administrador', 'webadmin',
                'manage', 'manager', 'management', 'cp', 'controlpanel', 'console',
                
                # Development and testing
                'dev', 'development', 'developer', 'test', 'testing', 'staging', 'stage', 'uat',
                'qa', 'debug', 'debugging', 'beta', 'alpha', 'demo', 'prototype', 'sandbox',
                
                # Infrastructure
                'cdn', 'cache', 'static', 'assets', 'media', 'img', 'images', 'css', 'js',
                'download', 'downloads', 'upload', 'uploads', 'file', 'files', 'storage',
                
                # Security
                'secure', 'security', 'ssl', 'vpn', 'auth', 'login', 'sso', 'ldap', 'firewall',
                'waf', 'proxy', 'gateway', 'fw',
                
                # Monitoring and status
                'monitor', 'monitoring', 'status', 'health', 'stats', 'statistics', 'graph',
                'graphs', 'metrics', 'prometheus', 'grafana',
                
                # Collaboration and tools
                'git', 'svn', 'jenkins', 'jira', 'confluence', 'wiki', 'redmine', 'gitlab',
                'github', 'bitbucket', 'repo', 'build', 'ci', 'cd',
                
                # Database
                'db', 'database', 'sql', 'mysql', 'postgres', 'postgresql', 'mongo', 'redis',
                'elasticsearch', 'solr', 'graphql',
                
                # Business functions
                'shop', 'store', 'cart', 'checkout', 'payment', 'pay', 'billing', 'bill',
                'crm', 'erp', 'hr', 'support', 'help', 'desk', 'ticket', 'tickets'
            ]
            wordlist.update(common)

            # Create wordlists directory if it doesn't exist
            os.makedirs("wordlists", exist_ok=True)

            # Load from multiple wordlist files
            wordlist_files = [
                "wordlists/subdomains.txt",
                "wordlists/subdomains-top1mil.txt",
                "wordlists/subdomains-top1mil-5000.txt",
                "wordlists/deepmagic.com-prefixes-top500.txt",
                "wordlists/dns-jhaddix.txt",
                "wordlists/combined_subdomains.txt"
            ]
            
            for wordlist_file in wordlist_files:
                if os.path.exists(wordlist_file):
                    with open(wordlist_file, 'r') as f:
                        wordlist.update(f.read().splitlines())

            # Generate additional combinations
            base_words = list(wordlist)[:100]  # Use top 100 words for combinations
            for word in base_words:
                # Add number suffixes
                for i in range(5):
                    wordlist.add(f"{word}{i}")
                    wordlist.add(f"{word}-{i}")
                
                # Add common prefixes/suffixes
                for affix in ['api', 'app', 'web', 'dev', 'prod', 'stage', 'test']:
                    wordlist.add(f"{affix}-{word}")
                    wordlist.add(f"{word}-{affix}")

        except Exception as e:
            logger.error(f"Error loading wordlist: {e}")

        return list(wordlist)

    async def _check_dns(self, session, subdomain):
        """Check if a subdomain resolves with enhanced DNS checks"""
        try:
            # Try HTTPS first
            try:
                url = f"https://{subdomain}"
                async with session.get(url, timeout=5, ssl=False) as response:
                    if response.status != 404:
                        return subdomain
            except:
                pass

            # Try HTTP if HTTPS fails
            try:
                url = f"http://{subdomain}"
                async with session.get(url, timeout=5) as response:
                    if response.status != 404:
                        return subdomain
            except:
                pass

            # Try DNS resolution directly
            try:
                socket.gethostbyname(subdomain)
                return subdomain
            except socket.gaierror:
                pass

            # Try DNS resolution with alternative record types
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 2
                resolver.lifetime = 2
                
                # Check multiple record types
                for record_type in ['A', 'AAAA', 'CNAME', 'MX']:
                    try:
                        answers = resolver.resolve(subdomain, record_type)
                        if answers:
                            return subdomain
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                           dns.resolver.NoNameservers, dns.exception.Timeout):
                        continue
            except:
                pass

            return None
        except Exception as e:
            logger.debug(f"Error checking DNS for {subdomain}: {e}")
            return None

    async def check_subdomain_status(self, subdomains):
        """Check which subdomains are active using httpx with rate limiting and chunking"""
        try:
            # Split subdomains into chunks to avoid overwhelming the target
            chunk_size = 50
            active_subdomains = []
            total_chunks = len(subdomains) // chunk_size + (1 if len(subdomains) % chunk_size else 0)
            
            for i in range(0, len(subdomains), chunk_size):
                chunk = subdomains[i:i + chunk_size]
                chunk_num = i // chunk_size + 1
                logger.info(f"Processing chunk {chunk_num}/{total_chunks} ({len(chunk)} subdomains)")
                
                try:
                    # Run httpx with rate limiting and timeout
                    results = await self._run_with_timeout(
                        self._run_with_rate_limit(
                            tool_manager.run_httpx(chunk),
                            rate_limit=config.RATE_LIMIT_PER_MINUTE
                        ),
                        timeout=config.SCAN_TIMEOUT
                    )
                    
                    for result in results:
                        if isinstance(result, dict) and result.get('status-code', 0) != 0:
                            url = result.get('url')
                            if url:
                                active_subdomains.append(url)
                                logger.debug(f"Active subdomain found: {url}")
                    
                    # Add delay between chunks
                    if chunk_num < total_chunks:
                        await asyncio.sleep(1)
                        
                except Exception as chunk_error:
                    logger.error(f"Error processing chunk {chunk_num}: {chunk_error}")
                    continue
            
            logger.info(f"Found {len(active_subdomains)} active subdomains")
            return list(set(active_subdomains))
            
        except Exception as e:
            logger.error(f"Error checking subdomain status: {e}")
            return []
        finally:
            self._cleanup_temp_files()

    async def fetch_urls(self, subdomains):
        """
        Fetch URLs from subdomains using various sources with rate limiting and chunking
        Returns:
            tuple: (wayback_data, paramspider_data)
        """
        try:
            wayback_data = {}
            paramspider_data = {}
            
            # Process subdomains in chunks
            chunk_size = 10
            total_chunks = len(subdomains) // chunk_size + (1 if len(subdomains) % chunk_size else 0)
            
            for i in range(0, len(subdomains), chunk_size):
                chunk = subdomains[i:i + chunk_size]
                chunk_num = i // chunk_size + 1
                logger.info(f"Processing URL discovery chunk {chunk_num}/{total_chunks}")
                
                tasks = []
                for subdomain in chunk:
                    tasks.append(
                        self._run_with_timeout(
                            self._run_with_rate_limit(
                                tool_manager.run_gau(subdomain),
                                rate_limit=config.RATE_LIMIT_PER_MINUTE
                            ),
                            timeout=config.SCAN_TIMEOUT
                        )
                    )
                
                try:
                    chunk_results = await asyncio.gather(*tasks, return_exceptions=True)
                    
                    for subdomain, urls in zip(chunk, chunk_results):
                        if isinstance(urls, Exception):
                            logger.error(f"Error fetching URLs for {subdomain}: {urls}")
                            continue
                            
                        if urls:
                            # Filter and validate URLs
                            valid_urls = []
                            param_urls = []
                            for url_data in urls:
                                url = url_data.get('url', '')
                                if url and isinstance(url, str):
                                    valid_urls.append(url)
                                    if '?' in url:
                                        param_urls.append(url)
                            
                            if valid_urls:
                                wayback_data[subdomain] = valid_urls
                            if param_urls:
                                paramspider_data[subdomain] = param_urls
                    
                    # Add delay between chunks
                    if chunk_num < total_chunks:
                        await asyncio.sleep(1)
                        
                except Exception as chunk_error:
                    logger.error(f"Error processing URL discovery chunk {chunk_num}: {chunk_error}")
                    continue

            logger.info(f"Discovered URLs for {len(wayback_data)} subdomains")
            logger.info(f"Found parameters in URLs for {len(paramspider_data)} subdomains")
            return wayback_data, paramspider_data
            
        except Exception as e:
            logger.error(f"Error fetching URLs: {e}")
            return {}, {}
        finally:
            self._cleanup_temp_files()

    def _is_valid_subdomain(self, subdomain, domain):
        """Validate subdomain format and relationship to main domain"""
        try:
            if not subdomain:
                return False
            
            # Clean the subdomain
            subdomain = subdomain.strip().lower()
            subdomain = subdomain.replace('*.', '')
            
            # Basic validation
            if not subdomain.endswith(domain):
                return False
            if subdomain == domain:
                return False
            if '..' in subdomain:
                return False
            if subdomain.count('.') < 2:
                return False
            if len(subdomain) > 255:
                return False
            
            # Check for valid characters
            valid_chars = set('abcdefghijklmnopqrstuvwxyz0123456789-.')
            if not all(c in valid_chars for c in subdomain):
                return False
            
            return True
        except:
            return False

    async def scan(self, domain, session):
        """
        Main entry point for subdomain scanning. This method is called from app.py.
        
        Args:
            domain (str): The domain to scan for subdomains
            session (aiohttp.ClientSession): The session to use for HTTP requests
            
        Returns:
            dict: Results of the subdomain scan
        """
        try:
            logger.info(f"Starting subdomain scan for {domain}")
            
            # Find subdomains
            subdomains = await self.find_subdomains(domain)
            
            if not subdomains:
                logger.warning(f"No subdomains found for {domain}")
                return {
                    "subdomain_scan": {
                        "status": "completed",
                        "subdomains_found": 0,
                        "subdomains": [],
                        "urls_found": 0,
                        "urls": {}
                    }
                }
            
            # Check which subdomains are active
            active_subdomains = await self.check_subdomain_status(subdomains)
            
            # Fetch URLs from active subdomains
            wayback_data, paramspider_data = await self.fetch_urls(active_subdomains)
            
            # Combine all URLs for vulnerability scanning
            all_urls = []
            for subdomain_urls in wayback_data.values():
                all_urls.extend(subdomain_urls)
            
            # Store the results in the global context for other scanners to use
            global_scan_context = {
                "subdomains": active_subdomains,
                "wayback_urls": wayback_data,
                "paramspider_urls": paramspider_data,
                "all_urls": all_urls
            }
            
            # Store in a global variable that other scanners can access
            global subdomain_scan_results
            subdomain_scan_results = global_scan_context
            
            return {
                "subdomain_scan": {
                    "status": "completed",
                    "subdomains_found": len(active_subdomains),
                    "subdomains": active_subdomains,
                    "urls_found": len(all_urls),
                    "urls": {
                        "wayback": wayback_data,
                        "paramspider": paramspider_data
                    }
                }
            }
            
        except Exception as e:
            logger.error(f"Error in subdomain scan: {e}")
            return {
                "subdomain_scan": {
                    "status": "error",
                    "error": str(e)
                }
            }

# Create a global instance
subdomain_scanner = SubdomainScanner()

# Global variable to store subdomain scan results
subdomain_scan_results = None

async def subdomain_scanner_wrapper(domain, session):
    """
    Wrapper function for the subdomain scanner.
    This is the function that's imported and called from app.py.
    """
    return await subdomain_scanner.scan(domain, session)

# Replace the global instance with the wrapper function
subdomain_scanner = subdomain_scanner_wrapper
