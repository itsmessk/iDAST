import asyncio
import os
import json
import httpx
from pathlib import Path
import subprocess
from logger import get_logger
from utils import create_directory_if_not_exists, extract_domain_from_url
from config import config

logger = get_logger('subdomain_scanner')

class SubdomainScanner:
    """Class for scanning subdomains and collecting URLs."""
    
    def __init__(self):
        """Initialize the subdomain scanner."""
        self.results_dir = config.RESULTS_DIR
        create_directory_if_not_exists(self.results_dir)
    
    async def run_tool_async(self, command):
        """
        Run external tools asynchronously using subprocess.
        
        Args:
            command (list): Command to run as a list of arguments.
            
        Returns:
            list: Lines of output from the command.
        """
        logger.info(f"Running command: {' '.join(command)}")
        
        try:
            process = await asyncio.create_subprocess_exec(
                *command, 
                stdout=asyncio.subprocess.PIPE, 
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if stderr:
                logger.warning(f"Command stderr: {stderr.decode('utf-8')}")
            
            output = stdout.decode('utf-8').splitlines()
            logger.info(f"Command completed successfully, returned {len(output)} lines")
            return output
        except Exception as e:
            logger.error(f"Error running command {command}: {e}")
            return []
    
    async def find_subdomains(self, domain):
        """
        Use subfinder and assetfinder to find subdomains asynchronously.
        
        Args:
            domain (str): The domain to scan.
            
        Returns:
            list: List of discovered subdomains.
        """
        domain = extract_domain_from_url(domain)
        logger.info(f"Finding subdomains for {domain} using subfinder and assetfinder...")
        
        try:
            # Run subfinder and assetfinder concurrently
            subfinder_task = self.run_tool_async(['subfinder', '-d', domain])
            assetfinder_task = self.run_tool_async(['assetfinder', '--subs-only', domain])
            
            subfinder_subs, assetfinder_subs = await asyncio.gather(subfinder_task, assetfinder_task)
            
            # Combine and deduplicate results
            all_subdomains = list(set(subfinder_subs + assetfinder_subs))
            
            logger.info(f"Found {len(all_subdomains)} unique subdomains")
            return all_subdomains
        except Exception as e:
            logger.error(f"Error finding subdomains for {domain}: {e}")
            return []
    
    async def check_subdomain_status(self, subdomains):
        """
        Check HTTP status of subdomains using httpx.
        
        Args:
            subdomains (list): List of subdomains to check.
            
        Returns:
            list: List of dictionaries with subdomain and status information.
        """
        logger.info(f"Checking HTTP status for {len(subdomains)} subdomains...")
        
        results = []
        
        try:
            # Use connection pooling and limits for better performance
            limits = httpx.Limits(
                max_connections=config.MAX_CONNECTIONS,
                max_keepalive_connections=20
            )
            
            async with httpx.AsyncClient(
                timeout=config.REQUEST_TIMEOUT,
                limits=limits,
                follow_redirects=True
            ) as client:
                # Create tasks for all subdomains
                tasks = []
                for subdomain in subdomains:
                    # Try both HTTP and HTTPS
                    tasks.append(self._check_subdomain_url(client, f"http://{subdomain}", subdomain))
                    tasks.append(self._check_subdomain_url(client, f"https://{subdomain}", subdomain))
                
                # Run all tasks concurrently
                all_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Process results, filtering out exceptions and None results
                for result in all_results:
                    if isinstance(result, dict) and result not in results:
                        results.append(result)
            
            logger.info(f"Found {len(results)} active subdomains")
            return results
        except Exception as e:
            logger.error(f"Error checking subdomain status: {e}")
            return []
    
    async def _check_subdomain_url(self, client, url, subdomain):
        """
        Check a single subdomain URL.
        
        Args:
            client (httpx.AsyncClient): HTTP client to use.
            url (str): URL to check.
            subdomain (str): Subdomain being checked.
            
        Returns:
            dict: Subdomain status information or None if error.
        """
        try:
            response = await client.get(url)
            
            # Only return successful responses
            if response.status_code in [200, 301, 302, 307, 308]:
                return {
                    "subdomain": subdomain,
                    "url": url,
                    "status_code": response.status_code,
                    "title": self._extract_title(response.text),
                    "content_type": response.headers.get("content-type", ""),
                    "server": response.headers.get("server", "")
                }
            return None
        except Exception as e:
            logger.debug(f"Error checking {url}: {e}")
            return None
    
    def _extract_title(self, html):
        """
        Extract title from HTML content.
        
        Args:
            html (str): HTML content.
            
        Returns:
            str: Page title or empty string.
        """
        try:
            import re
            title_match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
            if title_match:
                return title_match.group(1).strip()
            return ""
        except Exception:
            return ""
    
    async def fetch_urls(self, active_subdomains):
        """
        Fetch URLs from Wayback URLs and Paramspider for validated subdomains.
        
        Args:
            active_subdomains (list): List of active subdomains with status information.
            
        Returns:
            tuple: (wayback_data, paramspider_data) dictionaries.
        """
        logger.info(f"Fetching URLs from Wayback and Paramspider for {len(active_subdomains)} subdomains...")
        
        wayback_data = {}
        paramspider_data = {}
        
        try:
            # Create tasks for all subdomains
            wayback_tasks = []
            paramspider_tasks = []
            
            for subdomain_info in active_subdomains:
                subdomain = subdomain_info["subdomain"]
                wayback_tasks.append(self.run_tool_async(['waybackurls', subdomain]))
                paramspider_tasks.append(self.run_tool_async(['paramspider', '--domain', subdomain]))
            
            # Run wayback tasks concurrently
            wayback_results = await asyncio.gather(*wayback_tasks, return_exceptions=True)
            
            # Process wayback results
            for i, result in enumerate(wayback_results):
                if isinstance(result, list):
                    subdomain = active_subdomains[i]["subdomain"]
                    wayback_data[subdomain] = result
            
            # Run paramspider tasks concurrently
            paramspider_results = await asyncio.gather(*paramspider_tasks, return_exceptions=True)
            
            # Process paramspider results
            for i, result in enumerate(paramspider_results):
                if isinstance(result, list):
                    subdomain = active_subdomains[i]["subdomain"]
                    paramspider_data[subdomain] = result
            
            # Consolidate paramspider results from files
            paramspider_data = await self.consolidate_paramspider_results()
            
            logger.info(f"Fetched URLs for {len(wayback_data)} subdomains from Wayback")
            logger.info(f"Fetched URLs for {len(paramspider_data)} subdomains from Paramspider")
            
            return wayback_data, paramspider_data
        except Exception as e:
            logger.error(f"Error fetching URLs: {e}")
            return wayback_data, paramspider_data
    
    async def consolidate_paramspider_results(self):
        """
        Consolidate Paramspider results stored in a directory.
        
        Returns:
            dict: Consolidated Paramspider results by subdomain.
        """
        paramspider_data = {}
        results_dir = Path('results')
        
        try:
            if not results_dir.exists():
                logger.warning(f"Results directory {results_dir} does not exist")
                return paramspider_data
            
            # Find all Paramspider output files
            for file_path in results_dir.glob('*.txt'):
                try:
                    subdomain = file_path.stem
                    with open(file_path, 'r') as f:
                        urls = [line.strip() for line in f if line.strip()]
                    
                    paramspider_data[subdomain] = urls
                    logger.debug(f"Loaded {len(urls)} URLs from {file_path}")
                except Exception as e:
                    logger.error(f"Error processing Paramspider file {file_path}: {e}")
            
            logger.info(f"Consolidated Paramspider results for {len(paramspider_data)} subdomains")
            return paramspider_data
        except Exception as e:
            logger.error(f"Error consolidating Paramspider results: {e}")
            return paramspider_data

# Create a global instance
subdomain_scanner = SubdomainScanner()
