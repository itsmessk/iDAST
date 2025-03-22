# dalfox_scanner.py

import os
import json
import asyncio
from datetime import datetime
from logger import get_logger

logger = get_logger(__name__)

class DalfoxScanner:
    def __init__(self):
        self.results_dir = os.path.join('tests', 'dalfox_results')
        os.makedirs(self.results_dir, exist_ok=True)

    async def scan_urls(self, urls, domain):
        """
        Scan multiple URLs for XSS vulnerabilities using Dalfox
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        urls_file = os.path.join(self.results_dir, f'urls_{domain}_{timestamp}.txt')
        output_file = os.path.join(self.results_dir, f'dalfox_{domain}_{timestamp}.txt')
        
        # Write URLs to file
        with open(urls_file, 'w') as f:
            for url in urls:
                f.write(f"{url}\n")
        
        # Prepare Dalfox command
        cmd = f'dalfox file {urls_file} -o {output_file} --format json --silence --skip-bav --mass'
        logger.info(f"Starting Dalfox scan with command: {cmd}")
        
        try:
            # Run Dalfox scan
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            
            if process.returncode == 0:
                logger.info("Dalfox scan completed successfully")
                
                # Read and parse results
                if os.path.exists(output_file):
                    with open(output_file, 'r') as f:
                        content = f.read()
                        if content:
                            results = {}
                            try:
                                findings = json.loads(content)
                                # Group findings by URL
                                for finding in findings:
                                    if not finding:  # Skip empty findings
                                        continue
                                    url = finding.get('data', '')
                                    if url:
                                        if url not in results:
                                            results[url] = {'vulnerabilities': []}
                                        results[url]['vulnerabilities'].append(finding)
                                return results
                            except json.JSONDecodeError:
                                logger.error("Failed to parse Dalfox results JSON")
                                return {}
            else:
                logger.error("Dalfox scan failed")
                return {}
                
        except Exception as e:
            logger.error(f"Error during Dalfox scan: {e}")
            return {}
        
        return {}