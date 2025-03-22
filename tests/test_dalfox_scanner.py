import os
import sys
import asyncio
from pathlib import Path

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from dalfox_scanner import DalfoxScanner
from logger import get_logger

logger = get_logger(__name__)

async def test_dalfox():
    """Test the Dalfox scanner functionality"""
    try:
        logger.info("Starting Dalfox scan test...")
        
        # Initialize scanner
        scanner = DalfoxScanner()
        
        # Test URLs with potential vulnerabilities
        test_urls = [
            "http://testphp.vulnweb.com/search.php?test=query",
            "http://testphp.vulnweb.com/redir.php?r=http://example.com",
            "http://testphp.vulnweb.com/showimage.php?file=",
            "http://testphp.vulnweb.com/artists.php?artist=1"
        ]
        
        domain = "testphp.vulnweb.com"
        
        # Run the scan
        results = await scanner.scan_urls(test_urls, domain)
        
        # Display results
        logger.info("\nScan Results:")
        if not results['vulnerabilities']:
            logger.info("No vulnerabilities found.")
            return
            
        for vuln in results['vulnerabilities']:
            logger.info(f"\nVulnerability Type: {vuln['type']}")
            logger.info(f"URL: {vuln['url']}")
            logger.info(f"Parameter: {vuln['parameter']}")
            logger.info(f"Severity: {vuln['severity']}")
            logger.info(f"Payload: {vuln['payload']}")
            logger.info(f"Proof: {vuln['proof']}")
            
        logger.info("\nRecommendations:")
        for rec in results['recommendations']:
            logger.info(f"- {rec}")
            
    except Exception as e:
        logger.error(f"Error in Dalfox test: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(test_dalfox())
