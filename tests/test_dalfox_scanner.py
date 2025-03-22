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
        logger.info("Starting Dalfox XSS scan test...")
        
        # Initialize scanner
        scanner = DalfoxScanner()
        
        # Test URLs with potential XSS vulnerabilities
        test_urls = [
            "http://testphp.vulnweb.com/search.php?test=query",
            "http://testphp.vulnweb.com/artists.php?artist=1",
            "http://testphp.vulnweb.com/guestbook.php?name=test",
            "http://testphp.vulnweb.com/comment.php?aid=1"
        ]
        
        domain = "testphp.vulnweb.com"
        logger.info(f"Scanning {len(test_urls)} URLs for domain: {domain}")
        
        # Run the scan
        results = await scanner.scan_urls(test_urls, domain)
        
        # Display results
        logger.info("\nScan Results:")
        if not results.get('vulnerabilities'):
            logger.info("No XSS vulnerabilities found.")
            return
        
        vuln_count = len(results['vulnerabilities'])
        logger.info(f"\nFound {vuln_count} XSS vulnerabilities:")
        
        # Display each vulnerability with details
        for i, vuln in enumerate(results['vulnerabilities'], 1):
            logger.info(f"\n=== Vulnerability #{i} ===")
            logger.info(f"URL: {vuln['url']}")
            logger.info(f"Parameter: {vuln['parameter']}")
            logger.info(f"Severity: {vuln['severity']}")
            logger.info(f"Payload: {vuln['payload']}")
            
            if 'details' in vuln:
                logger.info("\nDetails:")
                logger.info(f"Description: {vuln['details']['description']}")
                logger.info(f"Impact: {vuln['details']['impact']}")
                logger.info("\nMitigation Steps:")
                for step in vuln['details']['mitigation']:
                    logger.info(f"  {step}")
        
        # Display recommendations
        if results.get('recommendations'):
            logger.info("\n=== General Recommendations ===")
            for rec in results['recommendations']:
                logger.info(f"- {rec}")
            
    except Exception as e:
        logger.error(f"Error in Dalfox test: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(test_dalfox())
