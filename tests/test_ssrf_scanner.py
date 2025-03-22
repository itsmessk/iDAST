import os
import sys
import asyncio
from pathlib import Path

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from ssrf_scanner import SSRFScanner
from logger import get_logger

logger = get_logger(__name__)

async def test_ssrf():
    """
    Test the SSRF scanner functionality
    """
    try:
        logger.info("Starting SSRF scan test...")
        
        # Initialize scanner
        scanner = SSRFScanner()
        
        # Test URLs with potential SSRF vulnerabilities
        test_urls = [
            "http://testphp.vulnweb.com/showimage.php?file=",
            "http://testphp.vulnweb.com/redir.php?r=",
            "http://testphp.vulnweb.com/loading.php?src="
        ]
        
        logger.info(f"Starting SSRF scan for {len(test_urls)} URLs")
        
        # Run the scan
        results = await scanner.scan_urls(test_urls)
        
        # Process and display results
        logger.info("\nScan Results:")
        if not results:
            logger.info("No SSRF vulnerabilities found.")
            return
            
        for url, data in results.items():
            logger.info(f"\nVulnerable URL: {url}")
            logger.info(f"Risk Level: {data['risk_level']}")
            logger.info(f"CWE: {data['cwe']}")
            
            logger.info("\nVulnerabilities Found:")
            for vuln in data['vulnerabilities']:
                logger.info(f"\n- Parameter: {vuln['parameter']}")
                logger.info(f"  Payload: {vuln['payload']}")
                logger.info(f"  Evidence: {vuln['evidence']}")
                
                logger.info("\n  Test Results:")
                for test in vuln['test_results']:
                    logger.info(f"  - {test['test']}: {test['result']}")
            
            logger.info("\nRecommendations:")
            for rec in data['recommendations']:
                logger.info(f"- {rec}")
                
    except Exception as e:
        logger.error(f"Error in SSRF test: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(test_ssrf())
