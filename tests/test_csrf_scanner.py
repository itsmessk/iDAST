import os
import sys
import asyncio
from pathlib import Path

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from csrf_scanner import CSRFScanner
from logger import get_logger

logger = get_logger(__name__)

async def test_csrf():
    """
    Test the CSRF scanner functionality
    """
    try:
        logger.info("Starting CSRF scan test...")
        
        # Initialize scanner
        scanner = CSRFScanner()
        
        # Test domain with known forms
        domain = "http://testphp.vulnweb.com"
        logger.info(f"\nScanning domain: {domain}")
        
        # Run the scan
        results = await scanner.scan(domain)
        
        # Process and display results
        logger.info("\nScan Results:")
        if not results:
            logger.info("No CSRF vulnerabilities found.")
            return
            
        for url, data in results.items():
            logger.info(f"\nVulnerable Form Found at: {url}")
            logger.info(f"Method: {data['method']}")
            logger.info(f"Risk Level: {data['risk_level']}")
            logger.info("\nMissing Protections:")
            for protection in data['missing_protections']:
                logger.info(f"- {protection}")
                
            logger.info("\nRecommendations:")
            for rec in data['recommendations']:
                logger.info(f"- {rec}")
                
    except Exception as e:
        logger.error(f"Error in CSRF test: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(test_csrf())
