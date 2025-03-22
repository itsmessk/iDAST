import asyncio
import sys
import os
import json
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlmap_scanner import SQLMapScanner
from logger import get_logger

logger = get_logger('sqlmap_test')

async def test_sqlmap():
    scanner = SQLMapScanner()
    
    # Test URLs with known SQL injection vulnerabilities
    test_urls = [
        "http://testphp.vulnweb.com/artists.php?artist=1",
        "http://testphp.vulnweb.com/listproducts.php?cat=1",
        "http://testphp.vulnweb.com/product.php?pic=1"
    ]
    
    try:
        logger.info("Starting SQLMap scan test...")
        results = await scanner.scan_urls(test_urls)
        
        logger.info("\n=== SQL Injection Scan Results ===")
        for url, result in results.items():
            logger.info(f"\nTarget URL: {url}")
            
            if result.get('is_vulnerable'):
                logger.info("Status: VULNERABLE")
                
                # Display injection points
                if result.get('injection_points'):
                    logger.info("\nInjection Points Found:")
                    for point in result.get('injection_points', []):
                        logger.info(f"\nParameter: {point.get('parameter')}")
                        logger.info(f"Type: {point.get('type')}")
                        logger.info(f"Title: {point.get('title')}")
                        
                        # Show POC
                        logger.info("\nProof of Concept:")
                        logger.info(f"Payload: {point.get('payload')}")
                        if point.get('data'):
                            logger.info(f"Data: {point.get('data')}")
                
                # Display database info if available
                if result.get('dbms_info'):
                    logger.info("\nDatabase Information:")
                    dbms = result['dbms_info']
                    logger.info(f"Type: {dbms.get('type')}")
                    logger.info(f"Version: {dbms.get('version')}")
                    logger.info(f"Technology: {dbms.get('technology')}")
                
                # Add recommendations
                logger.info("\nRecommendations:")
                logger.info("1. Use parameterized queries or prepared statements")
                logger.info("2. Implement proper input validation")
                logger.info("3. Apply the principle of least privilege for database users")
                logger.info("4. Enable WAF rules for SQL injection protection")
                logger.info("5. Regularly update and patch database software")
                
                # Risk Assessment
                logger.info("\nRisk Assessment:")
                logger.info("Severity: HIGH")
                logger.info("Impact: Potential data breach, unauthorized access to database")
                logger.info("CVSS Score: 9.8 (Critical)")
            else:
                logger.info("Status: NOT VULNERABLE")
            
            logger.info("-" * 50)
        
        return results
    except Exception as e:
        logger.error(f"Error in SQLMap test: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(test_sqlmap())
