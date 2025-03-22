import asyncio
from test_sqlmap_scanner import test_sqlmap
from test_csrf_scanner import test_csrf
from test_ssrf_scanner import test_ssrf
from test_dalfox_scanner import test_dalfox
from logger import get_logger

logger = get_logger(__name__)

async def run_all_tests():
    """Run all scanner tests"""
    tests = {
        'SQLMap Scanner': test_sqlmap,
        'CSRF Scanner': test_csrf,
        'SSRF Scanner': test_ssrf,
        'Dalfox XSS Scanner': test_dalfox
    }
    
    results = {}
    
    for name, test_func in tests.items():
        logger.info(f"\nRunning {name} test...")
        try:
            success = await test_func()
            results[name] = 'PASSED' if success else 'FAILED'
        except Exception as e:
            logger.error(f"Error running {name} test: {e}")
            results[name] = 'ERROR'
    
    # Print summary
    logger.info("\n=== Test Results Summary ===")
    for name, status in results.items():
        logger.info(f"{name}: {status}")

if __name__ == "__main__":
    asyncio.run(run_all_tests())
