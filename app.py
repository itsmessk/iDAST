import asyncio
import os
import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse
import pytz
import logging
import logging.handlers
from functools import wraps
from cachetools import TTLCache
import aiohttp
from aiohttp import ClientTimeout
import signal
import secrets
from typing import Dict, List, Optional, Union

from flask import Flask, jsonify, request, Response
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from werkzeug.middleware.proxy_fix import ProxyFix

# Import configuration and utility modules
from config import config
from logger import get_logger
from database import db
from utils import ensure_url_has_protocol, extract_domain_from_url, get_current_time, format_timestamp

# Import security scanner modules
from sqlmap_scanner import SQLMapScanner
from dalfox_scanner import DalfoxScanner
from csrf_scanner import CSRFScanner
from ssrf_scanner import SSRFScanner
from cors_scanner import CORSScanner
from lfi_scanner import LFIScanner
from smuggling_scanner import SmugglingScanner
from retirejs_scanner import RetireJSScanner
from autopoisoning_scanner import AutoPoisoningScanner
from ratelimit_scanner import RateLimitScanner
from xxe_scanner import XXEScanner
from crlf_scanner import CRLFScanner
from template_scanner import TemplateScanner
from subdomain_scanner import subdomain_scanner
from http_security import http_security
from dns_email_security import dns_email_security
from website_health import website_health

# Initialize logger
logger = get_logger('app')

# Initialize Flask application
app = Flask(__name__)

# Security headers
talisman = Talisman(
    app,
    force_https=True,
    strict_transport_security=True,
    session_cookie_secure=True,
    session_cookie_http_only=True,
    feature_policy={
        'geolocation': '\'none\'',
        'midi': '\'none\'',
        'notifications': '\'none\'',
        'push': '\'none\'',
        'sync-xhr': '\'none\'',
        'microphone': '\'none\'',
        'camera': '\'none\'',
        'magnetometer': '\'none\'',
        'gyroscope': '\'none\'',
        'speaker': '\'none\'',
        'vibrate': '\'none\'',
        'fullscreen': '\'none\'',
        'payment': '\'none\''
    }
)

# Configure CORS with strict settings
CORS(app, resources={
    r"/*": {
        "origins": config.ALLOWED_ORIGINS,
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "expose_headers": ["Content-Range", "X-Content-Range"],
        "supports_credentials": True,
        "max_age": 600
    }
})

# Configure proxy settings if behind a reverse proxy
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

# Initialize rate limiter with Redis backend for distributed setup
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri=config.REDIS_URL,
    strategy="fixed-window-elastic-expiry",
    default_limits=[
        "200 per day",
        "50 per hour",
        "5 per minute"
    ]
)

# Initialize cache with Redis for distributed caching
scan_cache = TTLCache(maxsize=1000, ttl=3600)  # Cache scan results for 1 hour

# Initialize timezones
SERVER_TZ = pytz.timezone(config.SERVER_TIMEZONE)
OUTPUT_TZ = pytz.timezone(config.OUTPUT_TIMEZONE)

# Global timeout settings
SCAN_TIMEOUT = ClientTimeout(total=config.SCAN_TIMEOUT)
REQUEST_TIMEOUT = ClientTimeout(total=config.REQUEST_TIMEOUT)

def require_api_key(f):
    """Decorator to require API key authentication."""
    @wraps(f)
    async def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return jsonify({"error": "No API key provided"}), 401

        try:
            # Validate API key and check expiration
            user = await db.validate_api_key(api_key)
            if not user:
                return jsonify({
                    "error": "Invalid or expired API key",
                    "message": "Please check your API key or contact support for renewal"
                }), 401

            # Add user to request context
            request.user = user
            return await f(*args, **kwargs)
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return jsonify({"error": "Authentication failed"}), 401

    return decorated

def validate_request_data(data: Dict) -> Optional[tuple]:
    """Validate request data."""
    if not data:
        return jsonify({"error": "No data provided"}), 400

    domain = data.get('domain')
    if not domain:
        return jsonify({"error": "Domain is required"}), 400

    scan_type = data.get('scan_type', 'quick')
    if scan_type not in ['quick', 'full', 'custom']:
        return jsonify({"error": "Invalid scan type"}), 400

    return None

class VulnerabilityScanner:
    """Class for orchestrating comprehensive vulnerability scanning."""
    
    def __init__(self):
        """Initialize the vulnerability scanner with component scanners."""
        self.sqlmap_scanner = SQLMapScanner()
        self.ssrf_scanner = SSRFScanner()
        self.csrf_scanner = CSRFScanner()
        self.dalfox_scanner = DalfoxScanner()
        self.cors_scanner = CORSScanner()
        self.lfi_scanner = LFIScanner()
        self.smuggling_scanner = SmugglingScanner()
        self.retirejs_scanner = RetireJSScanner()
        self.autopoisoning_scanner = AutoPoisoningScanner()
        self.ratelimit_scanner = RateLimitScanner()
        self.xxe_scanner = XXEScanner()
        self.crlf_scanner = CRLFScanner()
        self.template_scanner = TemplateScanner()
        self.results_dir = config.RESULTS_DIR
        self.setup_folders()
        self.session = None
        logger.info("VulnerabilityScanner initialized with all modules")
    
    async def initialize(self):
        """Initialize aiohttp session with connection pooling."""
        if not self.session:
            connector = aiohttp.TCPConnector(
                limit=config.MAX_CONCURRENT_CONNECTIONS,
                ttl_dns_cache=300,
                use_dns_cache=True
            )
            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=SCAN_TIMEOUT,
                headers={'User-Agent': config.USER_AGENT}
            )
    
    async def cleanup(self):
        """Cleanup resources."""
        if self.session:
            await self.session.close()
            self.session = None
    
    def setup_folders(self):
        """Create necessary folders for scan results."""
        try:
            os.makedirs(self.results_dir, exist_ok=True)
            logger.debug(f"Created results directory: {self.results_dir}")
        except Exception as e:
            logger.error(f"Error creating results directory: {e}")
            raise

    # ... [Rest of the VulnerabilityScanner class implementation remains the same] ...

# Create a global vulnerability scanner instance
vulnerability_scanner = VulnerabilityScanner()

@app.before_request
def before_request():
    """Pre-request processing."""
    request.start_time = time.time()

@app.after_request
def after_request(response: Response) -> Response:
    """Post-request processing."""
    # Add security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Server'] = 'SecPro'
    
    # Add request processing time
    if hasattr(request, 'start_time'):
        process_time = time.time() - request.start_time
        response.headers['X-Process-Time'] = str(process_time)
    
    return response

@app.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limit exceeded."""
    return jsonify({
        "error": "Rate limit exceeded",
        "message": str(e.description)
    }), 429

@app.route('/')
@limiter.exempt
async def index():
    """API root endpoint."""
    return jsonify({
        'name': 'SecPro API',
        'version': config.VERSION,
        'status': 'running',
        'endpoints': {
            'health': '/health',
            'scan': '/scan'
        }
    })

@app.route('/health')
@limiter.exempt
async def health_check():
    """API health check endpoint."""
    try:
        # Check MongoDB connection
        is_healthy = await db.ping()
        if not is_healthy:
            raise Exception("Database ping failed")
        
        return jsonify({
            'status': 'healthy',
            'timestamp': format_timestamp(),
            'version': config.VERSION,
            'environment': config.FLASK_ENV
        })
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': format_timestamp()
        }), 503

@app.route('/scan', methods=['POST'])
@limiter.limit(config.SCAN_RATE_LIMIT)
@require_api_key
async def scan_domain():
    """API endpoint to scan a domain for security vulnerabilities."""
    try:
        # Validate request data
        data = request.json
        validation_error = validate_request_data(data)
        if validation_error:
            return validation_error
targetid = data.get('targetid')
if not targetid:
    return jsonify({"error": "Target ID is required"}), 400

# Extract domain from target ID (format: target_domain_timestamp_suffix)
try:
    target_parts = targetid.split('_')
    if len(target_parts) < 4 or target_parts[0] != 'target':
        return jsonify({"error": "Invalid target ID format"}), 400
    domain = target_parts[1]
except Exception as e:
    logger.error(f"Error parsing target ID: {e}")
    return jsonify({"error": "Invalid target ID format"}), 400

userid = request.user.get('id')
scan_type = data.get('scan_type', 'quick')

# Check cache
cache_hit = scan_cache.get(f"{domain}:{scan_type}:{userid}")
if cache_hit:
    logger.info(f"Returning cached results for {domain}")
    return jsonify(cache_hit)

# Process domain/URL for validation
parsed_url = urlparse(ensure_url_has_protocol(domain))
validated_domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path

# Ensure the domain matches the target ID
if validated_domain != domain:
    return jsonify({"error": "Domain mismatch with target ID"}), 400
        domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path
        
        logger.info(f"Starting {scan_type} scan for {domain} (User: {userid}, Target: {targetid})")
        
        # Record scan start time
        start_time = get_current_time()
        
        # Initialize scan results structure
        scan_results = {
            "domain": domain,
            "scan_type": scan_type,
            "scan_start_time": format_timestamp(start_time),
            "scan_status": "in_progress",
            "request_id": secrets.token_hex(16),
            "target": {
                "id": targetid,
                "domain": domain,
                "scan_count": await db.get_scan_count(targetid) + 1,
                "last_scan": format_timestamp(start_time)
            }
        }
        
        try:
            # Run all scans with timeout
            async with asyncio.timeout(config.TOTAL_SCAN_TIMEOUT):
                # ... [Rest of the scan implementation remains the same] ...
                pass

        except asyncio.TimeoutError:
            scan_results.update({
                "scan_status": "timeout",
                "error": f"Scan timed out after {config.TOTAL_SCAN_TIMEOUT} seconds"
            })
        
        # Store results
        if config.ENABLE_DATABASE and targetid:
            await db.store_scan_results(targetid, scan_results)
        
        # Cache results
        scan_cache[f"{domain}:{scan_type}:{userid}"] = scan_results
        
        return jsonify(scan_results)
        
    except Exception as e:
        logger.error(f"Error during scan: {str(e)}")
        return jsonify({
            "error": "Internal server error",
            "message": str(e) if config.DEBUG_MODE else "An unexpected error occurred",
            "request_id": getattr(request, 'request_id', None)
        }), 500

async def shutdown_event():
    """Cleanup on shutdown."""
    logger.info("Shutting down application...")
    await vulnerability_scanner.cleanup()
    # Close other connections (Redis, MongoDB, etc.)
    await db.close()

# Register shutdown handler
signal.signal(signal.SIGTERM, lambda s, f: asyncio.create_task(shutdown_event()))
signal.signal(signal.SIGINT, lambda s, f: asyncio.create_task(shutdown_event()))

if __name__ == '__main__':
    port = int(os.getenv('PORT', 3000))
    app.run(
        host='0.0.0.0',
        port=port,
        debug=config.DEBUG_MODE
    )
