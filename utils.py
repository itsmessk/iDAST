import asyncio
import os
import shutil
import socket
import ssl
import time
from datetime import datetime
from urllib.parse import urlparse
import pytz
import dns.resolver
import dns.asyncresolver
import httpx
import requests
from config import config
from logger import get_logger

logger = get_logger('utils')

def ensure_url_has_protocol(url):
    """Ensure URL has a protocol prefix."""
    if not url.startswith(('http://', 'https://')):
        return f'https://{url}'
    return url

def extract_domain_from_url(url):
    """Extract domain from URL."""
    parsed_url = urlparse(url)
    return parsed_url.netloc if parsed_url.netloc else parsed_url.path

def create_directory_if_not_exists(directory):
    """Create directory if it doesn't exist."""
    os.makedirs(directory, exist_ok=True)
    logger.debug(f"Ensured directory exists: {directory}")

def remove_directory_if_exists(directory):
    """Remove directory if it exists."""
    if os.path.exists(directory):
        shutil.rmtree(directory)
        logger.debug(f"Removed directory: {directory}")

def get_current_time(timezone=None):
    """Get current time in specified timezone."""
    tz = pytz.timezone(timezone or config.OUTPUT_TIMEZONE)
    return datetime.now(tz)

def format_timestamp(dt=None, timezone=None):
    """Format datetime as ISO 8601 string."""
    if dt is None:
        dt = get_current_time(timezone)
    return dt.isoformat()

async def make_http_request(url, method='GET', timeout=None, **kwargs):
    """Make HTTP request with timeout and error handling."""
    timeout = timeout or config.REQUEST_TIMEOUT
    url = ensure_url_has_protocol(url)
    
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            start_time = time.time()
            response = await client.request(method, url, **kwargs)
            response_time = (time.time() - start_time) * 1000  # ms
            
            logger.debug(f"HTTP {method} request to {url} completed in {response_time:.2f}ms with status {response.status_code}")
            return response
    except httpx.TimeoutException:
        logger.warning(f"HTTP request to {url} timed out after {timeout}s")
        raise
    except httpx.RequestError as e:
        logger.error(f"HTTP request to {url} failed: {e}")
        raise

async def resolve_dns(domain, record_type='A'):
    """Resolve DNS records for a domain."""
    try:
        resolver = dns.asyncresolver.Resolver()
        results = await resolver.resolve(domain, record_type)
        return [str(rdata) for rdata in results]
    except Exception as e:
        logger.warning(f"DNS resolution failed for {domain} ({record_type}): {e}")
        return []

def is_valid_ip(ip):
    """Check if string is a valid IP address."""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def is_internal_ip(ip):
    """Check if IP address is in private IP ranges."""
    # Check for localhost
    if ip.startswith('127.'):
        return True
    
    # Check for private IP ranges
    private_ranges = [
        ('10.0.0.0', '10.255.255.255'),     # 10.0.0.0/8
        ('172.16.0.0', '172.31.255.255'),   # 172.16.0.0/12
        ('192.168.0.0', '192.168.255.255')  # 192.168.0.0/16
    ]
    
    # Convert IP to integer for range comparison
    ip_int = int(''.join([f'{int(octet):08b}' for octet in ip.split('.')]), 2)
    
    for start, end in private_ranges:
        start_int = int(''.join([f'{int(octet):08b}' for octet in start.split('.')]), 2)
        end_int = int(''.join([f'{int(octet):08b}' for octet in end.split('.')]), 2)
        if start_int <= ip_int <= end_int:
            return True
    
    return False

def check_ssl_certificate(domain):
    """Check SSL certificate for a domain."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # Extract certificate information
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                issuer = dict(x[0] for x in cert['issuer'])
                subject = dict(x[0] for x in cert['subject'])
                
                # Check if certificate is valid
                now = datetime.now()
                is_valid = not_before <= now <= not_after
                
                return {
                    'valid': is_valid,
                    'issuer': issuer.get('organizationName', 'Unknown'),
                    'subject': subject.get('commonName', 'Unknown'),
                    'valid_from': not_before.isoformat(),
                    'valid_until': not_after.isoformat(),
                    'days_remaining': (not_after - now).days
                }
    except Exception as e:
        logger.error(f"SSL certificate check failed for {domain}: {e}")
        return {
            'valid': False,
            'error': str(e)
        }
