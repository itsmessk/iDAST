import asyncio
import time
import socket
import ssl
from datetime import datetime
import aiohttp
import httpx
import re
from urllib.parse import urlparse, urljoin
from utils import ensure_url_has_protocol, resolve_dns, check_ssl_certificate
from logger import get_logger
from config import config

logger = get_logger('website_health')

class WebsiteHealthChecker:
    """Class for checking website health and performance."""
    
    def __init__(self):
        """Initialize the website health checker."""
        self.request_timeout = config.REQUEST_TIMEOUT
        self.max_redirects = 5
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        self.security_headers = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection',
            'Referrer-Policy'
        ]
    
    async def check_website_health(self, url):
        """
        Perform comprehensive health checks on a website asynchronously.
        
        Args:
            url (str): The website URL to check
            
        Returns:
            dict: Detailed health check results with units
        """
        url = ensure_url_has_protocol(url)
        logger.info(f"Checking website health for {url}")
        
        health_results = {
            'timestamp': datetime.now().isoformat(),
            'url': url,
            'basic_checks': {},
            'dns_checks': {},
            'performance': {},
            'ssl_checks': {},
            'security_headers': {},
            'accessibility': {},
            'errors': []
        }
        
        try:
            # Run all checks concurrently
            tasks = [
                self._check_basic_connection(url),
                self._check_dns(url),
                self._check_performance(url),
                self._check_ssl(url),
                self._check_security_headers(url),
                self._check_accessibility(url)
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    error_msg = f"Error in check {tasks[i].__name__}: {str(result)}"
                    health_results['errors'].append(error_msg)
                    logger.error(error_msg)
                else:
                    check_name = tasks[i].__name__.lstrip('_').replace('check_', '')
                    health_results[check_name] = result
            
            # Add overall health score and status
            health_score = self._calculate_health_score(health_results)
            health_results['health_score'] = health_score
            health_results['overall_status'] = self._determine_overall_status(health_results)
            
            # Add recommendations
            health_results['recommendations'] = self._generate_recommendations(health_results)
            
            logger.info(f"Website health check completed for {url}: Score {health_score}/100")
            return health_results
            
        except Exception as e:
            error_msg = f"Critical error checking website health for {url}: {str(e)}"
            logger.error(error_msg)
            health_results['errors'].append(error_msg)
            health_results['overall_status'] = 'Critical Error'
            return health_results
    
    async def _check_basic_connection(self, url):
        """Check basic HTTP/HTTPS connection to a website."""
        try:
            async with aiohttp.ClientSession(headers=self.headers) as session:
                start_time = time.time()
                async with session.get(url, timeout=self.request_timeout, 
                                    allow_redirects=True, 
                                    max_redirects=self.max_redirects) as response:
                    response_time = (time.time() - start_time) * 1000
                    content = await response.read()
                    
                    redirect_history = [str(resp.url) for resp in response.history]
                    
                    return {
                        'status_code': response.status,
                        'is_reachable': response.status < 400,
                        'response_time': f"{round(response_time, 2)} ms",
                        'response_time_ms': round(response_time, 2),
                        'server': response.headers.get('Server', 'Not specified'),
                        'content_type': response.headers.get('Content-Type', 'Not specified'),
                        'content_length': f"{len(content) // 1024} KB",
                        'content_length_kb': len(content) // 1024,
                        'redirects': redirect_history,
                        'final_url': str(response.url),
                        'compression': response.headers.get('Content-Encoding', 'None')
                    }
        except Exception as e:
            logger.warning(f"Connection error for {url}: {e}")
            return {
                'is_reachable': False,
                'error': str(e)
            }
    
    async def _check_dns(self, url):
        """Check DNS records for a domain."""
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.split(':')[0]  # Remove port if present
        
        try:
            # Resolve different DNS record types concurrently
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
            tasks = [resolve_dns(domain, record_type) for record_type in record_types]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            dns_results = {}
            
            for record_type, result in zip(record_types, results):
                if isinstance(result, Exception):
                    dns_results[f'{record_type.lower()}_records'] = []
                    logger.warning(f"Error resolving {record_type} records for {domain}: {result}")
                else:
                    dns_results[f'{record_type.lower()}_records'] = result
            
            # Add analysis
            dns_results.update({
                'has_ipv4': len(dns_results.get('a_records', [])) > 0,
                'has_ipv6': len(dns_results.get('aaaa_records', [])) > 0,
                'has_mail_server': len(dns_results.get('mx_records', [])) > 0,
                'num_nameservers': len(dns_results.get('ns_records', [])),
                'has_spf': any('v=spf1' in txt.lower() for txt in dns_results.get('txt_records', [])),
                'has_dmarc': any('v=dmarc1' in txt.lower() for txt in dns_results.get('txt_records', []))
            })
            
            return dns_results
        except Exception as e:
            logger.warning(f"DNS check error for {domain}: {e}")
            return {'error': str(e)}
    
    async def _check_performance(self, url):
        """Check website performance metrics."""
        try:
            results = []
            num_requests = 3
            
            async with httpx.AsyncClient(timeout=self.request_timeout, 
                                       headers=self.headers,
                                       follow_redirects=True) as client:
                for _ in range(num_requests):
                    start_time = time.time()
                    response = await client.get(url)
                    response_time = (time.time() - start_time) * 1000
                    
                    results.append({
                        'response_time': response_time,
                        'size': len(response.content),
                        'status_code': response.status_code
                    })
                    
                    # Add small delay between requests
                    await asyncio.sleep(0.5)
            
            # Calculate metrics
            response_times = [r['response_time'] for r in results]
            sizes = [r['size'] for r in results]
            
            avg_response_time = sum(response_times) / len(response_times)
            avg_size = sum(sizes) / len(sizes) / 1024  # Convert to KB
            
            # Calculate standard deviation for response time
            std_dev = (sum((x - avg_response_time) ** 2 for x in response_times) / len(response_times)) ** 0.5
            
            # Determine performance rating
            rating = self._calculate_performance_rating(avg_response_time, std_dev)
            
            return {
                'average_response_time': f"{round(avg_response_time, 2)} ms",
                'average_response_time_ms': round(avg_response_time, 2),
                'response_time_std_dev': round(std_dev, 2),
                'average_page_size': f"{round(avg_size, 2)} KB",
                'average_page_size_kb': round(avg_size, 2),
                'num_requests': num_requests,
                'performance_rating': rating,
                'consistency': 'Good' if std_dev < avg_response_time * 0.2 else 'Variable'
            }
        except Exception as e:
            logger.warning(f"Performance check error for {url}: {e}")
            return {'error': str(e)}
    
    async def _check_ssl(self, url):
        """Check SSL/TLS certificate and configuration."""
        try:
            parsed_url = urlparse(url)
            if parsed_url.scheme != 'https':
                return {
                    'has_ssl': False,
                    'security_status': 'Not Applicable',
                    'recommendation': 'Consider implementing HTTPS for better security'
                }
            
            # Use the utility function to check SSL certificate
            ssl_result = await check_ssl_certificate(parsed_url.netloc)
            
            if not ssl_result:
                return {
                    'has_ssl': True,
                    'security_status': 'Unknown',
                    'error': 'Failed to check SSL certificate'
                }
            
            # Analyze SSL/TLS configuration
            security_status = 'Secure'
            recommendations = []
            
            # Check certificate validity
            if ssl_result.get('is_expired', False):
                security_status = 'Critical'
                recommendations.append('SSL certificate has expired')
            
            # Check certificate issuer
            if not ssl_result.get('is_trusted', True):
                security_status = 'Vulnerable'
                recommendations.append('SSL certificate is not from a trusted issuer')
            
            # Check protocol version
            protocol = ssl_result.get('protocol', '')
            if protocol in ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']:
                security_status = 'Vulnerable'
                recommendations.append(f'Outdated SSL/TLS protocol ({protocol}) in use')
            
            # Check certificate expiration
            days_to_expiry = ssl_result.get('days_to_expiry', 0)
            if 0 < days_to_expiry < 30:
                if security_status == 'Secure':
                    security_status = 'Warning'
                recommendations.append(f'SSL certificate expires in {days_to_expiry} days')
            
            return {
                'has_ssl': True,
                'issuer': ssl_result.get('issuer', 'Unknown'),
                'valid_from': ssl_result.get('valid_from', ''),
                'valid_to': ssl_result.get('valid_to', ''),
                'days_to_expiry': days_to_expiry,
                'protocol': protocol,
                'cipher': ssl_result.get('cipher', ''),
                'security_status': security_status,
                'recommendation': '; '.join(recommendations) if recommendations else 'No issues detected'
            }
        except Exception as e:
            logger.warning(f"SSL check error for {url}: {e}")
            return {
                'has_ssl': False,
                'security_status': 'Error',
                'error': str(e)
            }
    
    async def _check_accessibility(self, url):
        """Check basic website accessibility."""
        try:
            # Initialize accessibility checks
            accessibility_results = {
                'has_alt_text': False,
                'has_aria_attributes': False,
                'has_semantic_headings': False,
                'has_skip_links': False,
                'accessibility_score': 0,
                'issues': []
            }
            
            async with aiohttp.ClientSession(headers=self.headers) as session:
                async with session.get(url, timeout=self.request_timeout) as response:
                    content = await response.text()
                    
                    # Check for alt text on images
                    img_pattern = r'<img[^>]+>'
                    alt_pattern = r'<img[^>]+alt=["\'][^"\']*["\'][^>]*>'
                    
                    img_tags = re.findall(img_pattern, content, re.IGNORECASE)
                    total_images = len(img_tags)
                    
                    images_with_alt = re.findall(alt_pattern, content, re.IGNORECASE)
                    images_with_alt_count = len(images_with_alt)
                    
                    if total_images > 0:
                        alt_text_ratio = images_with_alt_count / total_images
                        accessibility_results['has_alt_text'] = alt_text_ratio > 0.8
                        if alt_text_ratio < 1.0:
                            missing = total_images - images_with_alt_count
                            accessibility_results['issues'].append(f'Missing alt text on {missing} of {total_images} images')
                    
                    # Check for ARIA attributes
                    aria_pattern = r'aria-[a-z]+=["\'][^"\']*["\']'
                    aria_attributes = re.findall(aria_pattern, content, re.IGNORECASE)
                    accessibility_results['has_aria_attributes'] = len(aria_attributes) > 0
                    
                    # Check for semantic headings
                    heading_pattern = r'<h[1-6][^>]*>.*?</h[1-6]>'
                    headings = re.findall(heading_pattern, content, re.IGNORECASE | re.DOTALL)
                    accessibility_results['has_semantic_headings'] = len(headings) > 0
                    
                    # Check for skip links
                    skip_pattern = r'<a[^>]+href=["\']#[^"\']+["\'][^>]*>.*?skip.*?</a>'
                    skip_links = re.findall(skip_pattern, content, re.IGNORECASE | re.DOTALL)
                    accessibility_results['has_skip_links'] = len(skip_links) > 0
            
            # Calculate accessibility score
            true_factors = 0
            total_factors = 4  # Number of accessibility factors we check
            
            if accessibility_results['has_alt_text']:
                true_factors += 1
            if accessibility_results['has_aria_attributes']:
                true_factors += 1
            if accessibility_results['has_semantic_headings']:
                true_factors += 1
            if accessibility_results['has_skip_links']:
                true_factors += 1
            
            accessibility_results['accessibility_score'] = int((true_factors / total_factors) * 100)
            
            # Add recommendations
            if not accessibility_results['has_alt_text']:
                accessibility_results['issues'].append('Add alt text to all images')
            if not accessibility_results['has_aria_attributes']:
                accessibility_results['issues'].append('Add ARIA attributes for better screen reader support')
            if not accessibility_results['has_semantic_headings']:
                accessibility_results['issues'].append('Use semantic heading tags (h1-h6) for content structure')
            if not accessibility_results['has_skip_links']:
                accessibility_results['issues'].append('Add skip navigation links for keyboard users')
            
            return accessibility_results
            
        except Exception as e:
            logger.warning(f"Accessibility check error for {url}: {e}")
            return {'error': str(e)}
    
    async def _check_security_headers(self, url):
        """Check security-related HTTP headers."""
        try:
            async with aiohttp.ClientSession(headers=self.headers) as session:
                async with session.get(url, timeout=self.request_timeout) as response:
                    headers = dict(response.headers)
                    
                    security_results = {
                        'present_headers': {},
                        'missing_headers': [],
                        'security_score': 0
                    }
                    
                    # Check each security header
                    for header in self.security_headers:
                        if header in headers:
                            security_results['present_headers'][header] = headers[header]
                        else:
                            security_results['missing_headers'].append(header)
                    
                    # Calculate security score (each header worth ~16.67 points)
                    security_results['security_score'] = round(
                        (len(self.security_headers) - len(security_results['missing_headers']))
                        * (100 / len(self.security_headers))
                    )
                    
                    return security_results
        except Exception as e:
            logger.warning(f"Security headers check error for {url}: {e}")
            return {'error': str(e)}
    
    def _calculate_performance_rating(self, avg_response_time, std_dev):
        """Calculate performance rating based on response time and consistency."""
        if avg_response_time <= 200 and std_dev < 50:
            return 'Excellent'
        elif avg_response_time <= 500 and std_dev < 100:
            return 'Good'
        elif avg_response_time <= 1000 and std_dev < 200:
            return 'Fair'
        else:
            return 'Poor'
    
    def _calculate_health_score(self, results):
        """Calculate overall health score out of 100."""
        score = 100
        deductions = []
        
        # Basic connection (30 points)
        if not results.get('basic_checks', {}).get('is_reachable', False):
            deductions.append(30)
        elif results['basic_checks'].get('response_time_ms', 0) > 1000:
            deductions.append(15)
        
        # SSL/TLS (25 points)
        ssl_status = results.get('ssl_checks', {}).get('security_status')
        if ssl_status == 'Vulnerable':
            deductions.append(25)
        elif ssl_status == 'Warning':
            deductions.append(15)
        elif ssl_status == 'Critical':
            deductions.append(20)
        
        # Security Headers (20 points)
        security_score = results.get('security_headers', {}).get('security_score', 0)
        deductions.append((100 - security_score) * 0.2)
        
        # Performance (15 points)
        perf_rating = results.get('performance', {}).get('performance_rating')
        if perf_rating == 'Poor':
            deductions.append(15)
        elif perf_rating == 'Fair':
            deductions.append(10)
        elif perf_rating == 'Good':
            deductions.append(5)
        
        # DNS (10 points)
        dns_results = results.get('dns_checks', {})
        if not dns_results.get('has_ipv4', False):
            deductions.append(5)
        if len(dns_results.get('ns_records', [])) < 2:
            deductions.append(5)
        
        # Calculate final score
        final_score = max(0, score - sum(deductions))
        return round(final_score)
    
    def _determine_overall_status(self, results):
        """Determine overall website health status."""
        health_score = results.get('health_score', 0)
        
        if health_score >= 90:
            return 'Excellent'
        elif health_score >= 80:
            return 'Good'
        elif health_score >= 70:
            return 'Fair'
        elif health_score >= 60:
            return 'Poor'
        else:
            return 'Critical'
    
    def _generate_recommendations(self, results):
        """Generate actionable recommendations based on health check results."""
        recommendations = []
        
        # Performance recommendations
        perf = results.get('performance', {})
        if perf.get('performance_rating') in ['Poor', 'Fair']:
            recommendations.append({
                'category': 'Performance',
                'priority': 'High' if perf.get('performance_rating') == 'Poor' else 'Medium',
                'issue': 'Slow response times',
                'action': 'Optimize server response time, enable caching, and compress content'
            })
        
        # Security recommendations
        security = results.get('security_headers', {})
        if security.get('missing_headers'):
            recommendations.append({
                'category': 'Security',
                'priority': 'High',
                'issue': f"Missing security headers: {', '.join(security['missing_headers'])}",
                'action': 'Implement missing security headers to improve website security'
            })
        
        # SSL recommendations
        ssl = results.get('ssl_checks', {})
        if ssl.get('security_status') in ['Vulnerable', 'Critical']:
            recommendations.append({
                'category': 'SSL/TLS',
                'priority': 'Critical',
                'issue': ssl.get('recommendation', 'SSL certificate issues detected'),
                'action': 'Update SSL certificate configuration'
            })
        
        # DNS recommendations
        dns = results.get('dns_checks', {})
        if not dns.get('has_ipv6', False):
            recommendations.append({
                'category': 'DNS',
                'priority': 'Low',
                'issue': 'No IPv6 support',
                'action': 'Add AAAA records to support IPv6'
            })
        
        return recommendations

# Create a global instance
website_health = WebsiteHealthChecker()
