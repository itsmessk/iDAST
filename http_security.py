import asyncio
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import socket
from logger import get_logger
from utils import ensure_url_has_protocol, make_http_request

logger = get_logger('http_security')

class HttpSecurityChecker:
    """Class for checking HTTP security headers and configurations."""
    
    def __init__(self):
        """Initialize the HTTP security checker."""
        # Security headers to check
        self.security_headers = {
            'Strict-Transport-Security': {
                'description': 'HTTP Strict Transport Security (HSTS)',
                'recommendation': 'Add HSTS header with a long max-age value'
            },
            'Content-Security-Policy': {
                'description': 'Content Security Policy (CSP)',
                'recommendation': 'Implement a strict CSP to prevent XSS attacks'
            },
            'X-Content-Type-Options': {
                'description': 'X-Content-Type-Options',
                'recommendation': 'Set X-Content-Type-Options to nosniff'
            },
            'X-Frame-Options': {
                'description': 'X-Frame-Options',
                'recommendation': 'Set X-Frame-Options to DENY or SAMEORIGIN'
            },
            'X-XSS-Protection': {
                'description': 'X-XSS-Protection',
                'recommendation': 'Set X-XSS-Protection to 1; mode=block'
            },
            'Referrer-Policy': {
                'description': 'Referrer Policy',
                'recommendation': 'Set a restrictive Referrer-Policy'
            },
            'Permissions-Policy': {
                'description': 'Permissions Policy',
                'recommendation': 'Implement a restrictive Permissions-Policy'
            }
        }
    
    async def check_http_headers(self, url):
        """
        Check for the presence of specific HTTP security headers.
        
        Args:
            url (str): The target URL.
            
        Returns:
            dict: A dictionary containing the status of headers and their vulnerability status.
        """
        url = ensure_url_has_protocol(url)
        logger.info(f"Checking HTTP security headers for {url}")
        
        try:
            response = await make_http_request(url)
            headers = response.headers
            
            results = {
                'headers_present': {},
                'headers_missing': {},
                'recommendations': []
            }
            
            # Check each security header
            for header, info in self.security_headers.items():
                if header in headers:
                    results['headers_present'][header] = {
                        'value': headers[header],
                        'description': info['description']
                    }
                else:
                    results['headers_missing'][header] = {
                        'description': info['description'],
                        'recommendation': info['recommendation']
                    }
                    results['recommendations'].append(info['recommendation'])
            
            # Determine overall security status
            if len(results['headers_missing']) > 3:
                results['security_status'] = 'Vulnerable'
                results['severity'] = 'high' if 'Content-Security-Policy' in results['headers_missing'] else 'medium'
            elif len(results['headers_missing']) > 0:
                results['security_status'] = 'Potentially Vulnerable'
                results['severity'] = 'medium'
            else:
                results['security_status'] = 'Secure'
                results['severity'] = 'low'
            
            logger.info(f"HTTP header check completed for {url}: {results['security_status']}")
            return results
            
        except Exception as e:
            logger.error(f"Error checking HTTP headers for {url}: {e}")
            return {
                'error': str(e),
                'security_status': 'Error',
                'severity': 'unknown'
            }
    
    async def check_client_access_policies(self, url):
        """
        Check for client access policies (crossdomain.xml and clientaccesspolicy.xml).
        
        Args:
            url (str): The target URL.
            
        Returns:
            dict: Results of the client access policy check.
        """
        url = ensure_url_has_protocol(url)
        base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        
        logger.info(f"Checking client access policies for {base_url}")
        
        results = {
            'crossdomain_xml': {'exists': False, 'content': None, 'issues': []},
            'clientaccesspolicy_xml': {'exists': False, 'content': None, 'issues': []},
            'recommendations': []
        }
        
        try:
            # Check crossdomain.xml
            crossdomain_url = f"{base_url}/crossdomain.xml"
            try:
                response = await make_http_request(crossdomain_url)
                if response.status_code == 200:
                    content = response.text
                    results['crossdomain_xml']['exists'] = True
                    results['crossdomain_xml']['content'] = content
                    
                    # Check for overly permissive policies
                    if '<allow-access-from domain="*"' in content:
                        results['crossdomain_xml']['issues'].append('Allows access from any domain')
                        results['recommendations'].append('Restrict crossdomain.xml to only allow specific domains')
            except Exception as e:
                logger.debug(f"Error checking crossdomain.xml: {e}")
            
            # Check clientaccesspolicy.xml
            clientaccess_url = f"{base_url}/clientaccesspolicy.xml"
            try:
                response = await make_http_request(clientaccess_url)
                if response.status_code == 200:
                    content = response.text
                    results['clientaccesspolicy_xml']['exists'] = True
                    results['clientaccesspolicy_xml']['content'] = content
                    
                    # Check for overly permissive policies
                    if '<domain uri="*"' in content:
                        results['clientaccesspolicy_xml']['issues'].append('Allows access from any domain')
                        results['recommendations'].append('Restrict clientaccesspolicy.xml to only allow specific domains')
            except Exception as e:
                logger.debug(f"Error checking clientaccesspolicy.xml: {e}")
            
            # Determine overall security status
            if (results['crossdomain_xml']['exists'] and results['crossdomain_xml']['issues']) or \
               (results['clientaccesspolicy_xml']['exists'] and results['clientaccesspolicy_xml']['issues']):
                results['security_status'] = 'Vulnerable'
                results['severity'] = 'medium'
            elif results['crossdomain_xml']['exists'] or results['clientaccesspolicy_xml']['exists']:
                results['security_status'] = 'Potentially Vulnerable'
                results['severity'] = 'low'
            else:
                results['security_status'] = 'Secure'
                results['severity'] = 'info'
            
            logger.info(f"Client access policy check completed for {base_url}: {results['security_status']}")
            return results
            
        except Exception as e:
            logger.error(f"Error checking client access policies for {base_url}: {e}")
            return {
                'error': str(e),
                'security_status': 'Error',
                'severity': 'unknown'
            }
    
    async def check_security_txt(self, url):
        """
        Check for security.txt file.
        
        Args:
            url (str): The target URL.
            
        Returns:
            dict: Results of the security.txt check.
        """
        url = ensure_url_has_protocol(url)
        base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        
        logger.info(f"Checking security.txt for {base_url}")
        
        results = {
            'exists': False,
            'content': None,
            'recommendations': []
        }
        
        try:
            # Check /.well-known/security.txt (preferred location)
            wellknown_url = f"{base_url}/.well-known/security.txt"
            try:
                response = await make_http_request(wellknown_url)
                if response.status_code == 200:
                    results['exists'] = True
                    results['location'] = wellknown_url
                    results['content'] = response.text
            except Exception:
                pass
            
            # If not found in .well-known, check at root
            if not results['exists']:
                root_url = f"{base_url}/security.txt"
                try:
                    response = await make_http_request(root_url)
                    if response.status_code == 200:
                        results['exists'] = True
                        results['location'] = root_url
                        results['content'] = response.text
                except Exception:
                    pass
            
            # Add recommendations if security.txt doesn't exist
            if not results['exists']:
                results['recommendations'].append('Create a security.txt file in the /.well-known/ directory')
                results['recommendations'].append('Include contact information for security researchers')
                results['security_status'] = 'Missing'
                results['severity'] = 'low'
            else:
                results['security_status'] = 'Present'
                results['severity'] = 'info'
            
            logger.info(f"Security.txt check completed for {base_url}: {results['security_status']}")
            return results
            
        except Exception as e:
            logger.error(f"Error checking security.txt for {base_url}: {e}")
            return {
                'error': str(e),
                'security_status': 'Error',
                'severity': 'unknown'
            }
    
    async def check_robots_txt(self, url):
        """
        Check for robots.txt file and analyze its content.
        
        Args:
            url (str): The target URL.
            
        Returns:
            dict: Results of the robots.txt check.
        """
        url = ensure_url_has_protocol(url)
        base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        robots_url = f"{base_url}/robots.txt"
        
        logger.info(f"Checking robots.txt for {base_url}")
        
        results = {
            'exists': False,
            'content': None,
            'disallowed_paths': [],
            'sensitive_paths': [],
            'recommendations': []
        }
        
        sensitive_paths = [
            '/admin', '/login', '/wp-admin', '/administrator', '/phpmyadmin',
            '/config', '/backup', '/db', '/database', '/api', '/private',
            '/secret', '/secure', '/test', '/dev', '/staging', '/beta'
        ]
        
        try:
            response = await make_http_request(robots_url)
            
            if response.status_code == 200:
                content = response.text
                results['exists'] = True
                results['content'] = content
                
                # Parse disallowed paths
                for line in content.split('\n'):
                    if line.lower().startswith('disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path:
                            results['disallowed_paths'].append(path)
                            
                            # Check if disallowed path contains sensitive information
                            for sensitive_path in sensitive_paths:
                                if sensitive_path in path.lower():
                                    results['sensitive_paths'].append({
                                        'path': path,
                                        'reason': f'Contains sensitive pattern: {sensitive_path}'
                                    })
                
                # Add recommendations based on findings
                if results['sensitive_paths']:
                    results['recommendations'].append('Review robots.txt for sensitive paths that could reveal system information')
                    results['security_status'] = 'Potentially Vulnerable'
                    results['severity'] = 'medium'
                else:
                    results['security_status'] = 'Secure'
                    results['severity'] = 'info'
            else:
                results['security_status'] = 'Missing'
                results['severity'] = 'info'
                results['recommendations'].append('Consider adding a robots.txt file to control search engine crawling')
            
            logger.info(f"Robots.txt check completed for {base_url}: {results['security_status']}")
            return results
            
        except Exception as e:
            logger.error(f"Error checking robots.txt for {base_url}: {e}")
            return {
                'error': str(e),
                'security_status': 'Error',
                'severity': 'unknown'
            }
    
    async def check_and_store_csp(self, url):
        """
        Check if CSP header is present and return the status.
        
        Args:
            url (str): The target URL.
            
        Returns:
            dict: CSP check results.
        """
        url = ensure_url_has_protocol(url)
        
        logger.info(f"Checking CSP for {url}")
        
        results = {
            'exists': False,
            'value': None,
            'directives': {},
            'issues': [],
            'recommendations': []
        }
        
        try:
            response = await make_http_request(url)
            headers = response.headers
            
            # Check for CSP header (both standard and legacy)
            csp_header = None
            if 'Content-Security-Policy' in headers:
                csp_header = headers['Content-Security-Policy']
                results['header_name'] = 'Content-Security-Policy'
            elif 'X-Content-Security-Policy' in headers:
                csp_header = headers['X-Content-Security-Policy']
                results['header_name'] = 'X-Content-Security-Policy'
                results['issues'].append('Using deprecated X-Content-Security-Policy header')
                results['recommendations'].append('Use the standard Content-Security-Policy header instead')
            
            if csp_header:
                results['exists'] = True
                results['value'] = csp_header
                
                # Parse CSP directives
                directives = csp_header.split(';')
                for directive in directives:
                    directive = directive.strip()
                    if not directive:
                        continue
                    
                    parts = directive.split(' ', 1)
                    if len(parts) == 1:
                        # Directive without values
                        results['directives'][parts[0]] = []
                    else:
                        # Directive with values
                        directive_name = parts[0]
                        directive_values = parts[1].strip().split(' ')
                        results['directives'][directive_name] = directive_values
                
                # Check for unsafe CSP configurations
                if 'default-src' not in results['directives'] and 'script-src' not in results['directives']:
                    results['issues'].append('Missing default-src or script-src directive')
                    results['recommendations'].append('Add default-src or script-src directive to restrict script execution')
                
                for directive, values in results['directives'].items():
                    if "'unsafe-inline'" in values:
                        results['issues'].append(f"'{directive}' allows unsafe inline scripts/styles")
                        results['recommendations'].append(f"Remove 'unsafe-inline' from {directive} directive")
                    
                    if "'unsafe-eval'" in values:
                        results['issues'].append(f"'{directive}' allows unsafe eval()")
                        results['recommendations'].append(f"Remove 'unsafe-eval' from {directive} directive")
                    
                    if '*' in values:
                        results['issues'].append(f"'{directive}' uses wildcard (*) source")
                        results['recommendations'].append(f"Replace wildcard in {directive} with specific domains")
                
                # Determine security status based on issues
                if results['issues']:
                    results['security_status'] = 'Potentially Vulnerable'
                    results['severity'] = 'medium'
                else:
                    results['security_status'] = 'Secure'
                    results['severity'] = 'info'
            else:
                results['security_status'] = 'Missing'
                results['severity'] = 'high'
                results['recommendations'].append('Implement a Content Security Policy to prevent XSS attacks')
            
            logger.info(f"CSP check completed for {url}: {results['security_status']}")
            return results
            
        except Exception as e:
            logger.error(f"Error checking CSP for {url}: {e}")
            return {
                'error': str(e),
                'security_status': 'Error',
                'severity': 'unknown'
            }
    
    async def check_clickjacking_vulnerability(self, url):
        """
        Check if a URL is vulnerable to clickjacking.
        
        Args:
            url (str): The target URL.
            
        Returns:
            dict: Clickjacking vulnerability check results.
        """
        url = ensure_url_has_protocol(url)
        
        logger.info(f"Checking clickjacking vulnerability for {url}")
        
        results = {
            'vulnerable': False,
            'protection_headers': {},
            'recommendations': []
        }
        
        try:
            response = await make_http_request(url)
            headers = response.headers
            
            # Check for X-Frame-Options header
            if 'X-Frame-Options' in headers:
                value = headers['X-Frame-Options'].upper()
                results['protection_headers']['X-Frame-Options'] = value
                
                if value not in ['DENY', 'SAMEORIGIN']:
                    results['vulnerable'] = True
                    results['recommendations'].append('Set X-Frame-Options to DENY or SAMEORIGIN')
            else:
                results['vulnerable'] = True
                results['recommendations'].append('Add X-Frame-Options header with DENY or SAMEORIGIN value')
            
            # Check for CSP frame-ancestors directive
            if 'Content-Security-Policy' in headers:
                csp = headers['Content-Security-Policy']
                results['protection_headers']['Content-Security-Policy'] = csp
                
                if 'frame-ancestors' in csp:
                    # Extract frame-ancestors directive
                    for directive in csp.split(';'):
                        directive = directive.strip()
                        if directive.startswith('frame-ancestors'):
                            values = directive.split(' ', 1)[1].strip() if ' ' in directive else ''
                            
                            if values in ['none', "'none'"]:
                                results['vulnerable'] = False
                            elif values in ["'self'"] or not values:
                                # 'self' is equivalent to SAMEORIGIN
                                results['vulnerable'] = False
                            elif '*' in values:
                                results['vulnerable'] = True
                                results['recommendations'].append('Remove wildcard (*) from frame-ancestors directive')
                else:
                    # No frame-ancestors directive in CSP
                    if 'X-Frame-Options' not in headers:
                        results['recommendations'].append('Add frame-ancestors directive to CSP')
            
            # Set final vulnerability status and severity
            if results['vulnerable']:
                results['security_status'] = 'Vulnerable'
                results['severity'] = 'medium'
                
                # Create a PoC recommendation
                results['recommendations'].append('Implement proper frame protection to prevent clickjacking attacks')
            else:
                results['security_status'] = 'Secure'
                results['severity'] = 'info'
            
            logger.info(f"Clickjacking check completed for {url}: {results['security_status']}")
            return results
            
        except Exception as e:
            logger.error(f"Error checking clickjacking vulnerability for {url}: {e}")
            return {
                'error': str(e),
                'security_status': 'Error',
                'severity': 'unknown'
            }
    
    async def get_cookie_details(self, url):
        """
        Get cookie details and security attributes.
        
        Args:
            url (str): The target URL.
            
        Returns:
            dict: Cookie details and security analysis.
        """
        url = ensure_url_has_protocol(url)
        
        logger.info(f"Checking cookies for {url}")
        
        results = {
            'cookies': [],
            'secure_cookies': 0,
            'insecure_cookies': 0,
            'httponly_cookies': 0,
            'samesite_cookies': 0,
            'recommendations': []
        }
        
        try:
            response = requests.get(url, allow_redirects=True)
            cookies = response.cookies
            
            for cookie in cookies:
                cookie_info = {
                    'name': cookie.name,
                    'domain': cookie.domain,
                    'path': cookie.path,
                    'secure': cookie.secure,
                    'httponly': cookie.has_nonstandard_attr('HttpOnly'),
                    'samesite': None,
                    'expires': cookie.expires
                }
                
                # Check for SameSite attribute
                for attr in cookie._rest.keys():
                    if attr.lower() == 'samesite':
                        cookie_info['samesite'] = cookie._rest[attr]
                
                # Count secure vs insecure cookies
                if cookie_info['secure']:
                    results['secure_cookies'] += 1
                else:
                    results['insecure_cookies'] += 1
                    results['recommendations'].append(f"Set 'Secure' flag for cookie: {cookie.name}")
                
                # Count HttpOnly cookies
                if cookie_info['httponly']:
                    results['httponly_cookies'] += 1
                else:
                    results['recommendations'].append(f"Set 'HttpOnly' flag for cookie: {cookie.name}")
                
                # Count SameSite cookies
                if cookie_info['samesite']:
                    results['samesite_cookies'] += 1
                else:
                    results['recommendations'].append(f"Set 'SameSite' attribute for cookie: {cookie.name}")
                
                results['cookies'].append(cookie_info)
            
            # Set security status based on findings
            if results['cookies']:
                if results['insecure_cookies'] > 0:
                    results['security_status'] = 'Vulnerable'
                    results['severity'] = 'medium'
                elif results['httponly_cookies'] < len(results['cookies']) or results['samesite_cookies'] < len(results['cookies']):
                    results['security_status'] = 'Potentially Vulnerable'
                    results['severity'] = 'low'
                else:
                    results['security_status'] = 'Secure'
                    results['severity'] = 'info'
            else:
                results['security_status'] = 'No Cookies'
                results['severity'] = 'info'
            
            logger.info(f"Cookie check completed for {url}: {results['security_status']}")
            return results
            
        except Exception as e:
            logger.error(f"Error checking cookies for {url}: {e}")
            return {
                'error': str(e),
                'security_status': 'Error',
                'severity': 'unknown'
            }

# Create a global instance
http_security = HttpSecurityChecker()
