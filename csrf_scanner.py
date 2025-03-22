import os
import re
import json
import asyncio
import requests
import urllib3
from bs4 import BeautifulSoup
from logger import get_logger

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = get_logger(__name__)

class CSRFScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 10
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }

    async def scan(self, domain):
        """Scan a domain for CSRF vulnerabilities"""
        try:
            if not domain.startswith('http'):
                domain = f'http://{domain}'
            
            logger.info(f"Starting CSRF scan for domain: {domain}")
            
            # Initialize results dictionary
            results = {}
            
            # Get all forms from the domain
            forms = await self._get_forms(domain)
            
            for form_url, form_data in forms.items():
                form_result = await self._analyze_form(form_url, form_data)
                if form_result:
                    results[form_url] = form_result
            
            return results
        except Exception as e:
            logger.error(f"Error in CSRF scan: {e}")
            raise

    async def _get_forms(self, url):
        """Get all forms from a URL"""
        forms = {}
        try:
            response = self.session.get(url, headers=self.headers)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, 'html.parser')
            for form in soup.find_all('form'):
                form_url = form.get('action', '')
                if form_url:
                    if not form_url.startswith('http'):
                        form_url = url + form_url if form_url.startswith('/') else url + '/' + form_url
                else:
                    form_url = url
                
                forms[form_url] = {
                    'method': form.get('method', 'get').lower(),
                    'inputs': [{'name': input.get('name'), 'type': input.get('type')} 
                              for input in form.find_all('input')],
                    'raw_html': str(form)
                }
            
            return forms
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching forms: {e}")
            return {}

    async def _analyze_form(self, form_url, form_data):
        """Analyze a form for CSRF vulnerabilities"""
        try:
            missing_protections = []
            risk_level = "Low"
            
            # Check for CSRF token
            has_csrf_token = any(
                input.get('name', '').lower().find('csrf') != -1 or
                input.get('name', '').lower().find('token') != -1
                for input in form_data['inputs']
            )
            
            if not has_csrf_token:
                missing_protections.append("CSRF Token")
                risk_level = "High"
            
            # Check for SameSite cookie attribute
            cookies = self.session.cookies.get_dict()
            if cookies:
                for cookie in self.session.cookies:
                    if not cookie.has_nonstandard_attr('SameSite'):
                        missing_protections.append("SameSite Cookie Attribute")
                        risk_level = "High"
            
            # Generate recommendations
            recommendations = [
                "Implement CSRF tokens in all forms",
                "Set SameSite=Strict for cookies",
                "Use secure session management",
                "Implement proper referrer checking"
            ]
            
            if missing_protections:
                return {
                    'is_vulnerable': True,
                    'method': form_data['method'],
                    'missing_protections': missing_protections,
                    'risk_level': risk_level,
                    'recommendations': recommendations,
                    'form_details': {
                        'inputs': form_data['inputs'],
                        'raw_html': form_data['raw_html']
                    }
                }
            
            return None
        except Exception as e:
            logger.error(f"Error analyzing form: {e}")
            return None
