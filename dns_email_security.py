import asyncio
import dns.resolver
import dns.exception
from logger import get_logger
from utils import extract_domain_from_url

logger = get_logger('dns_email_security')

class DnsEmailSecurityChecker:
    """Class for checking DNS and email security configurations."""
    
    def __init__(self):
        """Initialize the DNS and email security checker."""
        pass
    
    async def check_spf_record(self, domain):
        """
        Check for SPF record in DNS.
        
        Args:
            domain (str): The domain to check.
            
        Returns:
            dict: SPF record check results.
        """
        domain = extract_domain_from_url(domain)
        
        logger.info(f"Checking SPF record for {domain}")
        
        results = {
            'exists': False,
            'record': None,
            'recommendations': []
        }
        
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            
            for rdata in answers:
                txt_string = rdata.to_text()
                
                # Remove quotes from TXT record
                if txt_string.startswith('"') and txt_string.endswith('"'):
                    txt_string = txt_string[1:-1]
                
                if 'v=spf1' in txt_string:
                    results['exists'] = True
                    results['record'] = txt_string
                    
                    # Check for potentially insecure configurations
                    if '+all' in txt_string:
                        results['issues'] = ['SPF record uses +all, which allows all senders']
                        results['recommendations'].append('Change +all to ~all or -all to restrict email senders')
                        results['security_status'] = 'Vulnerable'
                        results['severity'] = 'high'
                    elif '?all' in txt_string:
                        results['issues'] = ['SPF record uses ?all, which is neutral for all senders']
                        results['recommendations'].append('Change ?all to ~all or -all to restrict email senders')
                        results['security_status'] = 'Potentially Vulnerable'
                        results['severity'] = 'medium'
                    elif '~all' in txt_string:
                        results['security_status'] = 'Potentially Vulnerable'
                        results['severity'] = 'low'
                        results['issues'] = ['SPF record uses ~all (soft fail)']
                        results['recommendations'].append('Consider using -all for stronger protection')
                    elif '-all' in txt_string:
                        results['security_status'] = 'Secure'
                        results['severity'] = 'info'
                    else:
                        results['security_status'] = 'Potentially Vulnerable'
                        results['severity'] = 'medium'
                        results['issues'] = ['SPF record does not specify a policy for all senders']
                        results['recommendations'].append('Add -all to your SPF record to reject unauthorized senders')
            
            if not results['exists']:
                results['security_status'] = 'Missing'
                results['severity'] = 'high'
                results['recommendations'].append('Implement an SPF record to prevent email spoofing')
            
            logger.info(f"SPF check completed for {domain}: {results.get('security_status', 'Missing')}")
            return results
            
        except dns.exception.DNSException as e:
            logger.error(f"Error checking SPF record for {domain}: {e}")
            results['error'] = str(e)
            results['security_status'] = 'Error'
            results['severity'] = 'unknown'
            return results
    
    async def check_dmarc_record(self, domain):
        """
        Check for DMARC record in DNS.
        
        Args:
            domain (str): The domain to check.
            
        Returns:
            dict: DMARC record check results.
        """
        domain = extract_domain_from_url(domain)
        dmarc_domain = f"_dmarc.{domain}"
        
        logger.info(f"Checking DMARC record for {domain}")
        
        results = {
            'exists': False,
            'record': None,
            'recommendations': []
        }
        
        try:
            answers = dns.resolver.resolve(dmarc_domain, 'TXT')
            
            for rdata in answers:
                txt_string = rdata.to_text()
                
                # Remove quotes from TXT record
                if txt_string.startswith('"') and txt_string.endswith('"'):
                    txt_string = txt_string[1:-1]
                
                if 'v=DMARC1' in txt_string:
                    results['exists'] = True
                    results['record'] = txt_string
                    
                    # Parse DMARC policy
                    policy = 'none'  # Default policy
                    for tag in txt_string.split(';'):
                        tag = tag.strip()
                        if tag.startswith('p='):
                            policy = tag[2:]
                    
                    results['policy'] = policy
                    
                    # Check for potentially insecure configurations
                    if policy == 'none':
                        results['issues'] = ['DMARC policy is set to "none", which only monitors but takes no action']
                        results['recommendations'].append('Change DMARC policy to "quarantine" or "reject" for better protection')
                        results['security_status'] = 'Potentially Vulnerable'
                        results['severity'] = 'medium'
                    elif policy == 'quarantine':
                        results['security_status'] = 'Potentially Vulnerable'
                        results['severity'] = 'low'
                        results['issues'] = ['DMARC policy is set to "quarantine"']
                        results['recommendations'].append('Consider using "reject" policy for stronger protection')
                    elif policy == 'reject':
                        results['security_status'] = 'Secure'
                        results['severity'] = 'info'
                    else:
                        results['security_status'] = 'Potentially Vulnerable'
                        results['severity'] = 'medium'
                        results['issues'] = [f'Unknown DMARC policy: {policy}']
                        results['recommendations'].append('Implement a valid DMARC policy (none, quarantine, or reject)')
            
            if not results['exists']:
                results['security_status'] = 'Missing'
                results['severity'] = 'high'
                results['recommendations'].append('Implement a DMARC record to prevent email spoofing and phishing')
            
            logger.info(f"DMARC check completed for {domain}: {results.get('security_status', 'Missing')}")
            return results
            
        except dns.exception.DNSException as e:
            logger.error(f"Error checking DMARC record for {domain}: {e}")
            results['error'] = str(e)
            results['security_status'] = 'Error'
            results['severity'] = 'unknown'
            return results
    
    async def check_email_security(self, domain):
        """
        Check SPF and DMARC records for a domain.
        
        Args:
            domain (str): The domain to check.
            
        Returns:
            dict: Email security check results.
        """
        domain = extract_domain_from_url(domain)
        
        logger.info(f"Checking email security for {domain}")
        
        try:
            # Run SPF and DMARC checks concurrently
            spf_task = self.check_spf_record(domain)
            dmarc_task = self.check_dmarc_record(domain)
            
            spf_results, dmarc_results = await asyncio.gather(spf_task, dmarc_task)
            
            # Combine results
            results = {
                'spf': spf_results,
                'dmarc': dmarc_results,
                'recommendations': []
            }
            
            # Add recommendations from both checks
            if 'recommendations' in spf_results:
                results['recommendations'].extend(spf_results['recommendations'])
            
            if 'recommendations' in dmarc_results:
                results['recommendations'].extend(dmarc_results['recommendations'])
            
            # Determine overall security status
            if (spf_results.get('security_status') == 'Vulnerable' or 
                dmarc_results.get('security_status') == 'Vulnerable'):
                results['security_status'] = 'Vulnerable'
                results['severity'] = 'high'
            elif (spf_results.get('security_status') == 'Missing' or 
                  dmarc_results.get('security_status') == 'Missing'):
                results['security_status'] = 'Vulnerable'
                results['severity'] = 'high'
            elif (spf_results.get('security_status') == 'Potentially Vulnerable' or 
                  dmarc_results.get('security_status') == 'Potentially Vulnerable'):
                results['security_status'] = 'Potentially Vulnerable'
                results['severity'] = 'medium'
            elif (spf_results.get('security_status') == 'Secure' and 
                  dmarc_results.get('security_status') == 'Secure'):
                results['security_status'] = 'Secure'
                results['severity'] = 'info'
            else:
                results['security_status'] = 'Potentially Vulnerable'
                results['severity'] = 'medium'
            
            logger.info(f"Email security check completed for {domain}: {results['security_status']}")
            return results
            
        except Exception as e:
            logger.error(f"Error checking email security for {domain}: {e}")
            return {
                'error': str(e),
                'security_status': 'Error',
                'severity': 'unknown'
            }

# Create a global instance
dns_email_security = DnsEmailSecurityChecker()
