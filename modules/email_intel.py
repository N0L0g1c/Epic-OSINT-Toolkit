"""Email Intelligence Module - Email discovery and verification"""

import re
import requests
from typing import Dict, List, Optional
from urllib.parse import urlparse

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


class EmailIntel:
    """Email intelligence gathering"""
    
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        # Common email patterns
        self.common_patterns = [
            'admin', 'administrator', 'contact', 'info', 'support', 'help',
            'sales', 'marketing', 'business', 'office', 'team', 'service',
            'webmaster', 'postmaster', 'hostmaster', 'abuse', 'security',
            'noreply', 'no-reply', 'donotreply', 'mail', 'email'
        ]
    
    def discover(self, domain: str) -> List[str]:
        """Discover email addresses for a domain"""
        emails = set()
        
        # Method 1: Common email patterns
        for pattern in self.common_patterns:
            emails.add(f"{pattern}@{domain}")
        
        # Method 2: Search engines (simulated - would use APIs in production)
        try:
            search_emails = self._search_emails(domain)
            emails.update(search_emails)
        except:
            pass
        
        # Method 3: WHOIS records
        try:
            whois_emails = self._extract_from_whois(domain)
            emails.update(whois_emails)
        except:
            pass
        
        # Method 4: Website scraping
        try:
            website_emails = self._scrape_website(domain)
            emails.update(website_emails)
        except:
            pass
        
        # Method 5: GitHub commits and profiles
        try:
            github_emails = self._search_github(domain)
            emails.update(github_emails)
        except:
            pass
        
        return sorted(list(emails))
    
    def verify(self, emails: List[str]) -> List[Dict]:
        """Verify email addresses"""
        verified = []
        
        for email in emails:
            result = {
                'email': email,
                'valid': False,
                'exists': False,
                'catch_all': False,
                'disposable': False
            }
            
            # Check if disposable email
            result['disposable'] = self._is_disposable(email)
            
            # Basic format validation
            if not self._is_valid_format(email):
                verified.append(result)
                continue
            
            # Check MX records
            domain = email.split('@')[1]
            if DNS_AVAILABLE:
                try:
                    mx_records = dns.resolver.resolve(domain, 'MX')
                    result['valid'] = len(mx_records) > 0
                except:
                    pass
            else:
                # Basic validation if DNS library not available
                result['valid'] = self._is_valid_format(email)
            
            # Try SMTP verification (basic)
            if result['valid']:
                try:
                    result['exists'] = self._smtp_verify(email)
                except:
                    pass
            
            verified.append(result)
        
        return verified
    
    def find_sources(self, domain: str) -> Dict:
        """Find sources where emails from domain were found"""
        sources = {
            'whois': [],
            'website': [],
            'github': [],
            'social_media': [],
            'data_breaches': []
        }
        
        # Check WHOIS
        try:
            whois_emails = self._extract_from_whois(domain)
            sources['whois'] = whois_emails
        except:
            pass
        
        # Check website
        try:
            website_emails = self._scrape_website(domain)
            sources['website'] = website_emails
        except:
            pass
        
        # Check GitHub
        try:
            github_emails = self._search_github(domain)
            sources['github'] = github_emails
        except:
            pass
        
        return sources
    
    def _search_emails(self, domain: str) -> List[str]:
        """Search for emails using search engines"""
        # Placeholder - would use search engine APIs
        return []
    
    def _extract_from_whois(self, domain: str) -> List[str]:
        """Extract emails from WHOIS records"""
        emails = []
        try:
            import subprocess
            result = subprocess.run(['whois', domain], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                found = re.findall(email_pattern, result.stdout, re.IGNORECASE)
                emails.extend(found)
        except:
            pass
        return emails
    
    def _scrape_website(self, domain: str) -> List[str]:
        """Scrape website for email addresses"""
        emails = []
        try:
            url = f"https://{domain}"
            response = requests.get(url, headers=self.headers, timeout=10)
            if response.status_code == 200:
                email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                found = re.findall(email_pattern, response.text, re.IGNORECASE)
                emails.extend(found)
        except:
            pass
        return emails
    
    def _search_github(self, domain: str) -> List[str]:
        """Search GitHub for emails from domain"""
        emails = []
        # Placeholder - would use GitHub API
        return emails
    
    def _is_valid_format(self, email: str) -> bool:
        """Check if email format is valid"""
        pattern = r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$'
        return bool(re.match(pattern, email))
    
    def _is_disposable(self, email: str) -> bool:
        """Check if email is from disposable email service"""
        disposable_domains = [
            'tempmail.com', '10minutemail.com', 'guerrillamail.com',
            'mailinator.com', 'throwaway.email', 'temp-mail.org'
        ]
        domain = email.split('@')[1].lower()
        return domain in disposable_domains
    
    def _smtp_verify(self, email: str) -> bool:
        """Basic SMTP verification (doesn't actually send email)"""
        # This is a placeholder - real SMTP verification would:
        # 1. Connect to MX server
        # 2. Check if mailbox exists
        # 3. Handle catch-all domains
        # For now, just return False to avoid false positives
        return False

