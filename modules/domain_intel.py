"""Domain Intelligence Module - DNS, Subdomain, WHOIS, SSL analysis"""

import socket
import ssl
import subprocess
import re
from typing import Dict, List, Optional
from urllib.parse import urlparse
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import dns.resolver
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


class DomainIntel:
    """Domain intelligence gathering"""
    
    def __init__(self):
        self.dns_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR']
        self.subdomain_wordlist = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
            'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn',
            'ns3', 'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx',
            'static', 'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar',
            'wiki', 'web', 'media', 'email', 'images', 'img', 'www1', 'intranet', 'portal',
            'video', 'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns4', 'www3', 'dns',
            'search', 'staging', 'server', 'mx1', 'chat', 'wap', 'my', 'svn', 'mail1',
            'sites', 'proxy', 'ads', 'online', 'ads', 'crm', 'cms', 'backup', 'mx2',
            'lyncdiscover', 'info', 'apps', 'download', 'remote', 'db', 'forums', 'store',
            'relay', 'files', 'news', 'vpn', 'ns', 'live', 'owa', 'en', 'start', 'sms',
            'office', 'exchange', 'ipv4', 'smtp2', 'smtp1', 'smtp3', 'smtp4', 'smtp5'
        ]
    
    def enumerate_dns(self, domain: str) -> Dict:
        """Enumerate DNS records"""
        results = {}
        
        if not DNS_AVAILABLE:
            # Fallback to socket for basic A record
            try:
                ip = socket.gethostbyname(domain)
                results['A'] = [ip]
            except:
                pass
            return results
        
        for record_type in self.dns_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                results[record_type] = [str(rdata) for rdata in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
                continue
            except Exception:
                pass
        
        # Also try to get reverse DNS
        try:
            ip = socket.gethostbyname(domain)
            results['IP'] = ip
            try:
                hostname, _, _ = socket.gethostbyaddr(ip)
                results['PTR'] = hostname
            except:
                pass
        except:
            pass
        
        return results
    
    def discover_subdomains(self, domain: str, threads: int = 50) -> List[str]:
        """Discover subdomains using multiple methods"""
        subdomains = set()
        
        # Method 1: DNS brute force
        def check_subdomain(subdomain):
            full_domain = f"{subdomain}.{domain}"
            try:
                socket.gethostbyname(full_domain)
                return full_domain
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(check_subdomain, sub) for sub in self.subdomain_wordlist]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    subdomains.add(result)
        
        # Method 2: Certificate Transparency logs (simulated)
        # In production, you'd use crt.sh API
        try:
            ct_subdomains = self._check_certificate_transparency(domain)
            subdomains.update(ct_subdomains)
        except:
            pass
        
        # Method 3: Search engines (simulated)
        try:
            search_subdomains = self._search_engines(domain)
            subdomains.update(search_subdomains)
        except:
            pass
        
        return sorted(list(subdomains))
    
    def _check_certificate_transparency(self, domain: str) -> List[str]:
        """Check Certificate Transparency logs"""
        subdomains = []
        try:
            # Using crt.sh API
            from urllib.parse import quote
            url = f"https://crt.sh/?q={quote('%.' + domain)}&output=json"
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    for candidate in name.split('\n'):
                        candidate = candidate.strip().lstrip('*.')
                        if candidate.endswith(domain) or candidate == domain:
                            subdomains.append(candidate)
        except Exception:
            pass
        return sorted(set(subdomains))
    
    def _search_engines(self, domain: str) -> List[str]:
        """Search for subdomains using search engines"""
        # This is a placeholder - in production you'd use actual search APIs
        # or scrape search results
        return []
    
    def get_whois(self, domain: str) -> Dict:
        """Get WHOIS information"""
        whois_info = {}
        
        try:
            # Try using python-whois if available
            try:
                import whois
                w = whois.whois(domain)
                whois_info = {
                    'domain_name': str(w.domain_name) if w.domain_name else None,
                    'registrar': str(w.registrar) if w.registrar else None,
                    'creation_date': str(w.creation_date) if w.creation_date else None,
                    'expiration_date': str(w.expiration_date) if w.expiration_date else None,
                    'updated_date': str(w.updated_date) if w.updated_date else None,
                    'name_servers': list(w.name_servers) if w.name_servers else [],
                    'status': list(w.status) if w.status else [],
                    'emails': list(w.emails) if w.emails else [],
                    'org': str(w.org) if w.org else None,
                    'country': str(w.country) if w.country else None
                }
            except ImportError:
                # Fallback to system whois command
                try:
                    result = subprocess.run(['whois', domain], capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        whois_info['raw'] = result.stdout
                except:
                    pass
        except Exception:
            # Fallback to system whois command
            try:
                result = subprocess.run(['whois', domain], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    whois_info['raw'] = result.stdout
            except:
                pass
        
        return whois_info
    
    def analyze_ssl(self, domain: str) -> Dict:
        """Analyze SSL certificate"""
        ssl_info = {}
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    ssl_info = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert.get('version'),
                        'serialNumber': cert.get('serialNumber'),
                        'notBefore': cert.get('notBefore'),
                        'notAfter': cert.get('notAfter'),
                        'subjectAltName': cert.get('subjectAltName', []),
                        'OCSP': cert.get('OCSP', []),
                        'caIssuers': cert.get('caIssuers', [])
                    }
        except:
            pass
        
        return ssl_info

