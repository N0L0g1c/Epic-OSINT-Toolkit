#!/usr/bin/env python3
"""
Epic OSINT Toolkit - Comprehensive Open Source Intelligence Gathering Tool
A powerful CLI-based OSINT tool combining multiple intelligence gathering techniques
"""

import argparse
import sys
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

from modules.domain_intel import DomainIntel
from modules.social_intel import SocialIntel
from modules.github_intel import GitHubIntel
from modules.web_crawler import WebCrawler
from modules.email_intel import EmailIntel
from modules.url_hunter import URLHunter
from modules.port_scanner import PortScanner
from modules.employee_intel import EmployeeIntel
from modules.dark_web_intel import DarkWebIntel
from modules.report_generator import ReportGenerator
from modules.ip_intel import IPIntel
from modules.wayback_intel import WaybackIntel
from modules.phone_intel import PhoneIntel
from modules.paste_intel import PasteIntel
from modules.host_intel import HostIntel
from modules.correlate import Correlator, detect_target_type
from modules.dork_intel import DorkIntel
from modules.asn_intel import ASNIntel
from modules.bucket_intel import BucketIntel
from modules.takeover_intel import TakeoverIntel
from modules.favicon_intel import FaviconIntel
from modules.meta_intel import MetaIntel


class OSINTToolkit:
    """Main OSINT Toolkit class"""
    
    def __init__(self, output_dir: str = "reports", github_token: Optional[str] = None,
                 shodan_key: Optional[str] = None, censys_id: Optional[str] = None,
                 censys_secret: Optional[str] = None):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.results = {}
        self.github_token = github_token
        
        # Initialize modules
        self.domain_intel = DomainIntel()
        self.social_intel = SocialIntel()
        self.github_intel = GitHubIntel()
        self.web_crawler = WebCrawler()
        self.email_intel = EmailIntel(github_token=github_token)
        self.url_hunter = URLHunter()
        self.port_scanner = PortScanner()
        self.employee_intel = EmployeeIntel()
        self.dark_web_intel = DarkWebIntel(use_tor=False)  # Tor disabled by default
        self.ip_intel = IPIntel()
        self.wayback_intel = WaybackIntel()
        self.phone_intel = PhoneIntel()
        self.paste_intel = PasteIntel(github_token=github_token)
        self.host_intel = HostIntel(shodan_key=shodan_key, censys_id=censys_id, censys_secret=censys_secret)
        self.dork_intel = DorkIntel()
        self.asn_intel = ASNIntel()
        self.bucket_intel = BucketIntel()
        self.takeover_intel = TakeoverIntel()
        self.favicon_intel = FaviconIntel()
        self.meta_intel = MetaIntel()
        self.correlator = Correlator()
        self.report_gen = ReportGenerator()
    
    def gather_domain_intel(self, domain: str, options: Dict[str, Any]) -> Dict:
        """Gather domain intelligence"""
        print(f"\n[+] Gathering domain intelligence for: {domain}")
        results = {
            'domain': domain,
            'dns_records': {},
            'subdomains': [],
            'whois': {},
            'ssl_info': {},
            'dnssec': {},
            'email_security': {},
        }
        
        if options.get('dns', True):
            print("  [*] Enumerating DNS records...")
            dns = self.domain_intel.enumerate_dns(domain)
            results['dns_records'] = dns
            results['dnssec'] = dns.get('dnssec') or {}
            results['email_security'] = dns.get('email_security') or {}
        
        if options.get('subdomains', True):
            print("  [*] Discovering subdomains...")
            results['subdomains'] = self.domain_intel.discover_subdomains(domain)
        
        if options.get('whois', True):
            print("  [*] Gathering WHOIS information...")
            results['whois'] = self.domain_intel.get_whois(domain)
        
        if options.get('ssl', True):
            print("  [*] Analyzing SSL certificate...")
            results['ssl_info'] = self.domain_intel.analyze_ssl(domain)
        
        return results
    
    def gather_social_intel(self, username: str, options: Dict[str, Any]) -> Dict:
        """Gather social media intelligence"""
        print(f"\n[+] Gathering social media intelligence for: {username}")
        results = {
            'username': username,
            'profiles': {},
            'email_addresses': [],
            'associated_accounts': []
        }
        
        if options.get('search', True):
            print("  [*] Searching across social platforms...")
            results['profiles'] = self.social_intel.search_username(username)
        
        if options.get('email', True):
            print("  [*] Discovering email addresses...")
            results['email_addresses'] = self.social_intel.discover_emails(username)
        
        if options.get('associated', True):
            print("  [*] Finding associated accounts...")
            results['associated_accounts'] = self.social_intel.find_associated_accounts(username)
        
        return results
    
    def gather_github_intel(self, username: str, options: Dict[str, Any]) -> Dict:
        """Gather GitHub intelligence"""
        print(f"\n[+] Gathering GitHub intelligence for: {username}")
        results = {
            'username': username,
            'profile': {},
            'repositories': [],
            'email': None,
            'creation_date': None
        }
        
        if options.get('profile', True):
            print("  [*] Fetching GitHub profile...")
            results['profile'] = self.github_intel.get_profile(username)
        
        if options.get('repos', True):
            print("  [*] Analyzing repositories...")
            results['repositories'] = self.github_intel.analyze_repositories(username)
        
        if options.get('email', True):
            print("  [*] Discovering email address...")
            results['email'] = self.github_intel.discover_email(username)
        
        if options.get('creation', True):
            print("  [*] Finding account creation date...")
            results['creation_date'] = self.github_intel.get_creation_date(username)
        
        return results
    
    def crawl_website(self, url: str, options: Dict[str, Any]) -> Dict:
        """Crawl website for intelligence"""
        print(f"\n[+] Crawling website: {url}")
        
        # Use comprehensive crawl if requested
        if options.get('comprehensive', False):
            print("  [*] Running comprehensive crawl (creepyCrawler-style)...")
            return self.web_crawler.comprehensive_crawl(
                url,
                max_depth=options.get('depth', 2),
                max_pages=options.get('max_pages', 500),
                include_robots=options.get('robots', True),
                include_sitemap=options.get('sitemap', True),
                extract_all=True
            )
        
        # Standard crawl
        results = {
            'url': url,
            'pages': [],
            'directories': [],
            'technologies': [],
            'emails': [],
            'phone_numbers': [],
            'social_links': []
        }
        
        if options.get('crawl', True):
            print("  [*] Crawling pages...")
            results['pages'] = self.web_crawler.crawl(url, max_depth=options.get('depth', 2))
        
        if options.get('directories', True):
            print("  [*] Enumerating directories...")
            results['directories'] = self.web_crawler.enumerate_directories(url)
        
        if options.get('tech', True):
            print("  [*] Detecting technologies...")
            results['technologies'] = self.web_crawler.detect_technologies(url)
        
        if options.get('extract', True):
            print("  [*] Extracting information...")
            extracted = self.web_crawler.extract_information(url, extract_all=options.get('extract_all', False))
            results['emails'] = extracted.get('emails', [])
            results['phone_numbers'] = extracted.get('phone_numbers', [])
            results['social_links'] = extracted.get('social_links', [])
            if options.get('extract_all', False):
                results['subdomains'] = extracted.get('subdomains', [])
                results['cloud_storage'] = extracted.get('cloud_storage', [])
                results['files'] = extracted.get('files', [])
                results['login_pages'] = extracted.get('login_pages', [])
                results['ip_addresses'] = extracted.get('ip_addresses', [])
                results['html_comments'] = extracted.get('html_comments', [])
                results['marketing_tags'] = extracted.get('marketing_tags', [])
        
        return results
    
    def hunt_urls(self, domain: str, options: Dict[str, Any]) -> Dict:
        """Hunt for exposed URLs via shortener services"""
        print(f"\n[+] Hunting URLs for: {domain}")
        results = {
            'domain': domain,
            'shortened_urls': [],
            'exposed_urls': []
        }
        
        if options.get('hunt', True):
            print("  [*] Searching for shortened URLs...")
            results['shortened_urls'] = self.url_hunter.find_shortened_urls(domain)
        
        if options.get('exposed', True):
            print("  [*] Finding exposed URLs...")
            results['exposed_urls'] = self.url_hunter.find_exposed_urls(domain)
        
        if options.get('urlteam', False):
            print("  [*] Searching URLTeam archives...")
            keywords = options.get('keywords', [domain])
            date = options.get('date', 'latest')
            urlteam_results = self.url_hunter.search_urlteam_archives(keywords, date=date)
            results['urlteam_matches'] = urlteam_results
        
        return results
    
    def analyze_dark_web(self, onion_url: str, options: Dict[str, Any]) -> Dict:
        """Analyze dark web .onion domain"""
        print(f"\n[+] Analyzing dark web: {onion_url}")
        results = {
            'onion_url': onion_url,
            'analysis': {},
            'crawl': {}
        }
        
        if options.get('analyze', True):
            print("  [*] Analyzing .onion domain...")
            results['analysis'] = self.dark_web_intel.analyze_onion(onion_url)
        
        if options.get('crawl', False):
            print("  [*] Crawling .onion domain...")
            results['crawl'] = self.dark_web_intel.crawl_onion(
                onion_url,
                max_depth=options.get('depth', 2),
                max_pages=options.get('max_pages', 50)
            )
        
        if options.get('map_links', False):
            print("  [*] Mapping link relationships...")
            results['link_map'] = self.dark_web_intel.map_onion_links(
                onion_url,
                max_depth=options.get('depth', 2)
            )
        
        return results
    
    def scan_ports(self, target: str, options: Dict[str, Any]) -> Dict:
        """Scan ports and detect services"""
        print(f"\n[+] Scanning ports for: {target}")
        results = {
            'target': target,
            'open_ports': [],
            'services': {},
            'banners': {}
        }
        
        if options.get('scan', True):
            ports = options.get('ports', 'common')
            print(f"  [*] Scanning ports ({ports})...")
            scan_results = self.port_scanner.scan(target, ports=ports)
            results['open_ports'] = scan_results.get('open_ports', [])
            results['services'] = scan_results.get('services', {})
            results['banners'] = scan_results.get('banners', {})
        
        return results
    
    def discover_emails(self, domain: str, options: Dict[str, Any]) -> Dict:
        """Discover email addresses"""
        print(f"\n[+] Discovering emails for: {domain}")
        results = {
            'domain': domain,
            'emails': [],
            'verified': [],
            'sources': {}
        }
        
        if options.get('discover', True):
            print("  [*] Discovering email addresses...")
            results['emails'] = self.email_intel.discover(domain)
        
        if options.get('verify', True):
            print("  [*] Verifying email addresses...")
            results['verified'] = self.email_intel.verify(results['emails'])
        
        if options.get('sources', True):
            print("  [*] Finding email sources...")
            results['sources'] = self.email_intel.find_sources(domain)
        
        return results
    
    def analyze_company(self, company: str, options: Dict[str, Any]) -> Dict:
        """Analyze company and discover employees with leaked credentials"""
        print(f"\n[+] Analyzing company: {company}")
        results = {
            'company': company,
            'employees': [],
            'leaked_credentials': [],
            'repositories': []
        }
        
        if options.get('discover', True):
            print("  [*] Discovering employees...")
            analysis = self.employee_intel.analyze_company(company)
            results['employees'] = analysis.get('employees', [])
            results['leaked_credentials'] = analysis.get('leaked_credentials', [])
            results['repositories'] = analysis.get('repositories', [])
        
        if options.get('check_leaks', True):
            print("  [*] Checking for leaked credentials...")
            # This is already done in analyze_company, but we can add more checks
            api_key = options.get('hibp_api_key')
            for employee in results['employees']:
                email = employee.get('email')
                if email:
                    leak_check = self.employee_intel.check_leaked_credentials(email, api_key)
                    if leak_check.get('breached'):
                        results['leaked_credentials'].append({
                            'employee': employee.get('name'),
                            'email': email,
                            'breaches': leak_check.get('breaches', []),
                            'pastes': leak_check.get('pastes', [])
                        })
        
        return results
    
    def analyze_ip(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict:
        """IP geo / ASN / risk intelligence"""
        print(f"\n[+] Analyzing IP: {target}")
        options = options or {}
        results = self.ip_intel.analyze(target)
        if options.get('shodan') or options.get('censys'):
            print("  [*] Querying host intel APIs...")
            results['host_intel'] = self.host_intel.analyze(target)
        return results

    def hunt_wayback(self, domain: str, options: Optional[Dict[str, Any]] = None) -> Dict:
        """Historical URLs via Wayback CDX"""
        print(f"\n[+] Wayback hunt: {domain}")
        options = options or {}
        return self.wayback_intel.hunt(
            domain,
            limit=int(options.get('limit', 200)),
            interesting_only=bool(options.get('interesting_only', True)),
        )

    def analyze_phone(self, number: str, options: Optional[Dict[str, Any]] = None) -> Dict:
        print(f"\n[+] Phone OSINT: {number}")
        return self.phone_intel.analyze(number)

    def hunt_pastes(self, query: str, options: Optional[Dict[str, Any]] = None) -> Dict:
        print(f"\n[+] Paste / leak hunt: {query}")
        options = options or {}
        return self.paste_intel.hunt(query, limit=int(options.get('limit', 30)))

    def analyze_host_apis(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict:
        print(f"\n[+] Host intel (Shodan/Censys): {target}")
        return self.host_intel.analyze(target)

    def search_onion_dirs(self, query: str) -> Dict:
        print(f"\n[+] Onion directory search: {query}")
        return {"query": query, "results": self.dark_web_intel.search_onion_directories(query)}

    def generate_dorks(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict:
        print(f"\n[+] Generating dorks: {target}")
        options = options or {}
        return self.dork_intel.generate(target, kind=options.get("kind", "auto"))

    def analyze_asn(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict:
        print(f"\n[+] ASN / netblock intel: {target}")
        return self.asn_intel.analyze(target)

    def hunt_buckets(self, name: str, options: Optional[Dict[str, Any]] = None) -> Dict:
        print(f"\n[+] Cloud bucket hunt: {name}")
        return self.bucket_intel.hunt(name)

    def check_takeovers(self, domain: str, options: Optional[Dict[str, Any]] = None) -> Dict:
        print(f"\n[+] Subdomain takeover check: {domain}")
        options = options or {}
        subs = options.get("subdomains")
        if subs is None and options.get("discover_subs", True):
            try:
                subs = self.domain_intel.discover_subdomains(domain)
            except Exception:
                subs = []
        return self.takeover_intel.check_domain(domain, subs)

    def analyze_favicon(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict:
        print(f"\n[+] Favicon hash: {target}")
        return self.favicon_intel.analyze(target)

    def analyze_metadata(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict:
        print(f"\n[+] Metadata / EXIF: {target}")
        return self.meta_intel.analyze(target)

    def correlate_results(self, results: Dict) -> Dict:
        print("\n[+] Correlating entities...")
        return self.correlator.correlate(results)

    def run_auto_scan(self, target: str) -> Dict:
        """Detect target type and run an appropriate full scan."""
        detected = detect_target_type(target)
        print(f"\n[+] Auto-detected type: {detected}")
        return self.run_full_scan(target, detected)
    
    def run_full_scan(self, target: str, scan_type: str = "domain") -> Dict:
        """Run a full comprehensive scan"""
        print(f"\n{'='*60}")
        print(f"  EPIC OSINT TOOLKIT - Full Scan")
        print(f"  Target: {target}")
        print(f"  Type: {scan_type}")
        print(f"  Timestamp: {self.timestamp}")
        print(f"{'='*60}\n")
        
        all_results = {
            'target': target,
            'scan_type': scan_type,
            'timestamp': self.timestamp,
            'results': {}
        }
        
        if scan_type == "domain":
            all_results['results']['domain'] = self.gather_domain_intel(target, {
                'dns': True, 'subdomains': True, 'whois': True, 'ssl': True
            })
            try:
                url = f"https://{target}" if not target.startswith('http') else target
                all_results['results']['website'] = self.crawl_website(url, {
                    'crawl': True, 'directories': True, 'tech': True, 'extract': True
                })
            except Exception:
                pass
            all_results['results']['emails'] = self.discover_emails(target, {
                'discover': True, 'verify': False, 'sources': True
            })
            all_results['results']['urls'] = self.hunt_urls(target, {
                'hunt': True, 'exposed': True
            })
            all_results['results']['wayback'] = self.hunt_wayback(target, {
                'limit': 100, 'interesting_only': True
            })
            all_results['results']['pastes'] = self.hunt_pastes(target, {'limit': 20})
            all_results['results']['ports'] = self.scan_ports(target, {
                'scan': True, 'ports': 'common'
            })
            all_results['results']['dorks'] = self.generate_dorks(target, {'kind': 'domain'})
            all_results['results']['buckets'] = self.hunt_buckets(target)
            try:
                subs = (all_results['results']['domain'] or {}).get('subdomains') or []
                all_results['results']['takeover'] = self.takeover_intel.check_domain(target, subs)
            except Exception:
                pass
            try:
                all_results['results']['favicon'] = self.analyze_favicon(target)
            except Exception:
                pass
            try:
                ip = (all_results['results']['domain'].get('dns_records') or {}).get('IP')
                if ip:
                    all_results['results']['ip'] = self.analyze_ip(ip, {})
                    all_results['results']['asn'] = self.analyze_asn(ip)
            except Exception:
                pass

        elif scan_type == "ip":
            all_results['results']['ip'] = self.analyze_ip(target, {})
            all_results['results']['asn'] = self.analyze_asn(target)
            all_results['results']['ports'] = self.scan_ports(target, {
                'scan': True, 'ports': 'common'
            })
            all_results['results']['host_intel'] = self.analyze_host_apis(target, {})
            all_results['results']['dorks'] = self.generate_dorks(target, {'kind': 'ip'})

        elif scan_type == "url":
            all_results['results']['website'] = self.crawl_website(target, {
                'crawl': True, 'directories': True, 'tech': True, 'extract': True
            })

        elif scan_type == "phone":
            all_results['results']['phone'] = self.analyze_phone(target, {})

        elif scan_type == "email":
            domain = target.split("@", 1)[-1]
            all_results['results']['pastes'] = self.hunt_pastes(target, {'limit': 25})
            all_results['results']['emails'] = {
                'domain': domain,
                'emails': [target],
                'verified': self.email_intel.verify([target]),
                'sources': self.email_intel.find_sources(domain),
            }
            all_results['results']['domain'] = self.gather_domain_intel(domain, {
                'dns': True, 'subdomains': False, 'whois': True, 'ssl': True
            })

        elif scan_type == "onion":
            all_results['results']['dark_web'] = self.analyze_dark_web(target, {
                'analyze': True, 'crawl': True, 'map_links': False, 'depth': 1, 'max_pages': 30
            })
            all_results['results']['onion_dirs'] = self.search_onion_dirs(target)

        elif scan_type == "username":
            all_results['results']['social'] = self.gather_social_intel(target, {
                'search': True, 'email': True, 'associated': True
            })
            all_results['results']['github'] = self.gather_github_intel(target, {
                'profile': True, 'repos': True, 'email': True, 'creation': True
            })
            all_results['results']['pastes'] = self.hunt_pastes(target, {'limit': 15})
        
        elif scan_type == "company":
            all_results['results']['company'] = self.analyze_company(target, {
                'discover': True, 'check_leaks': True, 'hibp_api_key': None
            })
            all_results['results']['pastes'] = self.hunt_pastes(target, {'limit': 15})

        all_results['correlation'] = self.correlate_results(all_results)
        return all_results
    
    def save_results(self, results: Dict, format: str = "json") -> str:
        """Save results to file"""
        safe_target = "".join(c if c.isalnum() or c in "._-" else "_" for c in str(results.get('target', 'unknown')))[:80]
        filename = f"osint_{self.timestamp}_{safe_target}.{format}"
        filepath = self.output_dir / filename
        
        if format == "json":
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, default=str)
        elif format == "txt":
            report = self.report_gen.generate_text_report(results)
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(report)
        elif format == "html":
            report = self.report_gen.generate_html_report(results)
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(report)
        
        return str(filepath)


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Epic OSINT Toolkit - Comprehensive Open Source Intelligence Gathering",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive TUI (keyboard GUI)
  python osint_toolkit.py
  python osint_toolkit.py --tui

  # Full domain scan
  python osint_toolkit.py -t example.com --full
  
  # Social media search
  python osint_toolkit.py -t username --type username
  
  # GitHub intelligence
  python osint_toolkit.py -t githubuser --github
  
  # Company employee discovery and leak checking
  python osint_toolkit.py -t "Company Name" --type company --employees --leaks
  
  # Custom scan with specific modules
  python osint_toolkit.py -t example.com --dns --subdomains --ports
  
  # Save as HTML report
  python osint_toolkit.py -t example.com --full --format html
        """
    )
    
    parser.add_argument('-t', '--target', help='Target (domain, username, IP, company, etc.)')
    parser.add_argument('--tui', action='store_true', help='Launch interactive ASCII/ANSI TUI')
    parser.add_argument('--type',
                       choices=['domain', 'username', 'ip', 'url', 'company', 'onion', 'phone', 'email', 'auto'],
                       default='auto',
                       help='Type of target (default: auto-detect)')
    parser.add_argument('--full', action='store_true', help='Run full comprehensive scan')
    parser.add_argument('--auto', action='store_true', help='Auto-detect target type and scan')
    
    # Module flags
    parser.add_argument('--dns', action='store_true', help='DNS enumeration')
    parser.add_argument('--subdomains', action='store_true', help='Subdomain discovery')
    parser.add_argument('--whois', action='store_true', help='WHOIS lookup')
    parser.add_argument('--ssl', action='store_true', help='SSL certificate analysis')
    parser.add_argument('--social', action='store_true', help='Social media search')
    parser.add_argument('--github', action='store_true', help='GitHub intelligence')
    parser.add_argument('--crawl', action='store_true', help='Website crawling')
    parser.add_argument('--directories', action='store_true', help='Directory enumeration')
    parser.add_argument('--emails', action='store_true', help='Email discovery')
    parser.add_argument('--urls', action='store_true', help='URL hunting')
    parser.add_argument('--wayback', action='store_true', help='Wayback Machine historical URLs')
    parser.add_argument('--pastes', action='store_true', help='Paste / code leak hunt')
    parser.add_argument('--ip', action='store_true', help='IP geo/ASN intelligence')
    parser.add_argument('--phone', action='store_true', help='Phone OSINT')
    parser.add_argument('--shodan', action='store_true', help='Shodan host lookup (needs API key)')
    parser.add_argument('--censys', action='store_true', help='Censys host lookup (needs API creds)')
    parser.add_argument('--ports', action='store_true', help='Port scanning')
    parser.add_argument('--employees', action='store_true', help='Discover company employees')
    parser.add_argument('--leaks', action='store_true', help='Check for leaked credentials')
    parser.add_argument('--comprehensive-crawl', action='store_true', help='Comprehensive crawl (creepyCrawler-style)')
    parser.add_argument('--robots', action='store_true', help='Parse robots.txt')
    parser.add_argument('--sitemap', action='store_true', help='Parse sitemap.xml')
    parser.add_argument('--urlteam', action='store_true', help='Search URLTeam archives')
    parser.add_argument('--dark-web', action='store_true', help='Analyze dark web .onion domain')
    parser.add_argument('--onion-search', action='store_true', help='Search onion directories (Ahmia)')
    parser.add_argument('--dorks', action='store_true', help='Generate search-engine dork packs')
    parser.add_argument('--asn', action='store_true', help='ASN / netblock intelligence')
    parser.add_argument('--buckets', action='store_true', help='Cloud bucket / blob exposure hunt')
    parser.add_argument('--takeover', action='store_true', help='Subdomain takeover fingerprint checks')
    parser.add_argument('--favicon', action='store_true', help='Favicon mmh3 hash + Shodan pivot')
    parser.add_argument('--meta', action='store_true', help='EXIF / metadata from image URL or local file')
    parser.add_argument('--tor', action='store_true', help='Use Tor proxy (requires Tor running)')
    parser.add_argument('--correlate', action='store_true', help='Build entity correlation graph')
    
    # Options
    parser.add_argument('--keywords-file', help='Keywords file for URLTeam search')
    parser.add_argument('--urlteam-date', default='latest', help='URLTeam archive date (latest, YYYY-MM-DD, YYYY, or range)')
    parser.add_argument('--max-pages', type=int, default=500, help='Maximum pages to crawl (default: 500)')
    parser.add_argument('--hibp-api-key', help='Have I Been Pwned API key (for leak checking)')
    parser.add_argument('--github-token', help='GitHub API token (raises rate limits)')
    parser.add_argument('--shodan-key', help='Shodan API key')
    parser.add_argument('--censys-id', help='Censys API ID')
    parser.add_argument('--censys-secret', help='Censys API secret')
    parser.add_argument('-o', '--output', default='reports', help='Output directory (default: reports)')
    parser.add_argument('-f', '--format', choices=['json', 'txt', 'html'], default='json',
                       help='Output format (default: json)')
    parser.add_argument('--ports-range', default='common', help='Port range to scan (default: common)')
    parser.add_argument('--depth', type=int, default=2, help='Crawl depth (default: 2)')
    parser.add_argument('--quiet', action='store_true', help='Quiet mode (minimal output)')
    
    args = parser.parse_args()
    
    # Initialize toolkit
    toolkit = OSINTToolkit(
        output_dir=args.output,
        github_token=args.github_token,
        shodan_key=args.shodan_key,
        censys_id=args.censys_id,
        censys_secret=args.censys_secret,
    )
    
    # Interactive TUI when no target given, or --tui requested
    if args.tui or not args.target:
        from modules.tui import launch_tui
        if args.tor:
            toolkit.dark_web_intel = DarkWebIntel(use_tor=True)
        try:
            launch_tui(toolkit)
        except KeyboardInterrupt:
            print("\n[!] Exited")
            sys.exit(0)
        return

    # Enable Tor if requested
    if args.tor:
        toolkit.dark_web_intel = DarkWebIntel(use_tor=True)

    scan_type = args.type
    if args.auto or scan_type == 'auto':
        scan_type = detect_target_type(args.target)
    
    try:
        if args.full or args.auto:
            results = toolkit.run_full_scan(args.target, scan_type)
        else:
            # Run specific modules
            results = {
                'target': args.target,
                'scan_type': scan_type,
                'timestamp': toolkit.timestamp,
                'results': {}
            }

            # Type-agnostic module flags
            if args.ip:
                results['results']['ip'] = toolkit.analyze_ip(args.target, {
                    'shodan': args.shodan, 'censys': args.censys
                })
            if args.phone:
                results['results']['phone'] = toolkit.analyze_phone(args.target)
            if args.wayback:
                results['results']['wayback'] = toolkit.hunt_wayback(args.target, {
                    'limit': 200, 'interesting_only': True
                })
            if args.pastes:
                results['results']['pastes'] = toolkit.hunt_pastes(args.target, {'limit': 30})
            if args.shodan or args.censys:
                results['results']['host_intel'] = toolkit.analyze_host_apis(args.target)
            if args.onion_search:
                results['results']['onion_dirs'] = toolkit.search_onion_dirs(args.target)
            if args.dorks:
                results['results']['dorks'] = toolkit.generate_dorks(args.target)
            if args.asn:
                results['results']['asn'] = toolkit.analyze_asn(args.target)
            if args.buckets:
                results['results']['buckets'] = toolkit.hunt_buckets(args.target)
            if args.takeover:
                results['results']['takeover'] = toolkit.check_takeovers(args.target)
            if args.favicon:
                results['results']['favicon'] = toolkit.analyze_favicon(args.target)
            if args.meta:
                results['results']['meta'] = toolkit.analyze_metadata(args.target)
            
            if scan_type == 'domain':
                module_flags = [
                    args.dns, args.subdomains, args.whois, args.ssl, args.crawl,
                    args.directories, args.comprehensive_crawl, args.emails,
                    args.urls, args.urlteam, args.ports, args.wayback, args.pastes, args.ip,
                    args.dorks, args.asn, args.buckets, args.takeover, args.favicon, args.meta,
                ]
                run_domain = args.dns or args.subdomains or args.whois or args.ssl or not any(module_flags)
                if run_domain:
                    results['results']['domain'] = toolkit.gather_domain_intel(args.target, {
                        'dns': args.dns or not any(module_flags),
                        'subdomains': args.subdomains,
                        'whois': args.whois,
                        'ssl': args.ssl
                    })
                
                if args.crawl or args.directories or args.comprehensive_crawl:
                    url = f"https://{args.target}" if not args.target.startswith('http') else args.target
                    results['results']['website'] = toolkit.crawl_website(url, {
                        'crawl': args.crawl or args.comprehensive_crawl,
                        'directories': args.directories,
                        'tech': True,
                        'extract': True,
                        'extract_all': args.comprehensive_crawl,
                        'comprehensive': args.comprehensive_crawl,
                        'robots': args.robots or args.comprehensive_crawl,
                        'sitemap': args.sitemap or args.comprehensive_crawl,
                        'depth': args.depth,
                        'max_pages': args.max_pages
                    })
                
                if args.emails:
                    results['results']['emails'] = toolkit.discover_emails(args.target, {
                        'discover': True,
                        'verify': False,
                        'sources': True
                    })
                
                if args.urls or args.urlteam:
                    keywords = [args.target]
                    if args.keywords_file:
                        try:
                            with open(args.keywords_file, 'r', encoding='utf-8') as f:
                                keywords = [line.strip() for line in f if line.strip()]
                        except OSError:
                            pass
                    
                    results['results']['urls'] = toolkit.hunt_urls(args.target, {
                        'hunt': args.urls,
                        'exposed': args.urls,
                        'urlteam': args.urlteam,
                        'keywords': keywords,
                        'date': args.urlteam_date
                    })

                if args.ports:
                    results['results']['ports'] = toolkit.scan_ports(args.target, {
                        'scan': True,
                        'ports': args.ports_range
                    })
            
            elif scan_type == 'ip':
                if 'ip' not in results['results']:
                    results['results']['ip'] = toolkit.analyze_ip(args.target, {
                        'shodan': args.shodan, 'censys': args.censys
                    })
                if args.ports or not any([args.shodan, args.censys, args.pastes]):
                    results['results']['ports'] = toolkit.scan_ports(args.target, {
                        'scan': True, 'ports': args.ports_range
                    })

            elif scan_type == 'phone':
                if 'phone' not in results['results']:
                    results['results']['phone'] = toolkit.analyze_phone(args.target)

            elif scan_type == 'email':
                domain = args.target.split('@', 1)[-1]
                results['results']['emails'] = {
                    'domain': domain,
                    'emails': [args.target],
                    'verified': toolkit.email_intel.verify([args.target]),
                    'sources': toolkit.email_intel.find_sources(domain),
                }
                results['results']['pastes'] = toolkit.hunt_pastes(args.target, {'limit': 25})

            elif scan_type == 'url':
                results['results']['website'] = toolkit.crawl_website(args.target, {
                    'crawl': True, 'directories': args.directories, 'tech': True, 'extract': True,
                    'depth': args.depth, 'max_pages': args.max_pages
                })
            
            elif scan_type == 'onion':
                if args.dark_web or args.onion_search or not args.ports:
                    results['results']['dark_web'] = toolkit.analyze_dark_web(args.target, {
                        'analyze': True,
                        'crawl': True,
                        'map_links': False,
                        'depth': args.depth,
                        'max_pages': args.max_pages
                    })
                if args.onion_search:
                    results['results']['onion_dirs'] = toolkit.search_onion_dirs(args.target)
                if args.ports:
                    results['results']['ports'] = toolkit.scan_ports(args.target, {
                        'scan': True,
                        'ports': args.ports_range
                    })
            
            elif scan_type == 'username':
                if args.social or (not args.github):
                    results['results']['social'] = toolkit.gather_social_intel(args.target, {
                        'search': True,
                        'email': True,
                        'associated': True
                    })
                
                if args.github:
                    results['results']['github'] = toolkit.gather_github_intel(args.target, {
                        'profile': True,
                        'repos': True,
                        'email': True,
                        'creation': True
                    })
            
            elif scan_type == 'company':
                results['results']['company'] = toolkit.analyze_company(args.target, {
                    'discover': args.employees or not args.leaks,
                    'check_leaks': args.leaks or not args.employees,
                    'hibp_api_key': args.hibp_api_key
                })

            if args.correlate or results.get('results'):
                results['correlation'] = toolkit.correlate_results(results)
        
        # Save results
        if not args.quiet:
            print(f"\n[+] Saving results...")
        filepath = toolkit.save_results(results, args.format)
        
        if not args.quiet:
            print(f"\n{'='*60}")
            print(f"  Scan completed successfully!")
            print(f"  Results saved to: {filepath}")
            print(f"{'='*60}\n")
        
        # Print summary
        if not args.quiet:
            toolkit.report_gen.print_summary(results)
    
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        if not args.quiet:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

