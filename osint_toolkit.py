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


class OSINTToolkit:
    """Main OSINT Toolkit class"""
    
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.results = {}
        
        # Initialize modules
        self.domain_intel = DomainIntel()
        self.social_intel = SocialIntel()
        self.github_intel = GitHubIntel()
        self.web_crawler = WebCrawler()
        self.email_intel = EmailIntel()
        self.url_hunter = URLHunter()
        self.port_scanner = PortScanner()
        self.employee_intel = EmployeeIntel()
        self.dark_web_intel = DarkWebIntel(use_tor=False)  # Tor disabled by default
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
            'dnssec': False
        }
        
        if options.get('dns', True):
            print("  [*] Enumerating DNS records...")
            results['dns_records'] = self.domain_intel.enumerate_dns(domain)
        
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
                'dns': True,
                'subdomains': True,
                'whois': True,
                'ssl': True
            })
            
            # Also crawl the website
            try:
                url = f"https://{target}" if not target.startswith('http') else target
                all_results['results']['website'] = self.crawl_website(url, {
                    'crawl': True,
                    'directories': True,
                    'tech': True,
                    'extract': True
                })
            except Exception:
                pass
            
            # Discover emails
            all_results['results']['emails'] = self.discover_emails(target, {
                'discover': True,
                'verify': False,
                'sources': True
            })
            
            # Hunt URLs
            all_results['results']['urls'] = self.hunt_urls(target, {
                'hunt': True,
                'exposed': True
            })
            
            # Scan ports
            all_results['results']['ports'] = self.scan_ports(target, {
                'scan': True,
                'ports': 'common'
            })
        
        elif scan_type == "username":
            all_results['results']['social'] = self.gather_social_intel(target, {
                'search': True,
                'email': True,
                'associated': True
            })
            
            # Also check GitHub
            all_results['results']['github'] = self.gather_github_intel(target, {
                'profile': True,
                'repos': True,
                'email': True,
                'creation': True
            })
        
        elif scan_type == "company":
            all_results['results']['company'] = self.analyze_company(target, {
                'discover': True,
                'check_leaks': True,
                'hibp_api_key': None
            })
        
        return all_results
    
    def save_results(self, results: Dict, format: str = "json") -> str:
        """Save results to file"""
        filename = f"osint_{self.timestamp}_{results.get('target', 'unknown')}.{format}"
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
    
    parser.add_argument('-t', '--target', required=True, help='Target (domain, username, IP, company, etc.)')
    parser.add_argument('--type', choices=['domain', 'username', 'ip', 'url', 'company', 'onion'], default='domain',
                       help='Type of target (default: domain)')
    parser.add_argument('--full', action='store_true', help='Run full comprehensive scan')
    
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
    parser.add_argument('--ports', action='store_true', help='Port scanning')
    parser.add_argument('--employees', action='store_true', help='Discover company employees')
    parser.add_argument('--leaks', action='store_true', help='Check for leaked credentials')
    parser.add_argument('--comprehensive-crawl', action='store_true', help='Comprehensive crawl (creepyCrawler-style)')
    parser.add_argument('--robots', action='store_true', help='Parse robots.txt')
    parser.add_argument('--sitemap', action='store_true', help='Parse sitemap.xml')
    parser.add_argument('--urlteam', action='store_true', help='Search URLTeam archives')
    parser.add_argument('--dark-web', action='store_true', help='Analyze dark web .onion domain')
    parser.add_argument('--tor', action='store_true', help='Use Tor proxy (requires Tor running)')
    
    # Options
    parser.add_argument('--keywords-file', help='Keywords file for URLTeam search')
    parser.add_argument('--urlteam-date', default='latest', help='URLTeam archive date (latest, YYYY-MM-DD, YYYY, or range)')
    parser.add_argument('--max-pages', type=int, default=500, help='Maximum pages to crawl (default: 500)')
    parser.add_argument('--hibp-api-key', help='Have I Been Pwned API key (for leak checking)')
    parser.add_argument('-o', '--output', default='reports', help='Output directory (default: reports)')
    parser.add_argument('-f', '--format', choices=['json', 'txt', 'html'], default='json',
                       help='Output format (default: json)')
    parser.add_argument('--ports-range', default='common', help='Port range to scan (default: common)')
    parser.add_argument('--depth', type=int, default=2, help='Crawl depth (default: 2)')
    parser.add_argument('--quiet', action='store_true', help='Quiet mode (minimal output)')
    
    args = parser.parse_args()
    
    # Initialize toolkit
    toolkit = OSINTToolkit(output_dir=args.output)
    
    # Enable Tor if requested
    if args.tor:
        toolkit.dark_web_intel = DarkWebIntel(use_tor=True)
    
    try:
        if args.full:
            # Run full scan
            results = toolkit.run_full_scan(args.target, args.type)
        else:
            # Run specific modules
            results = {
                'target': args.target,
                'scan_type': args.type,
                'timestamp': toolkit.timestamp,
                'results': {}
            }
            
            if args.type == 'domain':
                module_flags = [
                    args.dns, args.subdomains, args.whois, args.ssl, args.crawl,
                    args.directories, args.comprehensive_crawl, args.emails,
                    args.urls, args.urlteam, args.ports
                ]
                # Default to DNS when no module flags are provided
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
            
            elif args.type == 'onion':
                if args.dark_web or not args.ports:
                    results['results']['dark_web'] = toolkit.analyze_dark_web(args.target, {
                        'analyze': True,
                        'crawl': True,
                        'map_links': False,
                        'depth': args.depth,
                        'max_pages': args.max_pages
                    })
                
                if args.ports:
                    results['results']['ports'] = toolkit.scan_ports(args.target, {
                        'scan': True,
                        'ports': args.ports_range
                    })
            
            elif args.type == 'username':
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
            
            elif args.type == 'company':
                results['results']['company'] = toolkit.analyze_company(args.target, {
                    'discover': args.employees or not args.leaks,
                    'check_leaks': args.leaks or not args.employees,
                    'hibp_api_key': args.hibp_api_key
                })
        
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

