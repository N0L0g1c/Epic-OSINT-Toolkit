"""Web Crawler Module - Website crawling, directory enumeration, technology detection"""

import json
import requests
from bs4 import BeautifulSoup
import re
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import time


class WebCrawler:
    """Web crawling and intelligence gathering"""
    
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.visited_urls: Set[str] = set()
        
        # Common directory wordlist
        self.directory_wordlist = [
            'admin', 'administrator', 'api', 'app', 'assets', 'backup', 'blog',
            'cdn', 'config', 'database', 'db', 'dev', 'development', 'docs',
            'download', 'downloads', 'files', 'forum', 'ftp', 'git', 'help',
            'images', 'img', 'includes', 'index', 'js', 'lib', 'libs', 'mail',
            'media', 'mobile', 'old', 'panel', 'phpmyadmin', 'private', 'public',
            'secure', 'server', 'shop', 'sql', 'static', 'stats', 'store',
            'support', 'test', 'tmp', 'tools', 'uploads', 'user', 'users',
            'v1', 'v2', 'vendor', 'web', 'www', 'xml', 'xmlrpc'
        ]
        
        # Technology signatures
        self.tech_signatures = {
            'WordPress': ['wp-content', 'wp-includes', 'wp-admin'],
            'Drupal': ['sites/all', 'misc/drupal.js'],
            'Joomla': ['/administrator/', 'components/com_'],
            'Laravel': ['/vendor/laravel', 'laravel_session'],
            'React': ['react', 'react-dom'],
            'Vue.js': ['vue.js', 'vue.min.js'],
            'Angular': ['angular.js', '@angular'],
            'jQuery': ['jquery', 'jquery.min.js'],
            'Bootstrap': ['bootstrap', 'bootstrap.min.css'],
            'PHP': ['index.php', '.php'],
            'ASP.NET': ['.aspx', '__VIEWSTATE'],
            'Node.js': ['node_modules', 'package.json'],
            'Django': ['/admin/', 'csrfmiddlewaretoken'],
            'Flask': ['flask', 'werkzeug']
        }
    
    def crawl(self, url: str, max_depth: int = 2, max_pages: int = 100) -> List[Dict]:
        """Crawl website and extract information"""
        if not url.startswith('http'):
            url = f"https://{url}"
        
        pages = []
        self.visited_urls.clear()
        
        def crawl_recursive(current_url: str, depth: int = 0):
            if depth > max_depth or len(pages) >= max_pages:
                return
            
            if current_url in self.visited_urls:
                return
            
            self.visited_urls.add(current_url)
            
            try:
                response = self.session.get(current_url, timeout=10, allow_redirects=True)
                if response.status_code == 200:
                    page_info = {
                        'url': current_url,
                        'status_code': response.status_code,
                        'title': self._extract_title(response.text),
                        'links': [],
                        'forms': []
                    }
                    
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Extract links
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        full_url = urljoin(current_url, href)
                        if self._is_same_domain(full_url, url):
                            page_info['links'].append(full_url)
                            if depth < max_depth:
                                crawl_recursive(full_url, depth + 1)
                    
                    # Extract forms
                    for form in soup.find_all('form'):
                        form_info = {
                            'action': form.get('action', ''),
                            'method': form.get('method', 'GET'),
                            'inputs': []
                        }
                        for input_tag in form.find_all(['input', 'textarea', 'select']):
                            form_info['inputs'].append({
                                'name': input_tag.get('name', ''),
                                'type': input_tag.get('type', 'text')
                            })
                        page_info['forms'].append(form_info)
                    
                    pages.append(page_info)
            
            except Exception:
                pass
        
        crawl_recursive(url)
        return pages
    
    def enumerate_directories(self, url: str, threads: int = 20) -> List[Dict]:
        """Enumerate directories and files"""
        if not url.startswith('http'):
            url = f"https://{url}"
        
        base_url = url.rstrip('/')
        found_directories = []
        
        def check_directory(directory):
            test_url = f"{base_url}/{directory}"
            try:
                response = self.session.get(test_url, timeout=5, allow_redirects=False)
                if response.status_code in [200, 301, 302, 403]:
                    return {
                        'url': test_url,
                        'status_code': response.status_code,
                        'size': len(response.content),
                        'type': 'directory' if response.status_code == 301 else 'file'
                    }
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(check_directory, dir_name) for dir_name in self.directory_wordlist]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found_directories.append(result)
                time.sleep(0.1)  # Rate limiting
        
        return found_directories
    
    def detect_technologies(self, url: str) -> List[str]:
        """Detect technologies used on website"""
        if not url.startswith('http'):
            url = f"https://{url}"
        
        detected_tech = []
        
        try:
            response = self.session.get(url, timeout=10)
            content = response.text.lower()
            headers = {k.lower(): v for k, v in response.headers.items()}
            
            # Check headers
            server = headers.get('server', '')
            x_powered_by = headers.get('x-powered-by', '')
            
            if 'apache' in server.lower():
                detected_tech.append('Apache')
            if 'nginx' in server.lower():
                detected_tech.append('Nginx')
            if 'iis' in server.lower() or 'microsoft' in server.lower():
                detected_tech.append('IIS')
            if x_powered_by:
                detected_tech.append(f'X-Powered-By: {x_powered_by}')
            
            # Check content signatures
            for tech, signatures in self.tech_signatures.items():
                for signature in signatures:
                    if signature.lower() in content:
                        if tech not in detected_tech:
                            detected_tech.append(tech)
                        break
            
            # Check for common JavaScript libraries
            js_patterns = {
                'jQuery': r'jquery[.-]?\d+\.\d+',
                'React': r'react[.-]?\d+\.\d+',
                'Vue': r'vue[.-]?\d+\.\d+',
                'Angular': r'angular[.-]?\d+\.\d+'
            }
            
            for lib, pattern in js_patterns.items():
                if re.search(pattern, content, re.IGNORECASE):
                    if lib not in detected_tech:
                        detected_tech.append(lib)
        
        except:
            pass
        
        return detected_tech
    
    def extract_information(self, url: str, extract_all: bool = True) -> Dict:
        """Extract comprehensive information (creepyCrawler-style)"""
        if not url.startswith('http'):
            url = f"https://{url}"
        
        extracted = {
            'emails': [],
            'phone_numbers': [],
            'social_links': [],
            'subdomains': [],
            'cloud_storage': [],
            'files': [],
            'login_pages': [],
            'ip_addresses': [],
            'html_comments': [],
            'marketing_tags': [],
            'interesting_findings': []
        }
        
        try:
            response = self.session.get(url, timeout=10)
            content = response.text
            
            # Extract emails
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            emails = re.findall(email_pattern, content)
            extracted['emails'] = list(set(emails))
            
            # Extract phone numbers
            phone_patterns = [
                r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',  # US format
                r'\b\+?\d{1,3}[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',  # International
                r'\b\d{2,4}[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b'  # Generic
            ]
            phones = []
            for pattern in phone_patterns:
                phones.extend(re.findall(pattern, content))
            extracted['phone_numbers'] = list(set(phones))
            
            # Extract social links
            social_patterns = {
                'twitter': r'https?://(?:www\.)?(?:twitter\.com|x\.com)/[\w/]+',
                'facebook': r'https?://(?:www\.)?facebook\.com/[\w/]+',
                'instagram': r'https?://(?:www\.)?instagram\.com/[\w/]+',
                'linkedin': r'https?://(?:www\.)?linkedin\.com/[\w/]+',
                'youtube': r'https?://(?:www\.)?youtube\.com/[\w/]+',
                'github': r'https?://(?:www\.)?github\.com/[\w/]+'
            }
            
            for platform, pattern in social_patterns.items():
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    extracted['social_links'].append({
                        'platform': platform,
                        'url': match
                    })
            
            if extract_all:
                # Extract subdomains
                domain = urlparse(url).netloc
                base_domain = '.'.join(domain.split('.')[-2:])
                subdomain_pattern = rf'https?://([\w\-]+\.)+{re.escape(base_domain)}'
                subdomains = re.findall(subdomain_pattern, content, re.IGNORECASE)
                extracted['subdomains'] = list(set([s.rstrip('.') for s in subdomains]))
                
                # Extract cloud storage links (AWS, Azure, GCP)
                cloud_patterns = {
                    'aws_s3': r'https?://([\w\-]+)\.s3[\.\-]([\w\-]+)?\.amazonaws\.com',
                    'aws_cloudfront': r'https?://([\w\-]+)\.cloudfront\.net',
                    'azure_blob': r'https?://([\w\-]+)\.blob\.core\.windows\.net',
                    'gcp_storage': r'https?://storage\.cloud\.google\.com/[\w/]+',
                    'gcp_storage2': r'https?://storage\.googleapis\.com/[\w/]+',
                    'dropbox': r'https?://(?:www\.)?dropbox\.com/[\w/]+',
                    'onedrive': r'https?://(?:onedrive|1drv)\.(?:live|ms)/[\w/]+',
                    'google_drive': r'https?://drive\.google\.com/[\w/]+',
                    'google_docs': r'https?://docs\.google\.com/[\w/]+'
                }
                
                for cloud_type, pattern in cloud_patterns.items():
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        if isinstance(match, tuple):
                            match = ''.join(match)
                        extracted['cloud_storage'].append({
                            'type': cloud_type,
                            'url': match if isinstance(match, str) else f"https://{match}"
                        })
                
                # Extract file links
                file_extensions = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
                                 '.zip', '.rar', '.tar', '.gz', '.csv', '.txt', '.json', '.xml']
                file_pattern = rf'https?://[^\s"\'<>]+({"|".join([re.escape(ext) for ext in file_extensions])})'
                files = re.findall(file_pattern, content, re.IGNORECASE)
                extracted['files'] = list(set(files))
                
                # Detect login pages
                login_indicators = ['login', 'signin', 'sign-in', 'auth', 'authentication', 
                                  'password', 'username', 'user', 'account']
                soup = BeautifulSoup(content, 'html.parser')
                forms = soup.find_all('form')
                for form in forms:
                    form_text = form.get_text().lower()
                    if any(indicator in form_text for indicator in login_indicators):
                        action = form.get('action', '')
                        extracted['login_pages'].append({
                            'url': urljoin(url, action) if action else url,
                            'method': form.get('method', 'GET')
                        })
                
                # Extract IP addresses
                ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                ips = re.findall(ip_pattern, content)
                # Filter out common non-IP patterns
                valid_ips = [ip for ip in ips if all(0 <= int(octet) <= 255 for octet in ip.split('.'))]
                extracted['ip_addresses'] = list(set(valid_ips))
                
                # Extract HTML comments
                comments = re.findall(r'<!--(.*?)-->', content, re.DOTALL)
                extracted['html_comments'] = [c.strip() for c in comments if c.strip()]
                
                # Extract marketing tags (UA, GTM, etc.)
                tag_patterns = {
                    'google_analytics': r'UA-\d+-\d+',
                    'gtm': r'GTM-[A-Z0-9]+',
                    'facebook_pixel': r'fbq\([\'"]init[\'"],\s*[\'"](\d+)[\'"]',
                    'hotjar': r'hj\([\'"]site_id[\'"],\s*[\'"](\d+)[\'"]'
                }
                
                for tag_type, pattern in tag_patterns.items():
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        extracted['marketing_tags'].append({
                            'type': tag_type,
                            'values': list(set(matches))
                        })
                
                # Interesting findings
                # Check for JSON responses
                try:
                    json.loads(content)
                    extracted['interesting_findings'].append({
                        'type': 'json_response',
                        'url': url,
                        'description': 'Page returns JSON content'
                    })
                except:
                    pass
                
                # Check for frame ancestors
                if 'X-Frame-Options' in response.headers:
                    extracted['interesting_findings'].append({
                        'type': 'frame_ancestors',
                        'value': response.headers['X-Frame-Options'],
                        'description': 'Frame options header found'
                    })
        
        except:
            pass
        
        return extracted
    
    def parse_robots_txt(self, url: str) -> List[str]:
        """Parse robots.txt and return URLs"""
        urls = []
        try:
            robots_url = urljoin(url.rstrip('/'), '/robots.txt')
            response = self.session.get(robots_url, timeout=10)
            if response.status_code == 200:
                for line in response.text.split('\n'):
                    line = line.strip()
                    if line.startswith('Disallow:') or line.startswith('Allow:'):
                        path = line.split(':', 1)[1].strip()
                        if path:
                            full_url = urljoin(url, path)
                            urls.append(full_url)
        except:
            pass
        return urls
    
    def parse_sitemap(self, url: str) -> List[str]:
        """Parse sitemap.xml and return URLs"""
        urls = []
        try:
            sitemap_urls = [
                urljoin(url.rstrip('/'), '/sitemap.xml'),
                urljoin(url.rstrip('/'), '/sitemap_index.xml')
            ]
            
            for sitemap_url in sitemap_urls:
                response = self.session.get(sitemap_url, timeout=10)
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'xml')
                    # Find all URL tags
                    for url_tag in soup.find_all('url'):
                        loc = url_tag.find('loc')
                        if loc:
                            urls.append(loc.text)
                    # Also check for sitemap index
                    for sitemap_tag in soup.find_all('sitemap'):
                        loc = sitemap_tag.find('loc')
                        if loc:
                            # Recursively parse nested sitemaps
                            nested_urls = self.parse_sitemap(loc.text)
                            urls.extend(nested_urls)
        except:
            pass
        return urls
    
    def comprehensive_crawl(self, url: str, max_depth: int = 2, max_pages: int = 500,
                           include_robots: bool = True, include_sitemap: bool = True,
                           extract_all: bool = True) -> Dict:
        """Comprehensive crawl with all creepyCrawler features"""
        if not url.startswith('http'):
            url = f"https://{url}"
        
        results = {
            'url': url,
            'pages': [],
            'directories': [],
            'technologies': [],
            'extracted_info': {},
            'robots_urls': [],
            'sitemap_urls': [],
            'all_urls': set()
        }
        
        # Parse robots.txt
        if include_robots:
            print("  [*] Parsing robots.txt...")
            results['robots_urls'] = self.parse_robots_txt(url)
            results['all_urls'].update(results['robots_urls'])
        
        # Parse sitemap
        if include_sitemap:
            print("  [*] Parsing sitemap.xml...")
            results['sitemap_urls'] = self.parse_sitemap(url)
            results['all_urls'].update(results['sitemap_urls'])
        
        # Crawl pages
        print("  [*] Crawling pages...")
        pages = self.crawl(url, max_depth=max_depth, max_pages=max_pages)
        results['pages'] = pages
        
        # Collect all URLs from crawled pages
        for page in pages:
            results['all_urls'].add(page['url'])
            results['all_urls'].update(page.get('links', []))
        
        # Extract comprehensive information from all pages
        if extract_all:
            print("  [*] Extracting comprehensive information...")
            all_extracted = {
                'emails': set(),
                'phone_numbers': set(),
                'social_links': [],
                'subdomains': set(),
                'cloud_storage': [],
                'files': set(),
                'login_pages': [],
                'ip_addresses': set(),
                'html_comments': [],
                'marketing_tags': [],
                'interesting_findings': []
            }
            
            for page_url in list(results['all_urls'])[:100]:  # Limit to 100 for performance
                try:
                    extracted = self.extract_information(page_url, extract_all=True)
                    all_extracted['emails'].update(extracted['emails'])
                    all_extracted['phone_numbers'].update(extracted['phone_numbers'])
                    all_extracted['social_links'].extend(extracted['social_links'])
                    all_extracted['subdomains'].update(extracted['subdomains'])
                    all_extracted['cloud_storage'].extend(extracted['cloud_storage'])
                    all_extracted['files'].update(extracted['files'])
                    all_extracted['login_pages'].extend(extracted['login_pages'])
                    all_extracted['ip_addresses'].update(extracted['ip_addresses'])
                    all_extracted['html_comments'].extend(extracted['html_comments'])
                    all_extracted['marketing_tags'].extend(extracted['marketing_tags'])
                    all_extracted['interesting_findings'].extend(extracted['interesting_findings'])
                except:
                    continue
            
            # Convert sets to lists
            results['extracted_info'] = {
                'emails': list(all_extracted['emails']),
                'phone_numbers': list(all_extracted['phone_numbers']),
                'social_links': all_extracted['social_links'],
                'subdomains': list(all_extracted['subdomains']),
                'cloud_storage': all_extracted['cloud_storage'],
                'files': list(all_extracted['files']),
                'login_pages': all_extracted['login_pages'],
                'ip_addresses': list(all_extracted['ip_addresses']),
                'html_comments': all_extracted['html_comments'],
                'marketing_tags': all_extracted['marketing_tags'],
                'interesting_findings': all_extracted['interesting_findings']
            }
        
        # Detect technologies
        print("  [*] Detecting technologies...")
        results['technologies'] = self.detect_technologies(url)
        
        # Enumerate directories
        print("  [*] Enumerating directories...")
        results['directories'] = self.enumerate_directories(url)
        
        results['all_urls'] = list(results['all_urls'])
        
        return results
    
    def _extract_title(self, html: str) -> str:
        """Extract page title"""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            title_tag = soup.find('title')
            return title_tag.text.strip() if title_tag else ''
        except:
            return ''
    
    def _is_same_domain(self, url1: str, url2: str) -> bool:
        """Check if two URLs are from the same domain"""
        try:
            domain1 = urlparse(url1).netloc
            domain2 = urlparse(url2).netloc
            return domain1 == domain2
        except:
            return False

