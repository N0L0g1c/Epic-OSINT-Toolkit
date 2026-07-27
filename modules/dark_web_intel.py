"""Dark Web Intelligence Module - Tor/.onion domain crawling and analysis"""

import requests
import re
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import time


class DarkWebIntel:
    """Dark web and Tor intelligence gathering"""
    
    def __init__(self, use_tor: bool = True, tor_proxy: str = "socks5://127.0.0.1:9050"):
        self.use_tor = use_tor
        self.tor_proxy = tor_proxy
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        
        if use_tor:
            try:
                import socks  # noqa: F401 — required by requests for socks5h://
                # Scope Tor to this session only (avoid global socket monkey-patching)
                self.session.proxies.update({
                    'http': tor_proxy.replace('socks5://', 'socks5h://', 1)
                    if tor_proxy.startswith('socks5://') else tor_proxy,
                    'https': tor_proxy.replace('socks5://', 'socks5h://', 1)
                    if tor_proxy.startswith('socks5://') else tor_proxy,
                })
                print("  [*] Tor proxy configured (requires Tor running on 127.0.0.1:9050)")
            except ImportError:
                print("  [!] PySocks not installed. Install with: pip install PySocks")
                print("  [!] Continuing without Tor proxy...")
                self.use_tor = False
            except Exception as e:
                print(f"  [!] Error configuring Tor: {e}")
                self.use_tor = False
    
    def crawl_onion(self, onion_url: str, max_depth: int = 2, max_pages: int = 50) -> Dict:
        """Crawl .onion domain"""
        if not onion_url.startswith('http'):
            onion_url = f"http://{onion_url}"
        
        if '.onion' not in onion_url:
            return {'error': 'Not a .onion domain'}
        
        results = {
            'onion_url': onion_url,
            'pages': [],
            'links': [],
            'external_links': [],
            'onion_links': [],
            'emails': [],
            'ip_addresses': [],
            'technologies': [],
            'forms': [],
            'interesting_content': []
        }
        
        visited = set()
        
        def crawl_recursive(current_url: str, depth: int = 0):
            if depth > max_depth or len(results['pages']) >= max_pages:
                return
            
            if current_url in visited:
                return
            
            visited.add(current_url)
            
            try:
                response = self.session.get(current_url, timeout=30, allow_redirects=True)
                
                if response.status_code == 200:
                    page_info = {
                        'url': current_url,
                        'status_code': response.status_code,
                        'title': self._extract_title(response.text),
                        'content_length': len(response.content),
                        'links': []
                    }
                    
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Extract all links
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        full_url = urljoin(current_url, href)
                        
                        if '.onion' in full_url:
                            results['onion_links'].append(full_url)
                            page_info['links'].append(full_url)
                            if depth < max_depth:
                                crawl_recursive(full_url, depth + 1)
                        elif full_url.startswith('http'):
                            results['external_links'].append(full_url)
                        else:
                            page_info['links'].append(full_url)
                    
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
                        results['forms'].append(form_info)
                    
                    # Extract emails
                    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                    emails = re.findall(email_pattern, response.text)
                    results['emails'].extend(emails)
                    
                    # Extract IP addresses
                    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                    ips = re.findall(ip_pattern, response.text)
                    valid_ips = [ip for ip in ips if all(0 <= int(octet) <= 255 for octet in ip.split('.'))]
                    results['ip_addresses'].extend(valid_ips)
                    
                    # Detect interesting content
                    text_content = soup.get_text().lower()
                    interesting_keywords = ['bitcoin', 'btc', 'crypto', 'wallet', 'pgp', 'key',
                                         'password', 'login', 'admin', 'secret', 'hidden']
                    if any(keyword in text_content for keyword in interesting_keywords):
                        results['interesting_content'].append({
                            'url': current_url,
                            'keywords_found': [kw for kw in interesting_keywords if kw in text_content]
                        })
                    
                    results['pages'].append(page_info)
                    results['links'].extend(page_info['links'])
                
                time.sleep(1)  # Be respectful with Tor
            
            except Exception as e:
                results['errors'] = results.get('errors', [])
                results['errors'].append({
                    'url': current_url,
                    'error': str(e)
                })
        
        crawl_recursive(onion_url)
        
        # Remove duplicates
        results['emails'] = list(set(results['emails']))
        results['ip_addresses'] = list(set(results['ip_addresses']))
        results['onion_links'] = list(set(results['onion_links']))
        results['external_links'] = list(set(results['external_links']))
        
        return results
    
    def analyze_onion(self, onion_url: str) -> Dict:
        """Analyze .onion domain"""
        if not onion_url.startswith('http'):
            onion_url = f"http://{onion_url}"
        
        if '.onion' not in onion_url:
            return {'error': 'Not a .onion domain'}
        
        analysis = {
            'onion_url': onion_url,
            'accessible': False,
            'response_time': None,
            'status_code': None,
            'content_type': None,
            'server': None,
            'technologies': [],
            'links_count': 0,
            'onion_links_count': 0,
            'has_forms': False,
            'has_emails': False
        }
        
        try:
            start_time = time.time()
            response = self.session.get(onion_url, timeout=30)
            analysis['response_time'] = time.time() - start_time
            analysis['status_code'] = response.status_code
            analysis['accessible'] = response.status_code == 200
            
            if response.status_code == 200:
                analysis['content_type'] = response.headers.get('Content-Type', '')
                analysis['server'] = response.headers.get('Server', '')
                
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Count links
                links = soup.find_all('a', href=True)
                analysis['links_count'] = len(links)
                analysis['onion_links_count'] = len([l for l in links if '.onion' in l.get('href', '')])
                
                # Check for forms
                forms = soup.find_all('form')
                analysis['has_forms'] = len(forms) > 0
                
                # Check for emails
                email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                emails = re.findall(email_pattern, response.text)
                analysis['has_emails'] = len(emails) > 0
                
                # Detect technologies
                content_lower = response.text.lower()
                if 'wordpress' in content_lower:
                    analysis['technologies'].append('WordPress')
                if 'drupal' in content_lower:
                    analysis['technologies'].append('Drupal')
                if 'joomla' in content_lower:
                    analysis['technologies'].append('Joomla')
        
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis
    
    def search_onion_directories(self, query: str) -> List[Dict]:
        """Search clearnet onion indexes (Ahmia) — works without Tor for discovery."""
        results = []
        q = (query or "").strip()
        if not q or len(q) > 100:
            return results
        try:
            from urllib.parse import quote
            # Ahmia clearnet search
            url = f"https://ahmia.fi/search/?q={quote(q)}"
            # Use a plain session (not Tor) for clearnet index
            r = requests.get(url, headers=self.headers, timeout=20)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "html.parser")
                for a in soup.select("a"):
                    href = a.get("href") or ""
                    text = (a.get_text() or "").strip()
                    onion = None
                    m = re.search(r"([a-z2-7]{16,56}\.onion)", href + " " + text, re.I)
                    if m:
                        onion = m.group(1).lower()
                    if onion:
                        results.append({
                            "onion": onion,
                            "title": text[:200] or onion,
                            "source": "ahmia.fi",
                            "url": f"http://{onion}",
                        })
                # de-dupe
                seen = set()
                uniq = []
                for item in results:
                    if item["onion"] not in seen:
                        seen.add(item["onion"])
                        uniq.append(item)
                results = uniq[:50]
        except Exception as exc:
            print(f"  [!] Ahmia search failed: {exc}")
        # Optional Tor-only directories when Tor enabled
        if self.use_tor and not results:
            print("  [*] No Ahmia hits; Tor directory crawl skipped (indexes unstable)")
        return results
    
    def map_onion_links(self, onion_url: str, max_depth: int = 2) -> Dict:
        """Map link relationships between .onion sites"""
        if not onion_url.startswith('http'):
            onion_url = f"http://{onion_url}"
        
        link_map = {
            'root': onion_url,
            'nodes': {},
            'edges': []
        }
        
        visited = set()
        
        def map_recursive(current_url: str, depth: int = 0, parent: Optional[str] = None):
            if depth > max_depth or current_url in visited:
                return
            
            visited.add(current_url)
            
            try:
                response = self.session.get(current_url, timeout=30)
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Add node
                    link_map['nodes'][current_url] = {
                        'title': self._extract_title(response.text),
                        'depth': depth
                    }
                    
                    # Add edge if has parent
                    if parent:
                        link_map['edges'].append({
                            'from': parent,
                            'to': current_url
                        })
                    
                    # Find onion links
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        full_url = urljoin(current_url, href)
                        
                        if '.onion' in full_url and full_url not in visited:
                            map_recursive(full_url, depth + 1, current_url)
                
                time.sleep(1)
            
            except:
                pass
        
        map_recursive(onion_url)
        
        return link_map
    
    def _extract_title(self, html: str) -> str:
        """Extract page title"""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            title_tag = soup.find('title')
            return title_tag.text.strip() if title_tag else ''
        except:
            return ''

