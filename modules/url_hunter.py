"""URL Hunter Module - Find exposed URLs via shortener services (URLTeam archive search)"""

import requests
import re
import os
import json
import gzip
import tarfile
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse
from pathlib import Path
from datetime import datetime, timedelta


class URLHunter:
    """URL hunting for exposed URLs using URLTeam archives"""
    
    def __init__(self, archive_dir: str = "archive"):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.archive_dir = Path(archive_dir)
        self.archive_dir.mkdir(exist_ok=True)
        
        # URLTeam archive base URL (Archive.org)
        self.archive_base = "https://archive.org/download"
        
        # URL shortener services
        self.shortener_services = {
            'bit.ly': 'https://bit.ly/{}',
            'tinyurl.com': 'https://tinyurl.com/{}',
            't.co': 'https://t.co/{}',
            'goo.gl': 'https://goo.gl/{}',
            'ow.ly': 'https://ow.ly/{}',
            'is.gd': 'https://is.gd/{}',
            'buff.ly': 'https://buff.ly/{}',
            'short.link': 'https://short.link/{}',
            'cutt.ly': 'https://cutt.ly/{}',
            'rebrand.ly': 'https://rebrand.ly/{}'
        }
    
    def search_urlteam_archives(self, keywords: List[str], date: str = "latest", 
                                use_regex: bool = False) -> List[Dict]:
        """Search URLTeam archives for matching URLs"""
        results = []
        
        # Parse date
        dates = self._parse_date(date)
        
        for archive_date in dates:
            print(f"  [*] Searching archive for date: {archive_date}")
            
            # Download archive if needed
            archive_path = self._download_archive(archive_date)
            if not archive_path:
                continue
            
            # Extract and search
            urls = self._extract_urls_from_archive(archive_path)
            
            # Search for keywords
            matches = self._search_urls(urls, keywords, use_regex)
            results.extend(matches)
        
        return results
    
    def _parse_date(self, date_str: str) -> List[str]:
        """Parse date string into list of dates"""
        dates = []
        
        if date_str == "latest":
            # Get latest date (today)
            dates.append(datetime.now().strftime("%Y-%m-%d"))
        elif ":" in date_str:
            # Date range
            start_str, end_str = date_str.split(":")
            start = datetime.strptime(start_str, "%Y-%m-%d")
            end = datetime.strptime(end_str, "%Y-%m-%d")
            current = start
            while current <= end:
                dates.append(current.strftime("%Y-%m-%d"))
                current += timedelta(days=1)
        elif len(date_str) == 4:
            # Year only
            year = int(date_str)
            start = datetime(year, 1, 1)
            end = datetime(year, 12, 31)
            current = start
            while current <= end:
                dates.append(current.strftime("%Y-%m-%d"))
                current += timedelta(days=1)
        else:
            # Single date
            dates.append(date_str)
        
        return dates
    
    def _download_archive(self, date: str) -> Optional[Path]:
        """Download URLTeam archive for given date"""
        # Archive naming: urlteam_YYYY-MM-DD-HH-MM-SS
        # We'll try to find the archive for the date
        archive_name = f"urlteam_{date}"
        archive_path = self.archive_dir / archive_name
        
        # Check if already downloaded
        if archive_path.exists():
            return archive_path
        
        # Try to download from Archive.org
        # Note: This is a placeholder - actual URLTeam archives are on Archive.org
        # and may require specific identifiers
        print(f"    [*] Archive not found locally. Download would be needed from Archive.org")
        print(f"    [*] For production use, download archives manually or via torrent")
        print(f"    [*] Place archives in: {self.archive_dir}")
        
        return None
    
    def _extract_urls_from_archive(self, archive_path: Path) -> List[str]:
        """Extract URLs from archive file"""
        urls = []
        
        try:
            # Try to read as text file (if it's already extracted)
            if archive_path.is_file() and archive_path.suffix == '.txt':
                with open(archive_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if line and (line.startswith('http://') or line.startswith('https://')):
                            urls.append(line)
            
            # Try to extract from tar.gz
            elif archive_path.suffix == '.tar.gz' or archive_path.suffix == '.gz':
                if archive_path.suffix == '.tar.gz':
                    with tarfile.open(archive_path, 'r:gz') as tar:
                        for member in tar.getmembers():
                            if member.isfile():
                                f = tar.extractfile(member)
                                if f:
                                    content = f.read().decode('utf-8', errors='ignore')
                                    for line in content.split('\n'):
                                        line = line.strip()
                                        if line and (line.startswith('http://') or line.startswith('https://')):
                                            urls.append(line)
                else:
                    with gzip.open(archive_path, 'rt', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            line = line.strip()
                            if line and (line.startswith('http://') or line.startswith('https://')):
                                urls.append(line)
            
            # Try directory with files
            elif archive_path.is_dir():
                for file_path in archive_path.rglob('*.txt'):
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            for line in f:
                                line = line.strip()
                                if line and (line.startswith('http://') or line.startswith('https://')):
                                    urls.append(line)
                    except:
                        continue
        
        except Exception as e:
            print(f"    [!] Error extracting archive: {e}")
        
        return list(set(urls))
    
    def _search_urls(self, urls: List[str], keywords: List[str], use_regex: bool = False) -> List[Dict]:
        """Search URLs for keywords"""
        matches = []
        
        for url in urls:
            url_lower = url.lower()
            matched = False
            matched_keywords = []
            
            if use_regex:
                # Regex search
                for keyword in keywords:
                    if keyword.startswith('regex '):
                        pattern = keyword[6:]  # Remove 'regex ' prefix
                        try:
                            if re.search(pattern, url, re.IGNORECASE):
                                matched = True
                                matched_keywords.append(keyword)
                        except:
                            pass
            else:
                # Check if all keywords are in URL (AND logic)
                if ',' in keywords[0]:
                    # Multiple keywords with AND logic
                    keyword_list = [k.strip() for k in keywords[0].split(',')]
                    if all(k.lower() in url_lower for k in keyword_list):
                        matched = True
                        matched_keywords = keyword_list
                else:
                    # Single keyword (substring match)
                    for keyword in keywords:
                        if keyword.lower() in url_lower:
                            matched = True
                            matched_keywords.append(keyword)
            
            if matched:
                matches.append({
                    'url': url,
                    'keywords': matched_keywords,
                    'shortener': self._detect_shortener(url)
                })
        
        return matches
    
    def _detect_shortener(self, url: str) -> Optional[str]:
        """Detect which shortener service was used"""
        for service, pattern in self.shortener_services.items():
            if service in url:
                return service
        return None
    
    def find_shortened_urls(self, domain: str) -> List[Dict]:
        """Find URLs via local URLTeam archives, else Wayback CDX."""
        print(f"  [*] Searching archives / Wayback for: {domain}")
        results = self.search_urlteam_archives([domain], date="latest")
        if not results:
            results = self._wayback_urls(domain)
        return results

    def find_exposed_urls(self, domain: str) -> List[Dict]:
        """Find interesting / exposed historical URLs."""
        exposed = self.search_urlteam_archives(
            [domain, f"{domain},password", f"{domain},token", f"{domain},secret"],
            date="latest",
        )
        if not exposed:
            wb = self._wayback_urls(domain, interesting_only=True)
            exposed.extend(wb)
        return exposed

    def _wayback_urls(self, domain: str, interesting_only: bool = False) -> List[Dict]:
        try:
            from modules.wayback_intel import WaybackIntel
            data = WaybackIntel().hunt(domain, limit=150, interesting_only=interesting_only)
            return [
                {
                    "url": u.get("url"),
                    "keywords": [domain],
                    "shortener": None,
                    "timestamp": u.get("timestamp"),
                    "wayback": u.get("wayback"),
                    "source": "wayback",
                }
                for u in (data.get("urls") or [])
            ]
        except Exception as exc:
            print(f"  [!] Wayback fallback failed: {exc}")
            return []
    
    def expand_short_url(self, short_url: str) -> Optional[str]:
        """Expand a shortened URL to get the full URL"""
        try:
            response = requests.head(short_url, allow_redirects=True, timeout=10, headers=self.headers)
            return response.url
        except:
            try:
                response = requests.get(short_url, allow_redirects=True, timeout=10, headers=self.headers)
                return response.url
            except:
                return None
    
    def search_with_keywords_file(self, keywords_file: str, date: str = "latest") -> List[Dict]:
        """Search using keywords from file (like urlhunter tool)"""
        keywords = []
        
        try:
            with open(keywords_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        keywords.append(line)
        except Exception as e:
            print(f"  [!] Error reading keywords file: {e}")
            return []
        
        return self.search_urlteam_archives(keywords, date=date)
