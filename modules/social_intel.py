"""Social Media Intelligence Module - Username search across platforms"""

import requests
import re
from typing import Dict, List, Optional
from urllib.parse import quote


class SocialIntel:
    """Social media intelligence gathering"""
    
    def __init__(self):
        self.platforms = {
            'github': 'https://github.com/{}',
            'twitter': 'https://twitter.com/{}',
            'instagram': 'https://www.instagram.com/{}',
            'facebook': 'https://www.facebook.com/{}',
            'linkedin': 'https://www.linkedin.com/in/{}',
            'reddit': 'https://www.reddit.com/user/{}',
            'youtube': 'https://www.youtube.com/{}',
            'tiktok': 'https://www.tiktok.com/@{}',
            'pinterest': 'https://www.pinterest.com/{}',
            'snapchat': 'https://www.snapchat.com/add/{}',
            'tumblr': 'https://{}.tumblr.com',
            'flickr': 'https://www.flickr.com/people/{}',
            'vimeo': 'https://vimeo.com/{}',
            'soundcloud': 'https://soundcloud.com/{}',
            'spotify': 'https://open.spotify.com/user/{}',
            'medium': 'https://medium.com/@{}',
            'dev.to': 'https://dev.to/{}',
            'stackoverflow': 'https://stackoverflow.com/users/{}',
            'keybase': 'https://keybase.io/{}',
            'gravatar': 'https://www.gravatar.com/avatar/{}',
            'about.me': 'https://about.me/{}',
            'angel.co': 'https://angel.co/{}',
            'behance': 'https://www.behance.net/{}',
            'dribbble': 'https://dribbble.com/{}',
            'codepen': 'https://codepen.io/{}',
            'gitlab': 'https://gitlab.com/{}',
            'bitbucket': 'https://bitbucket.org/{}'
        }
        
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
    
    def search_username(self, username: str) -> Dict:
        """Search for username across social media platforms"""
        results = {}
        
        for platform, url_template in self.platforms.items():
            try:
                url = url_template.format(quote(username))
                response = requests.get(url, headers=self.headers, timeout=5, allow_redirects=False)
                
                if response.status_code == 200:
                    results[platform] = {
                        'url': url,
                        'exists': True,
                        'status_code': response.status_code
                    }
                elif response.status_code in [301, 302, 303, 307, 308]:
                    results[platform] = {
                        'url': url,
                        'exists': True,
                        'status_code': response.status_code,
                        'redirect': response.headers.get('Location', '')
                    }
                else:
                    results[platform] = {
                        'url': url,
                        'exists': False,
                        'status_code': response.status_code
                    }
            except:
                results[platform] = {
                    'url': url_template.format(username),
                    'exists': None,
                    'error': 'Connection failed'
                }
        
        return results
    
    def discover_emails(self, username: str) -> List[str]:
        """Discover email addresses associated with username"""
        emails = []
        
        # Common email patterns
        common_domains = [
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
            'protonmail.com', 'icloud.com', 'aol.com', 'mail.com'
        ]
        
        # Try common email patterns
        for domain in common_domains:
            emails.append(f"{username}@{domain}")
            emails.append(f"{username}1@{domain}")
            emails.append(f"{username}2@{domain}")
        
        # Try variations
        variations = [
            f"{username}.{domain}" for domain in common_domains
        ]
        emails.extend(variations)
        
        return list(set(emails))
    
    def find_associated_accounts(self, username: str) -> List[Dict]:
        """Find accounts associated with the username"""
        associated = []
        
        # Search for username in various contexts
        search_queries = [
            f'"{username}"',
            f'"{username}" email',
            f'"{username}" profile',
            f'"{username}" contact'
        ]
        
        # This would typically use search engine APIs
        # For now, return placeholder structure
        for query in search_queries:
            associated.append({
                'query': query,
                'sources': [],
                'accounts': []
            })
        
        return associated
    
    def get_profile_info(self, platform: str, username: str) -> Dict:
        """Get detailed profile information from a platform"""
        # This would require platform-specific APIs or scraping
        # Placeholder for now
        return {
            'platform': platform,
            'username': username,
            'profile_url': self.platforms.get(platform, '').format(username),
            'info': {}
        }

