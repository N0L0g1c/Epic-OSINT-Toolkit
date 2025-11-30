"""GitHub Intelligence Module - GitHub user and repository analysis"""

import requests
import re
from typing import Dict, List, Optional
from datetime import datetime


class GitHubIntel:
    """GitHub intelligence gathering"""
    
    def __init__(self, token: Optional[str] = None):
        self.base_url = "https://api.github.com"
        self.token = token
        self.headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'Epic-OSINT-Toolkit'
        }
        if token:
            self.headers['Authorization'] = f'token {token}'
    
    def get_profile(self, username: str) -> Dict:
        """Get GitHub user profile"""
        try:
            url = f"{self.base_url}/users/{username}"
            response = requests.get(url, headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'login': data.get('login'),
                    'id': data.get('id'),
                    'name': data.get('name'),
                    'company': data.get('company'),
                    'blog': data.get('blog'),
                    'location': data.get('location'),
                    'email': data.get('email'),
                    'bio': data.get('bio'),
                    'public_repos': data.get('public_repos'),
                    'public_gists': data.get('public_gists'),
                    'followers': data.get('followers'),
                    'following': data.get('following'),
                    'created_at': data.get('created_at'),
                    'updated_at': data.get('updated_at'),
                    'avatar_url': data.get('avatar_url'),
                    'html_url': data.get('html_url'),
                    'twitter_username': data.get('twitter_username'),
                    'hireable': data.get('hireable')
                }
            else:
                return {'error': f'Status code: {response.status_code}'}
        except Exception as e:
            return {'error': str(e)}
    
    def analyze_repositories(self, username: str, limit: int = 100) -> List[Dict]:
        """Analyze user repositories"""
        repos = []
        
        try:
            url = f"{self.base_url}/users/{username}/repos"
            params = {'per_page': min(limit, 100), 'sort': 'updated'}
            
            page = 1
            while len(repos) < limit:
                params['page'] = page
                response = requests.get(url, headers=self.headers, params=params, timeout=10)
                
                if response.status_code != 200:
                    break
                
                data = response.json()
                if not data:
                    break
                
                for repo in data:
                    repos.append({
                        'name': repo.get('name'),
                        'full_name': repo.get('full_name'),
                        'description': repo.get('description'),
                        'url': repo.get('html_url'),
                        'language': repo.get('language'),
                        'stars': repo.get('stargazers_count'),
                        'forks': repo.get('forks_count'),
                        'watchers': repo.get('watchers_count'),
                        'created_at': repo.get('created_at'),
                        'updated_at': repo.get('updated_at'),
                        'pushed_at': repo.get('pushed_at'),
                        'private': repo.get('private'),
                        'fork': repo.get('fork'),
                        'topics': repo.get('topics', [])
                    })
                    
                    if len(repos) >= limit:
                        break
                
                page += 1
                if len(data) < 100:
                    break
        
        except Exception as e:
            return [{'error': str(e)}]
        
        return repos[:limit]
    
    def discover_email(self, username: str) -> Optional[str]:
        """Discover email address from GitHub profile and commits"""
        email = None
        
        # First check profile
        profile = self.get_profile(username)
        if profile.get('email'):
            email = profile['email']
            return email
        
        # Try to find email in commits
        try:
            url = f"{self.base_url}/users/{username}/events/public"
            response = requests.get(url, headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                events = response.json()
                for event in events[:10]:  # Check first 10 events
                    if event.get('type') == 'PushEvent':
                        commits = event.get('payload', {}).get('commits', [])
                        for commit in commits:
                            author = commit.get('author', {})
                            if author.get('email'):
                                email = author['email']
                                if 'noreply' not in email.lower():
                                    return email
        except:
            pass
        
        # Try to construct email from username
        # Common patterns: username@users.noreply.github.com
        email = f"{username}@users.noreply.github.com"
        
        return email
    
    def get_creation_date(self, username: str) -> Optional[str]:
        """Get account creation date"""
        profile = self.get_profile(username)
        return profile.get('created_at')
    
    def get_organizations(self, username: str) -> List[Dict]:
        """Get organizations user belongs to"""
        orgs = []
        
        try:
            url = f"{self.base_url}/users/{username}/orgs"
            response = requests.get(url, headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                for org in data:
                    orgs.append({
                        'login': org.get('login'),
                        'id': org.get('id'),
                        'description': org.get('description'),
                        'url': org.get('html_url'),
                        'avatar_url': org.get('avatar_url')
                    })
        except:
            pass
        
        return orgs
    
    def get_contributions(self, username: str) -> Dict:
        """Get contribution statistics"""
        repos = self.analyze_repositories(username, limit=100)
        
        languages = {}
        total_stars = 0
        total_forks = 0
        
        for repo in repos:
            lang = repo.get('language')
            if lang:
                languages[lang] = languages.get(lang, 0) + 1
            total_stars += repo.get('stars', 0)
            total_forks += repo.get('forks', 0)
        
        return {
            'total_repos': len(repos),
            'total_stars': total_stars,
            'total_forks': total_forks,
            'languages': languages,
            'most_used_language': max(languages.items(), key=lambda x: x[1])[0] if languages else None
        }

