"""Social Media Intelligence — username search across 100+ platforms."""

from __future__ import annotations

import hashlib
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional
from urllib.parse import quote

import requests
from bs4 import BeautifulSoup

from modules.net_util import DEFAULT_HEADERS

# platform -> url template with {} for username
PLATFORMS: Dict[str, str] = {
    # Dev / code
    "github": "https://github.com/{}",
    "gitlab": "https://gitlab.com/{}",
    "bitbucket": "https://bitbucket.org/{}",
    "codeberg": "https://codeberg.org/{}",
    "sourceforge": "https://sourceforge.net/u/{}/",
    "replit": "https://replit.com/@{}",
    "codepen": "https://codepen.io/{}",
    "jsfiddle": "https://jsfiddle.net/user/{}/",
    "leetcode": "https://leetcode.com/{}",
    "hackerrank": "https://www.hackerrank.com/{}",
    "kaggle": "https://www.kaggle.com/{}",
    "npm": "https://www.npmjs.com/~{}",
    "pypi": "https://pypi.org/user/{}",
    "dockerhub": "https://hub.docker.com/u/{}",
    "devto": "https://dev.to/{}",
    "hashnode": "https://hashnode.com/@{}",
    "stackoverflow": "https://stackoverflow.com/users/{}",
    "keybase": "https://keybase.io/{}",
    # Social
    "twitter": "https://x.com/{}",
    "instagram": "https://www.instagram.com/{}/",
    "facebook": "https://www.facebook.com/{}",
    "linkedin": "https://www.linkedin.com/in/{}",
    "reddit": "https://www.reddit.com/user/{}",
    "tiktok": "https://www.tiktok.com/@{}",
    "youtube": "https://www.youtube.com/@{}",
    "pinterest": "https://www.pinterest.com/{}/",
    "tumblr": "https://{}.tumblr.com",
    "threads": "https://www.threads.net/@{}",
    "mastodon_social": "https://mastodon.social/@{}",
    "bluesky": "https://bsky.app/profile/{}.bsky.social",
    "snapchat": "https://www.snapchat.com/add/{}",
    "vk": "https://vk.com/{}",
    "okru": "https://ok.ru/{}",
    # Creative / media
    "behance": "https://www.behance.net/{}",
    "dribbble": "https://dribbble.com/{}",
    "flickr": "https://www.flickr.com/people/{}",
    "vimeo": "https://vimeo.com/{}",
    "soundcloud": "https://soundcloud.com/{}",
    "spotify": "https://open.spotify.com/user/{}",
    "bandcamp": "https://bandcamp.com/{}",
    "lastfm": "https://www.last.fm/user/{}",
    "deviantart": "https://www.deviantart.com/{}",
    "artstation": "https://www.artstation.com/{}",
    "medium": "https://medium.com/@{}",
    "substack": "https://substack.com/@{}",
    "aboutme": "https://about.me/{}",
    "linktree": "https://linktr.ee/{}",
    "carrd": "https://{}.carrd.co",
    # Gaming
    "steam": "https://steamcommunity.com/id/{}",
    "xbox": "https://xboxgamertag.com/search/{}",
    "playstation": "https://psnprofiles.com/{}",
    "twitch": "https://www.twitch.tv/{}",
    "roblox": "https://www.roblox.com/users/profile?username={}",
    "minecraft": "https://namemc.com/profile/{}",
    "chess": "https://www.chess.com/member/{}",
    "lichess": "https://lichess.org/@/{}",
    # Community / forums
    "hackernews": "https://news.ycombinator.com/user?id={}",
    "producthunt": "https://www.producthunt.com/@{}",
    "telegram": "https://t.me/{}",
    "discord_invite": "https://discord.com/users/{}",
    "slack_community": "https://{}.slack.com",
    "quora": "https://www.quora.com/profile/{}",
    "wikipedia": "https://en.wikipedia.org/wiki/User:{}",
    "imgur": "https://imgur.com/user/{}",
    "giphy": "https://giphy.com/{}",
    "patreon": "https://www.patreon.com/{}",
    "ko_fi": "https://ko-fi.com/{}",
    "buymeacoffee": "https://www.buymeacoffee.com/{}",
    "cashapp": "https://cash.app/${}",
    "venmo": "https://venmo.com/{}",
    # Professional / misc
    "angel": "https://angel.co/u/{}",
    "crunchbase": "https://www.crunchbase.com/person/{}",
    "researchgate": "https://www.researchgate.net/profile/{}",
    "orcid": "https://orcid.org/{}",
    "academia": "https://independent.academia.edu/{}",
    "gravatar": "https://en.gravatar.com/{}",
    "wordpress": "https://{}.wordpress.com",
    "blogger": "https://www.blogger.com/profile/{}",
    "ghost": "https://{}.ghost.io",
    "notion": "https://www.notion.so/{}",
    "trello": "https://trello.com/{}",
    "fandom": "https://www.fandom.com/u/{}",
    "imgur_user": "https://imgur.com/user/{}",
    "spotify_artist": "https://open.spotify.com/artist/{}",
    "apple_music": "https://music.apple.com/profile/{}",
    "goodreads": "https://www.goodreads.com/{}",
    "letterboxd": "https://letterboxd.com/{}",
    "myanimelist": "https://myanimelist.net/profile/{}",
    "duolingo": "https://www.duolingo.com/profile/{}",
    "strava": "https://www.strava.com/athletes/{}",
    "fitbit": "https://www.fitbit.com/user/{}",
    "vsco": "https://vsco.co/{}",
    "onlyfans": "https://onlyfans.com/{}",
    "pornhub": "https://www.pornhub.com/users/{}",
    "reddit_old": "https://old.reddit.com/user/{}",
    "gitlab_com": "https://gitlab.com/{}",
    "gitee": "https://gitee.com/{}",
    "sourceforge_user": "https://sourceforge.net/u/{}/profile",
    "launchpad": "https://launchpad.net/~{}",
    "askubuntu": "https://askubuntu.com/users/{}",
    "superuser": "https://superuser.com/users/{}",
    "serverfault": "https://serverfault.com/users/{}",
    "slashdot": "https://slashdot.org/~{}",
    "digg": "https://digg.com/@{}",
    "mix": "https://mix.com/{}",
    "flipboard": "https://flipboard.com/@{}",
    "weebly": "https://{}.weebly.com",
    "wix": "https://{}.wixsite.com/website",
}


class SocialIntel:
    """Social media intelligence gathering"""

    def __init__(self):
        self.platforms = dict(PLATFORMS)
        self.headers = dict(DEFAULT_HEADERS)
        self._not_found_hints = (
            "not found", "doesn't exist", "does not exist", "page not found",
            "sorry, this page", "user not found", "couldn't find", "404",
            "no such user", "account suspended",
        )

    def search_username(self, username: str, threads: int = 40) -> Dict:
        username = (username or "").strip()
        if not re.match(r"^[\w.\-]{1,39}$", username):
            return {}
        results: Dict = {}

        def check(platform: str, template: str) -> tuple:
            url = template.format(quote(username, safe=""))
            try:
                r = requests.get(url, headers=self.headers, timeout=6, allow_redirects=True)
                exists = self._decide_exists(r)
                return platform, {
                    "url": url,
                    "exists": exists,
                    "status_code": r.status_code,
                    "final_url": r.url,
                }
            except requests.RequestException:
                return platform, {"url": url, "exists": None, "error": "Connection failed"}

        with ThreadPoolExecutor(max_workers=threads) as pool:
            futs = [pool.submit(check, p, t) for p, t in self.platforms.items()]
            for fut in as_completed(futs):
                platform, data = fut.result()
                results[platform] = data
        return results

    def _decide_exists(self, response: requests.Response) -> Optional[bool]:
        if response.status_code == 404:
            return False
        if response.status_code in (401, 403):
            return None  # unknown / blocked
        if response.status_code >= 400:
            return False
        text = (response.text or "")[:8000].lower()
        if any(h in text for h in self._not_found_hints) and response.status_code == 200:
            # soft 404
            title = ""
            try:
                soup = BeautifulSoup(response.text, "html.parser")
                title = (soup.title.string or "").lower() if soup.title else ""
            except Exception:
                pass
            if "not found" in title or "404" in title:
                return False
        return response.status_code in (200, 301, 302, 303, 307, 308)

    def discover_emails(self, username: str) -> List[str]:
        """Guess + harvest emails tied to username from public sources."""
        emails = set()
        common = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "protonmail.com", "icloud.com"]
        for d in common:
            emails.add(f"{username}@{d}")
        # GitHub noreply + public profile email
        try:
            r = requests.get(f"https://api.github.com/users/{quote(username)}", headers=self.headers, timeout=8)
            if r.status_code == 200:
                data = r.json()
                if data.get("email"):
                    emails.add(data["email"])
                emails.add(f"{data.get('id', '')}+{username}@users.noreply.github.com")
            # events
            er = requests.get(
                f"https://api.github.com/users/{quote(username)}/events/public",
                headers=self.headers,
                timeout=10,
            )
            if er.status_code == 200:
                for ev in er.json()[:30]:
                    commits = (ev.get("payload") or {}).get("commits") or []
                    for c in commits:
                        em = (c.get("author") or {}).get("email")
                        if em and "noreply" not in em:
                            emails.add(em)
        except requests.RequestException:
            pass
        # gravatar existence (hash of email guesses) — skip network heavy
        return sorted(e for e in emails if "@" in e)

    def find_associated_accounts(self, username: str) -> List[Dict]:
        """Correlate found profiles + GitHub orgs / blog links."""
        associated: List[Dict] = []
        profiles = self.search_username(username)
        found = [{"platform": p, "url": i["url"]} for p, i in profiles.items() if i.get("exists") is True]
        if found:
            associated.append({"source": "platform_matrix", "accounts": found})
        try:
            r = requests.get(f"https://api.github.com/users/{quote(username)}", headers=self.headers, timeout=8)
            if r.status_code == 200:
                data = r.json()
                extra = []
                for key in ("blog", "twitter_username", "html_url"):
                    val = data.get(key)
                    if val:
                        extra.append({"platform": key, "url": val if str(val).startswith("http") else f"https://{val}"})
                orgs = requests.get(
                    f"https://api.github.com/users/{quote(username)}/orgs",
                    headers=self.headers,
                    timeout=8,
                )
                if orgs.status_code == 200:
                    for o in orgs.json()[:20]:
                        extra.append({"platform": "github_org", "url": o.get("html_url"), "name": o.get("login")})
                if extra:
                    associated.append({"source": "github_profile", "accounts": extra})
        except requests.RequestException:
            pass
        return associated

    def get_profile_info(self, platform: str, username: str) -> Dict:
        url = self.platforms.get(platform, "").format(quote(username, safe=""))
        info: Dict = {"platform": platform, "username": username, "profile_url": url, "info": {}}
        if not url:
            return info
        try:
            r = requests.get(url, headers=self.headers, timeout=8)
            info["info"]["status_code"] = r.status_code
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "html.parser")
                title = soup.title.string.strip() if soup.title and soup.title.string else ""
                desc = ""
                tag = soup.find("meta", attrs={"name": "description"}) or soup.find(
                    "meta", attrs={"property": "og:description"}
                )
                if tag:
                    desc = tag.get("content") or ""
                info["info"]["title"] = title[:200]
                info["info"]["description"] = desc[:500]
        except requests.RequestException as exc:
            info["info"]["error"] = str(exc)
        if platform == "github":
            try:
                r = requests.get(f"https://api.github.com/users/{quote(username)}", headers=self.headers, timeout=8)
                if r.status_code == 200:
                    info["info"]["api"] = r.json()
            except requests.RequestException:
                pass
        return info

    @staticmethod
    def gravatar_url(email: str) -> str:
        h = hashlib.md5(email.strip().lower().encode()).hexdigest()
        return f"https://www.gravatar.com/avatar/{h}?d=404"
