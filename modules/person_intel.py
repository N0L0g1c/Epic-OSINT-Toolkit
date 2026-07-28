"""Person / full-name OSINT — parse name, username seeds, public search pivots."""

from __future__ import annotations

import re
from typing import Any, Dict, List
from urllib.parse import quote, quote_plus

import requests

from modules.http_util import pace, rotate_headers

_NAME_RE = re.compile(r"^[\w\s.\-']{2,80}$", re.UNICODE)
_STOP = {"jr", "sr", "ii", "iii", "iv", "md", "phd", "dr", "mr", "mrs", "ms"}


class PersonIntel:
    """Build person-centric OSINT seeds and public people-search pivots."""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update(rotate_headers())

    def analyze(self, name: str) -> Dict[str, Any]:
        raw = " ".join((name or "").split()).strip()
        if not raw or not _NAME_RE.match(raw) or "@" in raw or "/" in raw:
            return {"error": "Invalid person name (use a full name, not email/URL)", "name": name}

        parts = self._parse(raw)
        seeds = self._username_seeds(parts)
        github = self._github_users(raw, limit=8)

        return {
            "name": raw,
            "parsed": parts,
            "username_seeds": seeds[:40],
            "email_seeds": self._email_localparts(parts)[:25],
            "github_users": github,
            "pivots": self._pivots(raw, parts),
            "note": "Pivots open public search pages — no scraping of people-search paywalls",
        }

    def _parse(self, name: str) -> Dict[str, Any]:
        tokens = [t for t in re.split(r"[\s.]+", name) if t]
        clean = [t for t in tokens if t.lower().strip(".") not in _STOP]
        first = clean[0] if clean else ""
        last = clean[-1] if len(clean) >= 2 else ""
        middle = clean[1:-1] if len(clean) > 2 else []
        return {
            "first": first,
            "middle": middle,
            "last": last,
            "tokens": clean,
        }

    def _username_seeds(self, parts: Dict[str, Any]) -> List[str]:
        first = (parts.get("first") or "").lower()
        last = (parts.get("last") or "").lower()
        if not first:
            return []
        f, l = re.sub(r"[^a-z0-9]", "", first), re.sub(r"[^a-z0-9]", "", last)
        if not f:
            return []
        seeds = {f}
        if l:
            seeds.update({
                f"{f}{l}",
                f"{f}.{l}",
                f"{f}_{l}",
                f"{f}-{l}",
                f"{f[0]}{l}",
                f"{f}{l[0]}",
                f"{l}{f}",
                f"{l}.{f}",
                f"{f[0]}.{l}",
                f"{f}.{l[0]}",
            })
        for m in parts.get("middle") or []:
            mi = re.sub(r"[^a-z0-9]", "", m.lower())
            if mi and l:
                seeds.add(f"{f}{mi[0]}{l}")
                seeds.add(f"{f}.{mi[0]}.{l}")
        return sorted(s for s in seeds if 2 <= len(s) <= 40)

    def _email_localparts(self, parts: Dict[str, Any]) -> List[str]:
        return self._username_seeds(parts)

    def _github_users(self, name: str, limit: int = 8) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        try:
            pace()
            r = self.session.get(
                "https://api.github.com/search/users",
                params={"q": f"{name} in:fullname", "per_page": limit},
                headers=rotate_headers({"Accept": "application/vnd.github+json"}),
                timeout=15,
            )
            if r.status_code != 200:
                return hits
            for u in (r.json().get("items") or [])[:limit]:
                hits.append({
                    "login": u.get("login"),
                    "url": u.get("html_url"),
                    "score": u.get("score"),
                })
        except (requests.RequestException, ValueError, TypeError):
            pass
        return hits

    @staticmethod
    def _pivots(full: str, parts: Dict[str, Any]) -> List[Dict[str, str]]:
        q = quote_plus(full)
        first = parts.get("first") or ""
        last = parts.get("last") or ""
        fl = quote_plus(f"{first} {last}".strip()) if last else q
        return [
            {"name": "Google", "url": f"https://www.google.com/search?q={q}"},
            {"name": "DuckDuckGo", "url": f"https://duckduckgo.com/?q={q}"},
            {"name": "Bing", "url": f"https://www.bing.com/search?q={q}"},
            {"name": "LinkedIn people", "url": f"https://www.linkedin.com/search/results/people/?keywords={fl}"},
            {"name": "LinkedIn google dork", "url": f"https://www.google.com/search?q=site%3Alinkedin.com%2Fin+{fl}"},
            {"name": "GitHub users", "url": f"https://github.com/search?q={quote(full)}+type%3Auser&type=users"},
            {"name": "Twitter/X", "url": f"https://x.com/search?q={q}&f=user"},
            {"name": "Facebook", "url": f"https://www.facebook.com/search/people/?q={q}"},
            {"name": "Spokeo", "url": f"https://www.spokeo.com/search?q={fl.replace('+', '+')}"},
            {"name": "TruePeopleSearch", "url": f"https://www.truepeoplesearch.com/results?name={fl}"},
            {"name": "FastPeopleSearch", "url": f"https://www.fastpeoplesearch.com/name/{quote(full.replace(' ', '-'))}"},
            {"name": "Whitepages", "url": f"https://www.whitepages.com/name/{quote(full.replace(' ', '-'))}"},
            {"name": "BeenVerified", "url": f"https://www.beenverified.com/people/{quote(full.replace(' ', '-').lower())}/"},
            {"name": "CourtListener", "url": f"https://www.courtlistener.com/?q={q}&type=r&order_by=score+desc"},
        ]
