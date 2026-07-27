"""Paste / code leak surface search — GitHub, Gists, public paste pivots."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import requests

from modules.net_util import DEFAULT_HEADERS

_SECRET_RE = re.compile(
    r"(?i)(password|passwd|secret|api[_-]?key|token|authorization|aws_access|private[_-]?key)\s*[=:]\s*\S+"
)


class PasteIntel:
    """Hunt for leaked credentials / pastes mentioning a target."""

    def __init__(self, github_token: Optional[str] = None):
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)
        if github_token:
            self.session.headers["Authorization"] = f"Bearer {github_token}"

    def hunt(self, query: str, limit: int = 30) -> Dict[str, Any]:
        q = (query or "").strip()
        if not q or len(q) > 200 or ".." in q:
            return {"error": "Invalid query", "query": query}

        results: Dict[str, Any] = {
            "query": q,
            "github_code": self._github_code(q, limit),
            "github_repos": self._github_repos(q, min(10, limit)),
            "dorks": self._dorks(q),
            "secret_snippets": [],
        }
        # Scan snippets for secret-like lines
        for item in results["github_code"].get("items") or []:
            text = item.get("text_matches") or []
            for tm in text:
                frag = tm.get("fragment") or ""
                if _SECRET_RE.search(frag):
                    results["secret_snippets"].append({
                        "repo": item.get("repo"),
                        "path": item.get("path"),
                        "url": item.get("url"),
                        "fragment": frag[:300],
                    })
        return results

    def _github_code(self, q: str, limit: int) -> Dict[str, Any]:
        try:
            r = self.session.get(
                "https://api.github.com/search/code",
                params={"q": f"{q} in:file", "per_page": min(limit, 30)},
                headers={**self.session.headers, "Accept": "application/vnd.github.text-match+json"},
                timeout=20,
            )
            if r.status_code == 200:
                data = r.json()
                items = []
                for i in (data.get("items") or [])[:limit]:
                    items.append({
                        "repo": (i.get("repository") or {}).get("full_name"),
                        "path": i.get("path"),
                        "url": i.get("html_url"),
                        "text_matches": i.get("text_matches") or [],
                    })
                return {"total": data.get("total_count", 0), "items": items}
            return {"total": 0, "items": [], "status": r.status_code, "note": r.text[:200]}
        except requests.RequestException as exc:
            return {"total": 0, "items": [], "error": str(exc)}

    def _github_repos(self, q: str, limit: int) -> Dict[str, Any]:
        try:
            r = self.session.get(
                "https://api.github.com/search/repositories",
                params={"q": q, "per_page": limit, "sort": "updated"},
                timeout=15,
            )
            if r.status_code == 200:
                data = r.json()
                return {
                    "total": data.get("total_count", 0),
                    "items": [
                        {"name": i.get("full_name"), "url": i.get("html_url"), "desc": i.get("description")}
                        for i in (data.get("items") or [])[:limit]
                    ],
                }
            return {"total": 0, "items": [], "status": r.status_code}
        except requests.RequestException as exc:
            return {"total": 0, "items": [], "error": str(exc)}

    @staticmethod
    def _dorks(q: str) -> List[Dict[str, str]]:
        enc = quote(q)
        return [
            {"name": "Pastebin", "url": f"https://www.google.com/search?q=site%3Apastebin.com+{enc}"},
            {"name": "Ghostbin/others", "url": f"https://www.google.com/search?q=site%3Aghostbin.com+OR+site%3Adpaste.com+{enc}"},
            {"name": "GitHub (web)", "url": f"https://github.com/search?q={enc}&type=code"},
            {"name": "GitLab", "url": f"https://gitlab.com/search?search={enc}"},
            {"name": "DuckDuckGo pastes", "url": f"https://duckduckgo.com/?q={enc}+(pastebin+OR+ghostbin+OR+%22api_key%22)"},
        ]
