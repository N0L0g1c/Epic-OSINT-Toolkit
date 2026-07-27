"""Wayback Machine / historical URL intelligence (CDX API)."""

from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import quote

import requests

from modules.net_util import DEFAULT_HEADERS


class WaybackIntel:
    """Query Internet Archive CDX for historical URLs."""

    CDX = "https://web.archive.org/cdx/search/cdx"

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)

    def hunt(self, domain: str, limit: int = 200, interesting_only: bool = True) -> Dict[str, Any]:
        domain = domain.strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0]
        if not domain or ".." in domain:
            return {"error": "Invalid domain", "domain": domain}

        urls = self._cdx(f"*.{domain}/*", limit=limit)
        urls += self._cdx(f"{domain}/*", limit=max(50, limit // 2))

        # de-dupe preserving order
        seen = set()
        unique = []
        for u in urls:
            key = u.get("url", "")
            if key and key not in seen:
                seen.add(key)
                unique.append(u)

        interesting = [u for u in unique if self._is_interesting(u.get("url", ""))]
        return {
            "domain": domain,
            "total": len(unique),
            "interesting_count": len(interesting),
            "interesting": interesting[:limit],
            "urls": (interesting if interesting_only else unique)[:limit],
            "source": "web.archive.org/cdx",
        }

    def _cdx(self, url_pattern: str, limit: int = 200) -> List[Dict[str, str]]:
        out: List[Dict[str, str]] = []
        try:
            r = self.session.get(
                self.CDX,
                params={
                    "url": url_pattern,
                    "output": "json",
                    "fl": "original,timestamp,statuscode,mimetype",
                    "collapse": "urlkey",
                    "limit": str(limit),
                    "filter": "statuscode:200",
                },
                timeout=45,
            )
            if r.status_code != 200:
                return out
            rows = r.json()
            if not rows or len(rows) < 2:
                return out
            # first row is header
            for row in rows[1:]:
                if len(row) < 4:
                    continue
                out.append({
                    "url": row[0],
                    "timestamp": row[1],
                    "status": row[2],
                    "mime": row[3],
                    "wayback": f"https://web.archive.org/web/{row[1]}/{quote(row[0], safe=':/')}",
                })
        except (requests.RequestException, ValueError):
            pass
        return out

    @staticmethod
    def _is_interesting(url: str) -> bool:
        u = url.lower()
        keys = (
            "admin", "login", "signin", "api", "backup", "config", ".env", "secret",
            "token", "password", "wp-admin", "phpinfo", "debug", ".git", "swagger",
            "graphql", "actuator", "internal", "staging", "dev.", "test.",
            ".sql", ".bak", ".zip", ".tar", "dump", "credential",
        )
        return any(k in u for k in keys)
