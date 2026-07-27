"""JavaScript / page secrets and endpoint miner."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Set
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from modules.http_util import pace, rotate_headers
from modules.net_util import is_safe_url

_PATTERNS = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "google_api": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "slack_token": re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,48}"),
    "github_token": re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    "firebase": re.compile(r"https://[a-z0-9\-]+\.firebaseio\.com"),
    "s3_url": re.compile(r"https?://[a-z0-9.\-]+\.s3[.\-][a-z0-9.\-]*\.amazonaws\.com/[^\s\"']+"),
    "generic_secret": re.compile(
        r"(?i)(?:api[_-]?key|secret|token|password|auth)\s*[:=]\s*['\"][^'\"]{8,64}['\"]"
    ),
    "endpoint": re.compile(r"(?i)['\"](/api/v?[0-9]?/[A-Za-z0-9_\-./{}]+)['\"]"),
    "url_endpoint": re.compile(r"https?://[^\s\"'<>]{12,200}"),
}


class JSSecretsIntel:
    """Fetch page + linked JS and extract secrets / API paths."""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update(rotate_headers())

    def mine(self, url: str, max_scripts: int = 15) -> Dict[str, Any]:
        if not url.startswith("http"):
            url = f"https://{url}"
        if not is_safe_url(url):
            return {"error": "Blocked or invalid URL", "url": url}

        findings: Dict[str, Set[str]] = {k: set() for k in _PATTERNS}
        scripts_checked: List[str] = []
        pages = []

        try:
            pace()
            r = self.session.get(url, headers=rotate_headers(), timeout=15)
            pages.append(url)
            self._scan(r.text or "", findings)
            soup = BeautifulSoup(r.text or "", "html.parser")
            srcs = []
            for tag in soup.find_all("script", src=True):
                src = urljoin(url, tag["src"])
                if is_safe_url(src):
                    srcs.append(src)
            for src in srcs[:max_scripts]:
                try:
                    pace()
                    sr = self.session.get(src, headers=rotate_headers(), timeout=12)
                    scripts_checked.append(src)
                    if sr.status_code == 200:
                        self._scan(sr.text or "", findings)
                except requests.RequestException:
                    continue
        except requests.RequestException as exc:
            return {"error": str(exc), "url": url}

        host = urlparse(url).hostname or ""
        endpoints = sorted(findings["endpoint"])[:50]
        # keep same-site-ish URLs separately
        urls = [u for u in findings["url_endpoint"] if host and host in u][:40]

        return {
            "url": url,
            "scripts_checked": scripts_checked,
            "secrets": {k: sorted(v)[:20] for k, v in findings.items()
                        if k not in ("endpoint", "url_endpoint") and v},
            "api_paths": endpoints,
            "interesting_urls": urls,
            "counts": {
                "secrets": sum(len(v) for k, v in findings.items() if k not in ("endpoint", "url_endpoint")),
                "api_paths": len(endpoints),
                "scripts": len(scripts_checked),
            },
        }

    @staticmethod
    def _scan(text: str, findings: Dict[str, Set[str]]) -> None:
        for name, pat in _PATTERNS.items():
            for m in pat.findall(text):
                val = m if isinstance(m, str) else m[0] if m else ""
                if val and len(val) < 300:
                    findings[name].add(val)
