"""Favicon hash + Shodan pivot helpers."""

from __future__ import annotations

import base64
import struct
from typing import Any, Dict, Optional
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from modules.net_util import DEFAULT_HEADERS, is_safe_url


def _mmh3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 32-bit (Shodan favicon hash compatible)."""
    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    length = len(data)
    h = seed
    nblocks = length // 4
    for i in range(nblocks):
        k = struct.unpack_from("<I", data, i * 4)[0]
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
        h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
        h = (h * 5 + 0xE6546B64) & 0xFFFFFFFF
    tail_index = nblocks * 4
    k = 0
    tail_size = length & 3
    if tail_size >= 3:
        k ^= data[tail_index + 2] << 16
    if tail_size >= 2:
        k ^= data[tail_index + 1] << 8
    if tail_size >= 1:
        k ^= data[tail_index]
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
    h ^= length
    h ^= (h >> 16)
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= (h >> 13)
    h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    h ^= (h >> 16)
    # signed 32-bit like mmh3 python package / Shodan
    if h >= 0x80000000:
        h -= 0x100000000
    return h


class FaviconIntel:
    """Fetch site favicon and compute Shodan-style hash."""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)

    def analyze(self, target: str) -> Dict[str, Any]:
        url = target.strip()
        if not url.startswith("http"):
            url = f"https://{url}"
        if not is_safe_url(url):
            return {"error": "Blocked or invalid URL", "target": target}

        fav_url = self._discover_favicon(url)
        if not fav_url or not is_safe_url(fav_url):
            return {"target": target, "url": url, "error": "Favicon not found"}

        try:
            r = self.session.get(fav_url, timeout=12)
            if r.status_code != 200 or not r.content:
                return {"target": target, "favicon_url": fav_url, "error": f"HTTP {r.status_code}"}
            content = r.content
            b64 = base64.encodebytes(content)  # with newlines — Shodan style
            digest = _mmh3_32(b64)
            return {
                "target": target,
                "page_url": url,
                "favicon_url": fav_url,
                "content_type": r.headers.get("Content-Type"),
                "size": len(content),
                "mmh3": digest,
                "shodan_dork": f"http.favicon.hash:{digest}",
                "shodan_url": f"https://www.shodan.io/search?query=http.favicon.hash%3A{digest}",
                "censys_dork": f"services.http.response.favicons.md5_hash (use local md5) / favicon hash {digest}",
            }
        except requests.RequestException as exc:
            return {"error": str(exc), "favicon_url": fav_url}

    def _discover_favicon(self, page_url: str) -> Optional[str]:
        try:
            r = self.session.get(page_url, timeout=10)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "html.parser")
                for rel in ("icon", "shortcut icon", "apple-touch-icon"):
                    tag = soup.find("link", rel=lambda v: v and rel in " ".join(v).lower() if isinstance(v, list) else rel in str(v).lower())
                    if tag and tag.get("href"):
                        return urljoin(page_url, tag["href"])
        except requests.RequestException:
            pass
        parsed = urlparse(page_url)
        return f"{parsed.scheme}://{parsed.netloc}/favicon.ico"
