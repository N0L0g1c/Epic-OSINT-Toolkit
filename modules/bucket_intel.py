"""Cloud storage bucket / blob enumeration (public exposure checks)."""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import requests

from modules.net_util import DEFAULT_HEADERS

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$")


class BucketIntel:
    """Probe common public cloud bucket naming patterns."""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)

    def hunt(self, name: str, threads: int = 20) -> Dict[str, Any]:
        base = self._normalize(name)
        if not base:
            return {"error": "Invalid name", "name": name}

        candidates = self._candidates(base)
        found: List[Dict[str, Any]] = []

        def check(item: Dict[str, str]) -> Optional[Dict[str, Any]]:
            url = item["url"]
            try:
                r = self.session.head(url, timeout=6, allow_redirects=True)
                # some buckets disallow HEAD — try GET lightly
                status = r.status_code
                if status in (403, 405):
                    r = self.session.get(url, timeout=6, stream=True)
                    status = r.status_code
                    r.close()
                if status in (200, 301, 302, 403):
                    return {
                        "provider": item["provider"],
                        "bucket": item["bucket"],
                        "url": url,
                        "status": status,
                        "public_list": status == 200,
                        "exists_hint": status in (200, 403),
                    }
            except requests.RequestException:
                return None
            return None

        with ThreadPoolExecutor(max_workers=threads) as pool:
            futs = [pool.submit(check, c) for c in candidates]
            for fut in as_completed(futs):
                res = fut.result()
                if res:
                    found.append(res)

        found.sort(key=lambda x: (not x.get("public_list"), x.get("provider"), x.get("bucket")))
        return {
            "name": base,
            "probed": len(candidates),
            "hits": len(found),
            "public": [f for f in found if f.get("public_list")],
            "exists": found,
        }

    def _normalize(self, name: str) -> str:
        n = (name or "").strip().lower()
        n = n.removeprefix("http://").removeprefix("https://").split("/")[0]
        n = n.replace("_", "-")
        # domain → slug
        if "." in n:
            n = n.split(".")[0] if n.count(".") >= 1 else n.replace(".", "-")
        n = re.sub(r"[^a-z0-9.\-]", "", n)
        if len(n) < 3 or len(n) > 63:
            return ""
        return n

    def _candidates(self, base: str) -> List[Dict[str, str]]:
        suffixes = (
            "", "-backup", "-backups", "-bak", "-dev", "-prod", "-staging",
            "-assets", "-static", "-media", "-uploads", "-data", "-logs",
            "-public", "-private", "-files", "-img", "-images", "-cdn",
        )
        names = []
        for s in suffixes:
            b = f"{base}{s}"
            if _NAME_RE.match(b) or (b.replace(".", "").isalnum() and 3 <= len(b) <= 63):
                names.append(b)
        out: List[Dict[str, str]] = []
        for b in names:
            out.append({
                "provider": "aws_s3",
                "bucket": b,
                "url": f"https://{b}.s3.amazonaws.com",
            })
            out.append({
                "provider": "aws_s3_path",
                "bucket": b,
                "url": f"https://s3.amazonaws.com/{quote(b)}",
            })
            out.append({
                "provider": "gcs",
                "bucket": b,
                "url": f"https://storage.googleapis.com/{quote(b)}",
            })
            out.append({
                "provider": "azure",
                "bucket": b,
                "url": f"https://{b}.blob.core.windows.net",
            })
            out.append({
                "provider": "digitalocean",
                "bucket": b,
                "url": f"https://{b}.digitaloceanspaces.com",
            })
        return out
