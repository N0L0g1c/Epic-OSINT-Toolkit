"""Optional IOC enrichment — VirusTotal / AlienVault OTX (API keys)."""

from __future__ import annotations

from typing import Any, Dict, Optional
from urllib.parse import quote

import requests

from modules.http_util import rotate_headers
from modules.net_util import is_safe_host, normalize_ip


class IOCIntel:
    """Enrich IP/domain/hash/URL via optional threat-intel APIs."""

    def __init__(self, vt_key: Optional[str] = None, otx_key: Optional[str] = None):
        self.vt_key = (vt_key or "").strip() or None
        self.otx_key = (otx_key or "").strip() or None
        self.session = requests.Session()
        self.session.headers.update(rotate_headers())

    def enrich(self, indicator: str) -> Dict[str, Any]:
        ind = (indicator or "").strip()
        if not ind:
            return {"error": "Empty indicator"}
        kind = self._kind(ind)
        out: Dict[str, Any] = {"indicator": ind, "kind": kind, "virustotal": None, "otx": None}
        if self.vt_key:
            out["virustotal"] = self._vt(ind, kind)
        else:
            out["virustotal"] = {"skipped": True, "reason": "No --vt-key"}
        if self.otx_key:
            out["otx"] = self._otx(ind, kind)
        else:
            out["otx"] = {"skipped": True, "reason": "No --otx-key"}
        out["pivots"] = self._pivots(ind, kind)
        return out

    def _kind(self, ind: str) -> str:
        if normalize_ip(ind):
            return "ip"
        if ind.startswith(("http://", "https://")):
            return "url"
        if len(ind) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in ind):
            return "hash"
        if is_safe_host(ind.split("/")[0]):
            return "domain"
        return "unknown"

    def _vt(self, ind: str, kind: str) -> Dict[str, Any]:
        headers = rotate_headers({"x-apikey": self.vt_key})
        try:
            if kind == "ip":
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{ind}"
            elif kind == "domain":
                url = f"https://www.virustotal.com/api/v3/domains/{ind}"
            elif kind == "url":
                import base64
                uid = base64.urlsafe_b64encode(ind.encode()).decode().strip("=")
                url = f"https://www.virustotal.com/api/v3/urls/{uid}"
            elif kind == "hash":
                url = f"https://www.virustotal.com/api/v3/files/{ind}"
            else:
                return {"error": f"Unsupported kind {kind}"}
            r = self.session.get(url, headers=headers, timeout=20)
            if r.status_code != 200:
                return {"error": f"HTTP {r.status_code}", "body": r.text[:200]}
            data = (r.json() or {}).get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats") or data.get("last_analysis_stats") or {}
            return {
                "malicious": stats.get("malicious"),
                "suspicious": stats.get("suspicious"),
                "harmless": stats.get("harmless"),
                "reputation": data.get("reputation"),
                "tags": (data.get("tags") or [])[:20],
            }
        except (requests.RequestException, ValueError) as exc:
            return {"error": str(exc)}

    def _otx(self, ind: str, kind: str) -> Dict[str, Any]:
        headers = rotate_headers({"X-OTX-API-KEY": self.otx_key})
        section = {"ip": "IPv4", "domain": "domain", "url": "url", "hash": "file"}.get(kind)
        if not section:
            return {"error": f"Unsupported kind {kind}"}
        try:
            r = self.session.get(
                f"https://otx.alienvault.com/api/v1/indicators/{section}/{quote(ind, safe='')}/general",
                headers=headers,
                timeout=20,
            )
            if r.status_code != 200:
                return {"error": f"HTTP {r.status_code}", "body": r.text[:200]}
            data = r.json() or {}
            return {
                "pulse_count": (data.get("pulse_info") or {}).get("count"),
                "reputation": data.get("reputation"),
                "validation": data.get("validation"),
                "sections": data.get("sections"),
            }
        except (requests.RequestException, ValueError) as exc:
            return {"error": str(exc)}

    @staticmethod
    def _pivots(ind: str, kind: str) -> list:
        q = quote(ind, safe="")
        return [
            {"name": "VirusTotal", "url": f"https://www.virustotal.com/gui/search/{q}"},
            {"name": "OTX", "url": f"https://otx.alienvault.com/indicator/{kind}/{q}"},
            {"name": "URLScan", "url": f"https://urlscan.io/search/#{q}"},
        ]
