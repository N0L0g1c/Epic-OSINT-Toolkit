"""Passive DNS / historical resolution hints (free sources)."""

from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import quote

import requests

from modules.http_util import pace, rotate_headers
from modules.net_util import is_safe_host, normalize_ip


class PassiveDNSIntel:
    """Best-effort passive DNS via HackerTarget + crt.sh co-occurrence."""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update(rotate_headers())

    def lookup(self, target: str) -> Dict[str, Any]:
        t = (target or "").strip()
        ip = normalize_ip(t)
        if ip:
            return self._by_ip(ip)
        host = t.removeprefix("http://").removeprefix("https://").split("/")[0]
        if not is_safe_host(host):
            return {"error": "Invalid host", "target": target}
        return self._by_host(host)

    def _by_host(self, host: str) -> Dict[str, Any]:
        history: List[Dict[str, str]] = []
        try:
            pace()
            r = self.session.get(
                f"https://api.hackertarget.com/dnslookup/?q={quote(host)}",
                timeout=15,
            )
            if r.status_code == 200 and "error" not in r.text.lower():
                for line in r.text.splitlines():
                    if ":" in line:
                        k, v = line.split(":", 1)
                        history.append({"record": k.strip(), "value": v.strip()})
        except requests.RequestException:
            pass
        # reverse via IP if A present
        ips = [h["value"] for h in history if h.get("record") == "A"]
        reverse = []
        for ip in ips[:3]:
            reverse.extend(self._ptr_hosts(ip))
        return {
            "target": host,
            "records": history,
            "related_hosts": reverse[:40],
            "source": "hackertarget+ptr",
        }

    def _by_ip(self, ip: str) -> Dict[str, Any]:
        hosts = self._ptr_hosts(ip)
        try:
            pace()
            r = self.session.get(
                f"https://api.hackertarget.com/reverseiplookup/?q={quote(ip)}",
                timeout=20,
            )
            if r.status_code == 200 and "error" not in r.text.lower():
                for line in r.text.splitlines():
                    h = line.strip().lower()
                    if h and "." in h:
                        hosts.append(h)
        except requests.RequestException:
            pass
        return {
            "target": ip,
            "hosts": sorted(set(hosts))[:100],
            "count": len(set(hosts)),
            "source": "hackertarget reverse + ptr",
        }

    def _ptr_hosts(self, ip: str) -> List[str]:
        import socket
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            return [host]
        except OSError:
            return []
