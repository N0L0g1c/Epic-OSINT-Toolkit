"""Related domain discovery — shared certs, same IP, CT SANs."""

from __future__ import annotations

import socket
import ssl
from typing import Any, Dict, List, Set
from urllib.parse import quote

import requests

from modules.http_util import pace, rotate_headers
from modules.net_util import is_safe_host


class RelatedDomainsIntel:
    """Find domains related to a target via CT + shared IP + SSL SANs."""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update(rotate_headers())

    def find(self, domain: str) -> Dict[str, Any]:
        domain = (domain or "").strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0]
        if not domain or not is_safe_host(domain):
            return {"error": "Invalid domain", "domain": domain}

        related: Set[str] = set()
        sources: Dict[str, List[str]] = {"ct_sans": [], "ssl_sans": [], "same_ip": []}

        # Certificate Transparency neighboring names
        try:
            pace()
            r = self.session.get(
                f"https://crt.sh/?q={quote('%.' + domain)}&output=json",
                timeout=25,
            )
            if r.status_code == 200:
                for entry in r.json()[:200]:
                    for name in str(entry.get("name_value") or "").split("\n"):
                        n = name.strip().lstrip("*.").lower()
                        if n and n != domain and "." in n:
                            # same registrable-ish or shares suffix
                            if n.endswith("." + domain) or domain.endswith("." + n.split(".", 1)[-1]):
                                related.add(n)
                                sources["ct_sans"].append(n)
                            elif self._same_sld(domain, n):
                                related.add(n)
                                sources["ct_sans"].append(n)
        except (requests.RequestException, ValueError):
            pass

        # Live SSL SAN
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=6) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    for typ, val in cert.get("subjectAltName") or []:
                        if typ == "DNS":
                            n = val.lstrip("*.").lower()
                            if n and n != domain:
                                related.add(n)
                                sources["ssl_sans"].append(n)
        except OSError:
            pass

        # Same IP reverse / crt for IP
        try:
            ip = socket.gethostbyname(domain)
            pace()
            r = self.session.get(f"https://crt.sh/?q={quote(ip)}&output=json", timeout=20)
            if r.status_code == 200:
                for entry in r.json()[:100]:
                    for name in str(entry.get("name_value") or "").split("\n"):
                        n = name.strip().lstrip("*.").lower()
                        if n and n != domain and "." in n and not n.startswith("."):
                            related.add(n)
                            sources["same_ip"].append(n)
            sources["ip"] = [ip]
        except (OSError, requests.RequestException, ValueError):
            pass

        # de-dupe source lists
        for k in list(sources.keys()):
            if isinstance(sources[k], list) and k != "ip":
                sources[k] = sorted(set(sources[k]))[:50]

        return {
            "domain": domain,
            "count": len(related),
            "related": sorted(related)[:100],
            "sources": sources,
        }

    @staticmethod
    def _same_sld(a: str, b: str) -> bool:
        def sld(d: str) -> str:
            parts = d.split(".")
            return ".".join(parts[-2:]) if len(parts) >= 2 else d
        return sld(a) == sld(b) and a != b
