"""IP Intelligence — geo, ASN, reverse DNS, hosting/proxy hints (free sources)."""

from __future__ import annotations

import socket
from typing import Any, Dict, Optional

import requests

from modules.net_util import DEFAULT_HEADERS, is_safe_host, normalize_ip


class IPIntel:
    """Gather open-source intelligence about an IP address."""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)

    def analyze(self, target: str) -> Dict[str, Any]:
        ip = normalize_ip(target)
        if not ip:
            # resolve hostname first
            if not is_safe_host(target):
                return {"error": "Blocked or invalid host", "target": target}
            try:
                ip = socket.gethostbyname(target)
            except socket.gaierror:
                return {"error": "Could not resolve host", "target": target}

        if not is_safe_host(ip):
            return {"error": "Private/reserved IP blocked", "ip": ip, "target": target}

        result: Dict[str, Any] = {
            "target": target,
            "ip": ip,
            "reverse_dns": self._reverse_dns(ip),
            "geo": self._geo(ip),
            "asn": self._asn(ip),
            "risk": {},
        }
        result["risk"] = self._risk_hints(result)
        return result

    def _reverse_dns(self, ip: str) -> Optional[str]:
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            return host
        except (socket.herror, socket.gaierror, OSError):
            return None

    def _geo(self, ip: str) -> Dict[str, Any]:
        # ip-api.com — free, no key, HTTP only, rate-limited
        try:
            r = self.session.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,message,country,countryCode,region,regionName,"
                                  "city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query"},
                timeout=10,
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("status") == "success":
                    return {
                        "country": data.get("country"),
                        "country_code": data.get("countryCode"),
                        "region": data.get("regionName"),
                        "city": data.get("city"),
                        "lat": data.get("lat"),
                        "lon": data.get("lon"),
                        "timezone": data.get("timezone"),
                        "isp": data.get("isp"),
                        "org": data.get("org"),
                        "as": data.get("as"),
                        "asname": data.get("asname"),
                        "mobile": data.get("mobile"),
                        "proxy": data.get("proxy"),
                        "hosting": data.get("hosting"),
                        "source": "ip-api.com",
                    }
        except (requests.RequestException, ValueError):
            pass
        return {}

    def _asn(self, ip: str) -> Dict[str, Any]:
        try:
            r = self.session.get(f"https://api.bgpview.io/ip/{ip}", timeout=12)
            if r.status_code == 200:
                data = r.json().get("data") or {}
                prefixes = data.get("prefixes") or []
                first = prefixes[0] if prefixes else {}
                asn = (first.get("asn") or {}) if isinstance(first, dict) else {}
                return {
                    "asn": asn.get("asn"),
                    "name": asn.get("name"),
                    "description": asn.get("description"),
                    "country_code": asn.get("country_code"),
                    "prefix": first.get("prefix"),
                    "rir": data.get("rir_allocation", {}).get("rir_name") if isinstance(data.get("rir_allocation"), dict) else None,
                    "source": "bgpview.io",
                }
        except (requests.RequestException, ValueError, TypeError):
            pass
        return {}

    def _risk_hints(self, result: Dict[str, Any]) -> Dict[str, Any]:
        geo = result.get("geo") or {}
        hints = []
        score = 0
        if geo.get("proxy"):
            hints.append("Marked as proxy/VPN by geo source")
            score += 40
        if geo.get("hosting"):
            hints.append("Hosting/datacenter IP")
            score += 20
        if geo.get("mobile"):
            hints.append("Mobile carrier IP")
            score += 5
        rdns = (result.get("reverse_dns") or "").lower()
        for token in ("tor-exit", "vpn", "proxy", "cloud", "amazon", "google", "digitalocean", "linode"):
            if token in rdns:
                hints.append(f"rDNS suggests {token}")
                score += 10
        return {"score": min(score, 100), "hints": hints}
