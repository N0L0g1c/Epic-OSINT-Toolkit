"""ASN / netblock intelligence via BGPView."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import requests

from modules.net_util import DEFAULT_HEADERS, is_safe_host, normalize_ip


class ASNIntel:
    """Expand IP → ASN → prefixes / related netblocks."""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)

    def analyze(self, target: str) -> Dict[str, Any]:
        ip = normalize_ip(target)
        asn_num: Optional[int] = None
        out: Dict[str, Any] = {"target": target, "ip": ip}

        if ip:
            if not is_safe_host(ip):
                return {"error": "Private/reserved IP blocked", "target": target}
            out.update(self._from_ip(ip))
            asn_num = out.get("asn")
        else:
            # treat as ASN number or AS123
            raw = target.strip().upper().removeprefix("AS")
            if raw.isdigit():
                asn_num = int(raw)
                out["asn"] = asn_num
            else:
                return {"error": "Provide IP or ASN (e.g. AS15169)", "target": target}

        if asn_num:
            out["prefixes"] = self._prefixes(asn_num)
            out["peers"] = self._peers(asn_num)
            out["upstreams"] = self._upstreams(asn_num)
        return out

    def _from_ip(self, ip: str) -> Dict[str, Any]:
        try:
            r = self.session.get(f"https://api.bgpview.io/ip/{ip}", timeout=15)
            if r.status_code != 200:
                return {"error": f"HTTP {r.status_code}"}
            data = (r.json() or {}).get("data") or {}
            prefixes = data.get("prefixes") or []
            first = prefixes[0] if prefixes else {}
            asn = (first.get("asn") or {}) if isinstance(first, dict) else {}
            return {
                "asn": asn.get("asn"),
                "asn_name": asn.get("name"),
                "asn_description": asn.get("description"),
                "asn_country": asn.get("country_code"),
                "prefix": first.get("prefix"),
                "rir": (data.get("rir_allocation") or {}).get("rir_name"),
                "related_prefixes": [p.get("prefix") for p in prefixes[:20] if p.get("prefix")],
            }
        except (requests.RequestException, ValueError, TypeError) as exc:
            return {"error": str(exc)}

    def _prefixes(self, asn: int) -> List[Dict[str, Any]]:
        try:
            r = self.session.get(f"https://api.bgpview.io/asn/{asn}/prefixes", timeout=20)
            if r.status_code != 200:
                return []
            data = (r.json() or {}).get("data") or {}
            ipv4 = data.get("ipv4_prefixes") or []
            return [
                {"prefix": p.get("prefix"), "name": p.get("name"), "country": p.get("country_code")}
                for p in ipv4[:40]
            ]
        except (requests.RequestException, ValueError):
            return []

    def _peers(self, asn: int) -> List[Dict[str, Any]]:
        try:
            r = self.session.get(f"https://api.bgpview.io/asn/{asn}/peers", timeout=15)
            if r.status_code != 200:
                return []
            data = (r.json() or {}).get("data") or {}
            peers = (data.get("ipv4_peers") or [])[:15]
            return [{"asn": p.get("asn"), "name": p.get("name"), "country": p.get("country_code")} for p in peers]
        except (requests.RequestException, ValueError):
            return []

    def _upstreams(self, asn: int) -> List[Dict[str, Any]]:
        try:
            r = self.session.get(f"https://api.bgpview.io/asn/{asn}/upstreams", timeout=15)
            if r.status_code != 200:
                return []
            data = (r.json() or {}).get("data") or {}
            ups = (data.get("ipv4_upstreams") or [])[:10]
            return [{"asn": p.get("asn"), "name": p.get("name")} for p in ups]
        except (requests.RequestException, ValueError):
            return []
