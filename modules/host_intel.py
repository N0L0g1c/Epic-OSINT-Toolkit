"""Optional internet-wide host intel (Shodan / Censys) — API key gated."""

from __future__ import annotations

from typing import Any, Dict, Optional

import requests

from modules.net_util import DEFAULT_HEADERS, is_safe_host, normalize_ip


class HostIntel:
    """Shodan + Censys lookups when API keys are configured."""

    def __init__(self, shodan_key: Optional[str] = None, censys_id: Optional[str] = None,
                 censys_secret: Optional[str] = None):
        self.shodan_key = (shodan_key or "").strip() or None
        self.censys_id = (censys_id or "").strip() or None
        self.censys_secret = (censys_secret or "").strip() or None
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)

    def analyze(self, target: str) -> Dict[str, Any]:
        ip = normalize_ip(target)
        host = target if not ip else ip
        if not is_safe_host(host if not ip else ip):
            return {"error": "Blocked or invalid target", "target": target}

        out: Dict[str, Any] = {"target": target, "ip": ip or host, "shodan": None, "censys": None}
        if self.shodan_key:
            out["shodan"] = self._shodan(ip or host)
        else:
            out["shodan"] = {"skipped": True, "reason": "No SHODAN_API_KEY / --shodan-key"}
        if self.censys_id and self.censys_secret:
            out["censys"] = self._censys(ip or host)
        else:
            out["censys"] = {"skipped": True, "reason": "No Censys credentials"}
        return out

    def _shodan(self, ip: str) -> Dict[str, Any]:
        try:
            r = self.session.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": self.shodan_key},
                timeout=20,
            )
            if r.status_code != 200:
                return {"error": f"HTTP {r.status_code}", "body": r.text[:300]}
            data = r.json()
            return {
                "org": data.get("org"),
                "isp": data.get("isp"),
                "os": data.get("os"),
                "ports": data.get("ports"),
                "hostnames": data.get("hostnames"),
                "vulns": list(data.get("vulns") or [])[:20],
                "tags": data.get("tags"),
                "data_sample": [
                    {"port": d.get("port"), "product": d.get("product"), "banner": (d.get("data") or "")[:200]}
                    for d in (data.get("data") or [])[:10]
                ],
            }
        except (requests.RequestException, ValueError) as exc:
            return {"error": str(exc)}

    def _censys(self, ip: str) -> Dict[str, Any]:
        try:
            r = self.session.get(
                f"https://search.censys.io/api/v2/hosts/{ip}",
                auth=(self.censys_id, self.censys_secret),
                timeout=20,
            )
            if r.status_code != 200:
                return {"error": f"HTTP {r.status_code}", "body": r.text[:300]}
            data = (r.json() or {}).get("result") or {}
            services = data.get("services") or []
            return {
                "autonomous_system": data.get("autonomous_system"),
                "location": data.get("location"),
                "services": [
                    {"port": s.get("port"), "service": s.get("service_name"), "software": s.get("software")}
                    for s in services[:20]
                ],
            }
        except (requests.RequestException, ValueError) as exc:
            return {"error": str(exc)}
