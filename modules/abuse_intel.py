"""IP/domain abuse & reputation via DNSBLs (no API key)."""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List

from modules.net_util import is_safe_host, normalize_ip

# Common DNS-based blocklists
_DNSBLS = (
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "b.barracudacentral.org",
    "dnsbl.sorbs.net",
    "cbl.abuseat.org",
)


class AbuseIntel:
    """Check IP reputation via public DNSBLs."""

    def check(self, target: str) -> Dict[str, Any]:
        ip = normalize_ip(target)
        if not ip:
            if not is_safe_host(target):
                return {"error": "Invalid target", "target": target}
            try:
                ip = socket.gethostbyname(target)
            except socket.gaierror:
                return {"error": "Could not resolve host", "target": target}
        if not is_safe_host(ip):
            return {"error": "Private/reserved IP blocked", "ip": ip}

        rev = ".".join(reversed(ip.split(".")))
        listings: List[Dict[str, Any]] = []

        def query(zone: str) -> Dict[str, Any]:
            qname = f"{rev}.{zone}"
            try:
                answers = socket.getaddrinfo(qname, None)
                codes = sorted({a[4][0] for a in answers})
                return {"zone": zone, "listed": True, "responses": codes}
            except socket.gaierror:
                return {"zone": zone, "listed": False}

        with ThreadPoolExecutor(max_workers=len(_DNSBLS)) as pool:
            futs = [pool.submit(query, z) for z in _DNSBLS]
            for fut in as_completed(futs):
                listings.append(fut.result())

        listed = [x for x in listings if x.get("listed")]
        return {
            "target": target,
            "ip": ip,
            "listed_count": len(listed),
            "listings": listings,
            "risk": "high" if len(listed) >= 2 else ("medium" if listed else "low"),
            "pivots": [
                f"https://www.abuseipdb.com/check/{ip}",
                f"https://virustotal.com/gui/ip-address/{ip}",
                f"https://www.spamhaus.org/query/ip/{ip}",
            ],
        }
