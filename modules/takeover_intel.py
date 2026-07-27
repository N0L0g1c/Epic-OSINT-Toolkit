"""Subdomain takeover fingerprint checks."""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

import requests

from modules.net_util import DEFAULT_HEADERS, is_safe_host

# service -> (cname needles, body fingerprints)
FINGERPRINTS: List[Tuple[str, Tuple[str, ...], Tuple[str, ...]]] = [
    ("GitHub Pages", ("github.io",), ("There isn't a GitHub Pages site here", "For root URLs (like http://example.com/)")),
    ("Heroku", ("herokuapp.com", "herokudns.com"), ("No such app", "no-such-app")),
    ("AWS/S3", ("s3.amazonaws.com", "s3-website"), ("NoSuchBucket", "The specified bucket does not exist")),
    ("Ghost", ("ghost.io",), ("The thing you were looking for is no longer here",)),
    ("Shopify", ("myshopify.com",), ("Sorry, this shop is currently unavailable")),
    ("Tumblr", ("tumblr.com", "domains.tumblr.com"), ("There's nothing here", "Whatever you were looking for")),
    ("WordPress.com", ("wordpress.com",), ("Do you want to register")),
    ("Pantheon", ("pantheonsite.io",), ("404 error unknown site")),
    ("Fastly", ("fastly.net",), ("Fastly error: unknown domain")),
    ("Azure", ("azurewebsites.net", "cloudapp.azure.com", "trafficmanager.net"),
     ("404 Web Site not found", "Error 404 - Web app not found")),
    ("Surge.sh", ("surge.sh",), ("project not found")),
    ("Bitbucket", ("bitbucket.io",), ("Repository not found")),
    ("Netlify", ("netlify.app", "netlify.com"), ("Not Found - Request ID")),
    ("Cargo", ("cargocollective.com",), ("404 Not Found")),
    ("Feedpress", ("feedpress.me",), ("The feed has not been found")),
    ("Readme.io", ("readme.io",), ("Project doesnt exist", "project not found")),
]


class TakeoverIntel:
    """Check hosts for dangling DNS / takeover fingerprints."""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)

    def check(self, hosts: List[str], threads: int = 15) -> Dict[str, Any]:
        cleaned = []
        for h in hosts:
            h = (h or "").strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0]
            if h and is_safe_host(h) and h not in cleaned:
                cleaned.append(h)
        if not cleaned:
            return {"error": "No valid hosts", "hosts": hosts}

        findings: List[Dict[str, Any]] = []

        def one(host: str) -> Optional[Dict[str, Any]]:
            cname = self._cname(host)
            nx = self._is_nxdomain(host)
            body = ""
            status = None
            try:
                r = self.session.get(f"https://{host}", timeout=8, allow_redirects=True)
                status = r.status_code
                body = (r.text or "")[:5000]
            except requests.RequestException:
                try:
                    r = self.session.get(f"http://{host}", timeout=8, allow_redirects=True)
                    status = r.status_code
                    body = (r.text or "")[:5000]
                except requests.RequestException:
                    pass

            matched = []
            cname_l = (cname or "").lower()
            body_l = body.lower()
            for service, needles, fps in FINGERPRINTS:
                cname_hit = any(n.strip() in cname_l for n in needles if n.strip())
                body_hit = any(fp.lower() in body_l for fp in fps)
                if cname_hit or body_hit:
                    matched.append({
                        "service": service,
                        "cname_match": cname_hit,
                        "fingerprint_match": body_hit,
                    })
            if matched or nx:
                return {
                    "host": host,
                    "cname": cname,
                    "nxdomain": nx,
                    "http_status": status,
                    "candidates": matched,
                    "risk": "high" if any(m["fingerprint_match"] for m in matched) else ("medium" if matched or nx else "low"),
                }
            return None

        with ThreadPoolExecutor(max_workers=threads) as pool:
            futs = {pool.submit(one, h): h for h in cleaned[:80]}
            for fut in as_completed(futs):
                res = fut.result()
                if res:
                    findings.append(res)

        findings.sort(key=lambda x: {"high": 0, "medium": 1, "low": 2}.get(x.get("risk"), 9))
        return {
            "checked": len(cleaned[:80]),
            "suspicious": len(findings),
            "findings": findings,
        }

    def check_domain(self, domain: str, subdomains: Optional[List[str]] = None) -> Dict[str, Any]:
        hosts = [domain]
        if subdomains:
            hosts.extend(subdomains[:50])
        result = self.check(hosts)
        result["domain"] = domain
        return result

    @staticmethod
    def _cname(host: str) -> Optional[str]:
        try:
            import dns.resolver
            answers = dns.resolver.resolve(host, "CNAME")
            return str(answers[0].target).rstrip(".")
        except Exception:
            return None

    @staticmethod
    def _is_nxdomain(host: str) -> bool:
        try:
            socket.getaddrinfo(host, None)
            return False
        except socket.gaierror as exc:
            return "Name or service not known" in str(exc) or getattr(exc, "errno", None) in (8, -2, -5)
        except OSError:
            return False
