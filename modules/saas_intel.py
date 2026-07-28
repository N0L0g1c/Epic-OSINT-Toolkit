"""SaaS / cloud tenant discovery for a domain (Azure AD, Workspace, etc.)."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import requests

from modules.http_util import pace, rotate_headers
from modules.net_util import is_safe_host

_DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,48}[a-z0-9]$")


class SaaSIntel:
    """Probe public SaaS/IdP endpoints that hint at tenant ownership."""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update(rotate_headers())

    def discover(self, domain: str) -> Dict[str, Any]:
        domain = self._normalize(domain)
        if not domain or not is_safe_host(domain):
            return {"error": "Invalid domain", "domain": domain}

        slug = domain.split(".")[0].lower()
        findings: List[Dict[str, Any]] = []

        # Sequential IdP checks (share domain context)
        for fn in (self._azure_realm, self._azure_oidc, self._google_workspace):
            try:
                hit = fn(domain)
                if hit:
                    findings.append(hit)
            except (requests.RequestException, ValueError, ET.ParseError):
                pass

        # Parallel slug-based SaaS probes (allowlisted hosts only)
        slug_checks = self._slug_probes(slug)
        with ThreadPoolExecutor(max_workers=8) as pool:
            futs = {pool.submit(self._probe_url, c): c for c in slug_checks}
            for fut in as_completed(futs):
                res = fut.result()
                if res:
                    findings.append(res)

        findings.sort(key=lambda x: (x.get("status") != "found", x.get("service", "")))
        return {
            "domain": domain,
            "slug": slug,
            "found": [f for f in findings if f.get("status") == "found"],
            "checked": findings,
            "count": sum(1 for f in findings if f.get("status") == "found"),
            "pivots": [
                {"name": "Azure AD login", "url": f"https://login.microsoftonline.com/{quote(domain)}"},
                {"name": "Google Workspace", "url": f"https://admin.google.com/"},
                {"name": "MX / SPF (manual)", "url": f"https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{quote(domain)}"},
            ],
        }

    def _normalize(self, raw: str) -> str:
        d = (raw or "").strip().lower()
        d = d.removeprefix("http://").removeprefix("https://").split("/")[0]
        d = d.split("@")[-1] if "@" in d else d
        if not _DOMAIN_RE.match(d):
            return ""
        return d

    def _azure_realm(self, domain: str) -> Optional[Dict[str, Any]]:
        pace()
        url = (
            "https://login.microsoftonline.com/getuserrealm.srf"
            f"?login=user@{quote(domain)}&xml=1"
        )
        r = self.session.get(url, headers=rotate_headers(), timeout=12)
        if r.status_code != 200 or not r.text:
            return {"service": "azure_ad_realm", "status": "unknown", "http": r.status_code}
        root = ET.fromstring(r.text)
        ns = ""
        name_tag = root.find(f".//{ns}NameSpaceType")
        fed = root.find(f".//{ns}FederationBrandName")
        auth = root.find(f".//{ns}AuthURL")
        nstype = (name_tag.text or "").strip() if name_tag is not None else ""
        brand = (fed.text or "").strip() if fed is not None else ""
        auth_url = (auth.text or "").strip() if auth is not None else ""
        # Federated / Managed = tenant exists; Unknown = often not claimed
        found = nstype.lower() in ("federated", "managed")
        return {
            "service": "azure_ad_realm",
            "status": "found" if found else "not_found",
            "namespace_type": nstype or None,
            "federation_brand": brand or None,
            "auth_url": auth_url or None,
            "http": r.status_code,
        }

    def _azure_oidc(self, domain: str) -> Optional[Dict[str, Any]]:
        pace()
        url = f"https://login.microsoftonline.com/{quote(domain)}/.well-known/openid-configuration"
        r = self.session.get(url, headers=rotate_headers({"Accept": "application/json"}), timeout=12)
        if r.status_code == 200:
            try:
                data = r.json()
            except ValueError:
                data = {}
            tid = None
            issuer = str(data.get("issuer") or "")
            m = re.search(r"([0-9a-fA-F\-]{36})", issuer)
            if m:
                tid = m.group(1)
            return {
                "service": "azure_ad_oidc",
                "status": "found",
                "tenant_id": tid,
                "issuer": issuer or None,
                "token_endpoint": data.get("token_endpoint"),
                "http": 200,
            }
        return {
            "service": "azure_ad_oidc",
            "status": "not_found" if r.status_code in (400, 404) else "unknown",
            "http": r.status_code,
        }

    def _google_workspace(self, domain: str) -> Optional[Dict[str, Any]]:
        pace()
        # Public endpoint: redirect / 200 often means Workspace or consumer routing
        url = f"https://www.google.com/a/{quote(domain)}/ServiceLogin"
        r = self.session.get(url, headers=rotate_headers(), timeout=12, allow_redirects=False)
        loc = r.headers.get("Location") or ""
        # 200 or redirect away from /a/domain often indicates managed domain presence
        found = r.status_code in (200, 302) and "AccountDomainNotFound" not in (r.text or "")
        if "not found" in (r.text or "").lower() or "does not exist" in (r.text or "").lower():
            found = False
        return {
            "service": "google_workspace",
            "status": "found" if found else "not_found",
            "http": r.status_code,
            "redirect": loc[:200] if loc else None,
            "note": "Heuristic — confirm via MX (ASPMX/google) or admin console",
        }

    def _slug_probes(self, slug: str) -> List[Dict[str, str]]:
        if not _SLUG_RE.match(slug):
            return []
        # Host templates are fixed allowlist — never user-controlled hosts
        return [
            {"service": "slack", "url": f"https://{slug}.slack.com"},
            {"service": "atlassian", "url": f"https://{slug}.atlassian.net"},
            {"service": "okta", "url": f"https://{slug}.okta.com"},
            {"service": "salesforce", "url": f"https://{slug}.my.salesforce.com"},
            {"service": "github_org", "url": f"https://github.com/{slug}"},
            {"service": "gitlab_group", "url": f"https://gitlab.com/{slug}"},
            {"service": "notion", "url": f"https://{slug}.notion.site"},
            {"service": "zendesk", "url": f"https://{slug}.zendesk.com"},
            {"service": "hubspot", "url": f"https://{slug}.hubspot.com"},
            {"service": "webex", "url": f"https://{slug}.webex.com"},
        ]

    def _probe_url(self, item: Dict[str, str]) -> Optional[Dict[str, Any]]:
        url = item["url"]
        host = url.split("/")[2] if "://" in url else ""
        if not is_safe_host(host):
            return None
        pace()
        try:
            r = self.session.head(url, headers=rotate_headers(), timeout=8, allow_redirects=True)
            status_code = r.status_code
            if status_code in (403, 405):
                r = self.session.get(url, headers=rotate_headers(), timeout=8, allow_redirects=True)
                status_code = r.status_code
        except requests.RequestException:
            return {
                "service": item["service"],
                "status": "unknown",
                "url": url,
            }

        # 200/401/403 often mean tenant/host exists; 404 = free/missing
        if status_code in (404, 410):
            st = "not_found"
        elif status_code in (200, 301, 302, 401, 403):
            st = "found"
        else:
            st = "unknown"
        return {
            "service": item["service"],
            "status": st,
            "url": url,
            "http": status_code,
        }
