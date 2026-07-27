"""Search-engine dork pack generator for OSINT pivots."""

from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import quote_plus


class DorkIntel:
    """Build categorized Google/DDG/Bing dorks for a target."""

    def generate(self, target: str, kind: str = "auto") -> Dict[str, Any]:
        t = (target or "").strip()
        if not t or len(t) > 200 or ".." in t:
            return {"error": "Invalid target", "target": target}

        kind = kind if kind != "auto" else self._guess(t)
        packs = {
            "domain": self._domain_dorks,
            "email": self._email_dorks,
            "username": self._username_dorks,
            "ip": self._ip_dorks,
            "company": self._company_dorks,
            "phone": self._phone_dorks,
            "wallet": self._wallet_dorks,
        }
        builder = packs.get(kind, self._domain_dorks)
        categories = builder(t)
        flat: List[Dict[str, str]] = []
        for cat, queries in categories.items():
            for q in queries:
                flat.append({
                    "category": cat,
                    "query": q,
                    "google": f"https://www.google.com/search?q={quote_plus(q)}",
                    "duckduckgo": f"https://duckduckgo.com/?q={quote_plus(q)}",
                    "bing": f"https://www.bing.com/search?q={quote_plus(q)}",
                })
        return {
            "target": t,
            "kind": kind,
            "count": len(flat),
            "categories": {k: len(v) for k, v in categories.items()},
            "dorks": flat,
        }

    @staticmethod
    def _guess(t: str) -> str:
        if "@" in t:
            return "email"
        if t.endswith(".eth") or t.startswith("0x") or t.startswith(("bc1", "1", "3", "T")) and len(t) >= 26:
            # Heuristic — correlate.detect is authoritative for CLI auto
            if t.endswith(".eth") or (t.startswith("0x") and len(t) in (42, 66)):
                return "wallet"
            if t.startswith(("bc1", "1", "3")) and 26 <= len(t) <= 90:
                return "wallet"
            if t.startswith("T") and len(t) == 34:
                return "wallet"
        if t.replace(".", "").isdigit() or ":" in t:
            return "ip"
        if t.startswith("+") or (t.isdigit() and len(t) >= 8):
            return "phone"
        if " " in t:
            return "company"
        if "." in t and not t.startswith("."):
            return "domain"
        return "username"

    def _domain_dorks(self, d: str) -> Dict[str, List[str]]:
        return {
            "files": [
                f'site:{d} ext:pdf OR ext:doc OR ext:docx OR ext:xls OR ext:xlsx',
                f'site:{d} ext:sql OR ext:bak OR ext:zip OR ext:env OR ext:log',
                f'site:{d} filetype:pdf "confidential" OR "internal"',
            ],
            "login_admin": [
                f'site:{d} inurl:admin OR inurl:login OR inurl:signin',
                f'site:{d} intitle:"index of"',
                f'site:{d} inurl:wp-admin OR inurl:phpmyadmin',
            ],
            "secrets": [
                f'site:{d} "api_key" OR "apikey" OR "secret_key"',
                f'site:{d} "password" OR "passwd" filetype:txt',
                f'site:{d} "aws_access_key_id" OR "BEGIN RSA PRIVATE KEY"',
            ],
            "exposed": [
                f'site:{d} ext:json "token"',
                f'site:pastebin.com | site:ghostbin.com "{d}"',
                f'site:github.com "{d}" password OR secret OR key',
            ],
            "subdomains": [
                f'site:*.{d} -www',
                f'inurl:{d} -site:{d}',
            ],
        }

    def _email_dorks(self, e: str) -> Dict[str, List[str]]:
        return {
            "presence": [
                f'"{e}"',
                f'"{e}" site:linkedin.com',
                f'"{e}" site:github.com OR site:gitlab.com',
            ],
            "leaks": [
                f'"{e}" password OR credentials OR breach',
                f'"{e}" site:pastebin.com OR site:ghostbin.com',
            ],
        }

    def _username_dorks(self, u: str) -> Dict[str, List[str]]:
        return {
            "profiles": [
                f'"{u}" site:twitter.com OR site:x.com OR site:instagram.com',
                f'"{u}" site:reddit.com OR site:github.com',
                f'inurl:"{u}" site:about.me OR site:linktr.ee',
            ],
            "mentions": [
                f'"{u}" email OR contact OR "@"',
                f'"{u}" resume OR CV OR portfolio',
            ],
        }

    def _ip_dorks(self, ip: str) -> Dict[str, List[str]]:
        return {
            "hosting": [
                f'"{ip}"',
                f'ip:{ip}',
                f'"{ip}" site:shodan.io OR site:censys.io',
            ],
        }

    def _company_dorks(self, c: str) -> Dict[str, List[str]]:
        return {
            "people": [
                f'"{c}" site:linkedin.com/in',
                f'"{c}" email OR "@" filetype:pdf',
            ],
            "docs": [
                f'"{c}" confidential OR "internal use" filetype:pdf',
                f'"{c}" "org chart" OR employees',
            ],
        }

    def _phone_dorks(self, p: str) -> Dict[str, List[str]]:
        bare = p.lstrip("+")
        return {
            "presence": [
                f'"{p}" OR "{bare}"',
                f'"{p}" name OR address OR email',
            ],
        }

    def _wallet_dorks(self, w: str) -> Dict[str, List[str]]:
        return {
            "presence": [
                f'"{w}"',
                f'"{w}" wallet OR address OR crypto OR bitcoin OR ethereum',
                f'"{w}" site:twitter.com OR site:x.com OR site:reddit.com',
            ],
            "leaks": [
                f'"{w}" site:pastebin.com OR site:ghostbin.com OR site:gist.github.com',
                f'"{w}" site:github.com',
                f'"{w}" private key OR seed OR mnemonic OR "begins with"',
            ],
            "scam_abuse": [
                f'"{w}" scam OR phishing OR hack OR stolen OR ransomware',
                f'"{w}" site:chainabuse.com OR site:bitcoinabuse.com',
                f'"{w}" OFAC OR sanctions OR tumbler OR mixer',
            ],
            "attribution": [
                f'"{w}" exchange OR binance OR coinbase OR kraken OR deposit',
                f'"{w}" ENS OR "vitalik" OR opensea OR nft',
            ],
        }
