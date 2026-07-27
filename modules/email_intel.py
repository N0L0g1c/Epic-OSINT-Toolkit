"""Email Intelligence Module - Email discovery and verification"""

from __future__ import annotations

import re
import smtplib
import socket
from typing import Dict, List, Optional
from urllib.parse import quote

import requests

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

from modules.net_util import DEFAULT_HEADERS, is_safe_host, is_safe_url


class EmailIntel:
    """Email intelligence gathering"""

    def __init__(self, github_token: Optional[str] = None):
        self.headers = dict(DEFAULT_HEADERS)
        if github_token:
            self.headers["Authorization"] = f"Bearer {github_token}"
        self.common_patterns = [
            "admin", "administrator", "contact", "info", "support", "help",
            "sales", "marketing", "business", "office", "team", "service",
            "webmaster", "postmaster", "hostmaster", "abuse", "security",
            "noreply", "no-reply", "donotreply", "mail", "email", "hr", "jobs",
        ]

    def discover(self, domain: str) -> List[str]:
        domain = domain.strip().lower()
        if not domain or not is_safe_host(domain.split(":")[0]):
            return []
        emails = set()
        for pattern in self.common_patterns:
            emails.add(f"{pattern}@{domain}")
        for fn in (self._search_emails, self._extract_from_whois, self._scrape_website, self._search_github):
            try:
                emails.update(fn(domain))
            except Exception:
                pass
        # keep only same-domain or discovered addresses mentioning domain
        cleaned = []
        for e in emails:
            if self._is_valid_format(e) and (e.endswith(f"@{domain}") or domain in e.split("@")[-1]):
                cleaned.append(e.lower())
        return sorted(set(cleaned))

    def verify(self, emails: List[str]) -> List[Dict]:
        verified = []
        for email in emails[:50]:  # bound work
            result = {
                "email": email,
                "valid": False,
                "exists": False,
                "catch_all": False,
                "disposable": self._is_disposable(email),
                "mx": [],
            }
            if not self._is_valid_format(email):
                verified.append(result)
                continue
            domain = email.split("@", 1)[1]
            mx_hosts = self._mx_hosts(domain)
            result["mx"] = mx_hosts
            result["valid"] = bool(mx_hosts) or self._is_valid_format(email)
            if mx_hosts:
                try:
                    exists, catch_all = self._smtp_verify(email, mx_hosts[0])
                    result["exists"] = exists
                    result["catch_all"] = catch_all
                except Exception:
                    pass
            verified.append(result)
        return verified

    def find_sources(self, domain: str) -> Dict:
        sources = {
            "whois": [],
            "website": [],
            "github": [],
            "social_media": [],
            "data_breaches": [],
            "wayback_hints": [],
        }
        try:
            sources["whois"] = self._extract_from_whois(domain)
        except Exception:
            pass
        try:
            sources["website"] = self._scrape_website(domain)
        except Exception:
            pass
        try:
            sources["github"] = self._search_github(domain)
        except Exception:
            pass
        try:
            sources["wayback_hints"] = self._search_emails(domain)
        except Exception:
            pass
        return sources

    def _search_emails(self, domain: str) -> List[str]:
        """Pull emails from Wayback-captured pages mentioning the domain."""
        emails: List[str] = []
        try:
            r = requests.get(
                "https://web.archive.org/cdx/search/cdx",
                params={
                    "url": f"*.{domain}/*",
                    "output": "json",
                    "fl": "original",
                    "collapse": "urlkey",
                    "limit": "40",
                    "filter": "statuscode:200",
                },
                headers=self.headers,
                timeout=25,
            )
            if r.status_code != 200:
                return emails
            rows = r.json()
            pattern = re.compile(rf"\b[A-Za-z0-9._%+\-]+@{re.escape(domain)}\b", re.I)
            for row in rows[1:15]:
                url = row[0] if row else ""
                if not url.startswith("http") or not is_safe_url(url):
                    continue
                try:
                    # Prefer archived snapshot over live origin (reduces SSRF/redirect risk)
                    snap = f"https://web.archive.org/web/2id_/{url}"
                    page = requests.get(snap, headers=self.headers, timeout=8, allow_redirects=False)
                    if page.status_code in (301, 302) and page.headers.get("Location"):
                        loc = page.headers["Location"]
                        if is_safe_url(loc):
                            page = requests.get(loc, headers=self.headers, timeout=8, allow_redirects=False)
                    emails.extend(pattern.findall(page.text or ""))
                except requests.RequestException:
                    continue
        except (requests.RequestException, ValueError):
            pass
        return list(set(emails))

    def _extract_from_whois(self, domain: str) -> List[str]:
        emails = []
        try:
            import subprocess
            result = subprocess.run(
                ["whois", domain], capture_output=True, text=True, timeout=10, check=False
            )
            if result.returncode == 0 or result.stdout:
                emails.extend(re.findall(
                    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
                    result.stdout or "",
                    re.I,
                ))
        except (OSError, Exception):
            pass
        try:
            import whois
            w = whois.whois(domain)
            raw = w.emails
            if isinstance(raw, list):
                emails.extend(str(e) for e in raw if e)
            elif raw:
                emails.append(str(raw))
        except Exception:
            pass
        return list(set(e.lower() for e in emails if self._is_valid_format(e)))

    def _scrape_website(self, domain: str) -> List[str]:
        emails = []
        if not is_safe_host(domain):
            return emails
        for scheme in ("https", "http"):
            try:
                r = requests.get(f"{scheme}://{domain}", headers=self.headers, timeout=10)
                if r.status_code == 200:
                    emails.extend(re.findall(
                        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
                        r.text,
                        re.I,
                    ))
                    break
            except requests.RequestException:
                continue
        return list(set(e.lower() for e in emails if self._is_valid_format(e)))

    def _search_github(self, domain: str) -> List[str]:
        emails = []
        try:
            r = requests.get(
                "https://api.github.com/search/code",
                params={"q": f'"{domain}" in:file', "per_page": 20},
                headers={**self.headers, "Accept": "application/vnd.github.text-match+json"},
                timeout=15,
            )
            if r.status_code != 200:
                # fallback: search commits via public events is harder; try users email noreply
                return emails
            data = r.json()
            pattern = re.compile(rf"\b[A-Za-z0-9._%+\-]+@{re.escape(domain)}\b", re.I)
            for item in data.get("items") or []:
                for tm in item.get("text_matches") or []:
                    emails.extend(pattern.findall(tm.get("fragment") or ""))
                emails.extend(pattern.findall(item.get("path") or ""))
        except (requests.RequestException, ValueError):
            pass
        # also search users with domain in email (rare publicly)
        try:
            r = requests.get(
                f"https://api.github.com/search/users?q={quote(domain)}+in:email",
                headers=self.headers,
                timeout=10,
            )
            if r.status_code == 200:
                for user in (r.json().get("items") or [])[:10]:
                    login = user.get("login")
                    if not login:
                        continue
                    ur = requests.get(f"https://api.github.com/users/{login}", headers=self.headers, timeout=8)
                    if ur.status_code == 200:
                        em = ur.json().get("email")
                        if em and domain in em:
                            emails.append(em)
        except requests.RequestException:
            pass
        return list(set(e.lower() for e in emails if self._is_valid_format(e)))

    def _mx_hosts(self, domain: str) -> List[str]:
        if not DNS_AVAILABLE:
            return []
        try:
            answers = dns.resolver.resolve(domain, "MX")
            pairs = sorted(((r.preference, str(r.exchange).rstrip(".")) for r in answers), key=lambda x: x[0])
            return [h for _, h in pairs if is_safe_host(h)]
        except Exception:
            return []

    def _smtp_verify(self, email: str, mx_host: str) -> tuple:
        """RCPT probe — never sends mail. Returns (exists, catch_all)."""
        if not is_safe_host(mx_host):
            return False, False
        exists = False
        catch_all = False
        try:
            with smtplib.SMTP(timeout=8) as smtp:
                smtp.connect(mx_host, 25)
                smtp.helo("epic-osint.local")
                smtp.mail("probe@epic-osint.local")
                code, _ = smtp.rcpt(email)
                exists = code in (250, 251)
                # catch-all probe
                bogus = f"no-such-user-epic-{socket.gethostname()}@{email.split('@', 1)[1]}"
                code2, _ = smtp.rcpt(bogus)
                catch_all = code2 in (250, 251)
                if catch_all:
                    exists = False  # can't trust positive
                smtp.quit()
        except (smtplib.SMTPException, OSError, socket.timeout):
            pass
        return exists, catch_all

    def _is_valid_format(self, email: str) -> bool:
        return bool(re.match(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$", email or ""))

    def _is_disposable(self, email: str) -> bool:
        disposable = {
            "tempmail.com", "10minutemail.com", "guerrillamail.com",
            "mailinator.com", "throwaway.email", "temp-mail.org", "yopmail.com",
            "sharklasers.com", "guerrillamail.info", "trashmail.com",
        }
        try:
            return email.split("@", 1)[1].lower() in disposable
        except IndexError:
            return False
