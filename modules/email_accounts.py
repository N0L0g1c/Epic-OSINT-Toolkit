"""Email → account registration checks (Holehe-style, public endpoints)."""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

import requests

from modules.http_util import pace, rotate_headers

_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


# name, method, url, check(response) -> Optional[bool]  True=exists False=not None=unknown
def _checks() -> List[Tuple[str, str, str, Any]]:
    def body_has(needles: Tuple[str, ...], invert: bool = False):
        def _fn(r: requests.Response) -> Optional[bool]:
            text = (r.text or "").lower()
            hit = any(n.lower() in text for n in needles)
            return (not hit) if invert else hit
        return _fn

    def status_in(codes: Tuple[int, ...], as_exists: bool = True):
        def _fn(r: requests.Response) -> Optional[bool]:
            if r.status_code in codes:
                return as_exists
            return False
        return _fn

    return [
        ("gravatar", "GET", "https://en.gravatar.com/{hash}.json", None),  # special
        ("github", "GET", "https://api.github.com/search/users?q={email}+in:email",
         lambda r: (r.json().get("total_count", 0) > 0) if r.status_code == 200 else None),
        ("adobe", "POST", "https://auth.services.adobe.com/signin/v2/users/accounts",
         body_has(("not found", "invalid"), invert=True)),
        ("spotify", "GET", "https://spclient.wg.spotify.com/signup/public/v1/account?validate=1&email={email}",
         lambda r: r.status_code == 200 and "status" in (r.text or "") and "20" not in (r.text or "")[:80]
         if r.status_code == 200 else None),
        ("twitter_x", "GET", "https://api.twitter.com/i/users/email_available.json?email={email}",
         lambda r: (r.json().get("taken") is True) if r.status_code == 200 else None),
        ("instagram", "POST", "https://www.instagram.com/accounts/web_create_ajax/attempt/",
         None),  # often blocked — skip soft
        ("pinterest", "POST", "https://www.pinterest.com/resource/EmailExistsResource/create/",
         body_has(("error",))),
        ("tumblr", "GET", "https://www.tumblr.com/api/v2/user/email?email={email}",
         status_in((200,), True)),
        ("wordpress", "GET", "https://public-api.wordpress.com/rest/v1.1/users/{email}/auth-options",
         lambda r: r.status_code == 200),
        ("flickr", "GET", "https://www.flickr.com/", None),
        ("skype", "POST", "https://login.live.com/", None),
    ]


class EmailAccountsIntel:
    """Probe whether an email appears registered on public services."""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update(rotate_headers())

    def check(self, email: str, threads: int = 8) -> Dict[str, Any]:
        email = (email or "").strip().lower()
        if not _EMAIL_RE.match(email):
            return {"error": "Invalid email", "email": email}

        import hashlib
        ghash = hashlib.md5(email.encode()).hexdigest()
        results: List[Dict[str, Any]] = []

        def probe(name: str) -> Dict[str, Any]:
            pace()
            try:
                if name == "gravatar":
                    url = f"https://en.gravatar.com/{ghash}.json"
                    r = self.session.get(url, headers=rotate_headers(), timeout=8)
                    exists = r.status_code == 200
                    return {"platform": "gravatar", "exists": exists, "url": f"https://gravatar.com/{ghash}",
                            "status": r.status_code}
                if name == "github":
                    r = self.session.get(
                        "https://api.github.com/search/users",
                        params={"q": f"{email} in:email"},
                        headers=rotate_headers(),
                        timeout=10,
                    )
                    exists = None
                    if r.status_code == 200:
                        exists = r.json().get("total_count", 0) > 0
                    return {"platform": "github", "exists": exists, "status": r.status_code,
                            "url": f"https://github.com/search?q={email}&type=users"}
                if name == "twitter_x":
                    r = self.session.get(
                        "https://api.twitter.com/i/users/email_available.json",
                        params={"email": email},
                        headers=rotate_headers(),
                        timeout=8,
                    )
                    exists = None
                    if r.status_code == 200:
                        try:
                            exists = bool(r.json().get("taken"))
                        except ValueError:
                            exists = None
                    return {"platform": "twitter_x", "exists": exists, "status": r.status_code}
                if name == "wordpress":
                    r = self.session.get(
                        f"https://public-api.wordpress.com/rest/v1.1/users/{email}/auth-options",
                        headers=rotate_headers(),
                        timeout=8,
                    )
                    return {"platform": "wordpress", "exists": r.status_code == 200, "status": r.status_code}
                if name == "adobe":
                    r = self.session.post(
                        "https://auth.services.adobe.com/signin/v2/users/accounts",
                        json={"username": email, "usernameType": "EMAIL"},
                        headers=rotate_headers({"Content-Type": "application/json"}),
                        timeout=10,
                    )
                    exists = None
                    if r.status_code in (200, 401, 403):
                        text = (r.text or "").lower()
                        if "not found" in text or "novalid" in text:
                            exists = False
                        elif r.status_code == 200:
                            exists = True
                    return {"platform": "adobe", "exists": exists, "status": r.status_code}
                # generic existence via HaveIBeenRegistered-style free endpoints is brittle;
                # return unknown for unsupported
                return {"platform": name, "exists": None, "status": None, "note": "probe skipped/unstable"}
            except requests.RequestException as exc:
                return {"platform": name, "exists": None, "error": str(exc)}

        platforms = ["gravatar", "github", "twitter_x", "wordpress", "adobe",
                      "spotify", "tumblr", "pinterest"]
        # lightweight dedicated probes
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futs = [pool.submit(probe, p) for p in platforms]
            for fut in as_completed(futs):
                results.append(fut.result())

        # Extra: DuckDuckGo / Google dork pivots (no scrape)
        results.append({
            "platform": "search_pivots",
            "exists": None,
            "pivots": [
                f"https://www.google.com/search?q=%22{email}%22",
                f"https://duckduckgo.com/?q=%22{email}%22",
                f"https://haveibeenpwned.com/account/{email}",
            ],
        })

        found = [r for r in results if r.get("exists") is True]
        missing = [r for r in results if r.get("exists") is False]
        unknown = [r for r in results if r.get("exists") is None and r.get("platform") != "search_pivots"]
        return {
            "email": email,
            "gravatar_hash": ghash,
            "found": found,
            "not_found": missing,
            "unknown": unknown,
            "all": results,
            "summary": {"registered": len(found), "not_registered": len(missing), "unknown": len(unknown)},
        }
