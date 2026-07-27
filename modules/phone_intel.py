"""Phone OSINT — validation, region hints, free lookup pivots."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

import requests

from modules.net_util import DEFAULT_HEADERS

# E.164-ish: optional +, country code, subscriber digits
_E164 = re.compile(r"^\+?[1-9]\d{6,14}$")

# Common country calling codes (subset) → ISO hint
_CC = {
    "1": "US/CA", "7": "RU/KZ", "20": "EG", "27": "ZA", "30": "GR", "31": "NL",
    "32": "BE", "33": "FR", "34": "ES", "36": "HU", "39": "IT", "40": "RO",
    "41": "CH", "43": "AT", "44": "GB", "45": "DK", "46": "SE", "47": "NO",
    "48": "PL", "49": "DE", "51": "PE", "52": "MX", "53": "CU", "54": "AR",
    "55": "BR", "56": "CL", "57": "CO", "58": "VE", "60": "MY", "61": "AU",
    "62": "ID", "63": "PH", "64": "NZ", "65": "SG", "66": "TH", "81": "JP",
    "82": "KR", "84": "VN", "86": "CN", "90": "TR", "91": "IN", "92": "PK",
    "93": "AF", "94": "LK", "95": "MM", "98": "IR", "212": "MA", "213": "DZ",
    "216": "TN", "218": "LY", "220": "GM", "234": "NG", "254": "KE", "255": "TZ",
    "256": "UG", "260": "ZM", "263": "ZW", "351": "PT", "352": "LU", "353": "IE",
    "354": "IS", "358": "FI", "359": "BG", "370": "LT", "371": "LV", "372": "EE",
    "380": "UA", "381": "RS", "385": "HR", "386": "SI", "420": "CZ", "421": "SK",
    "852": "HK", "853": "MO", "855": "KH", "856": "LA", "880": "BD", "886": "TW",
    "960": "MV", "961": "LB", "962": "JO", "963": "SY", "964": "IQ", "965": "KW",
    "966": "SA", "967": "YE", "968": "OM", "970": "PS", "971": "AE", "972": "IL",
    "973": "BH", "974": "QA", "975": "BT", "976": "MN", "977": "NP", "992": "TJ",
    "993": "TM", "994": "AZ", "995": "GE", "996": "KG", "998": "UZ",
}


class PhoneIntel:
    """Basic phone number OSINT without paid APIs."""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)

    def analyze(self, raw: str) -> Dict[str, Any]:
        digits = self._normalize(raw)
        if not digits or not _E164.match(digits):
            return {"error": "Invalid phone number", "input": raw}

        e164 = digits if digits.startswith("+") else f"+{digits}"
        bare = e164.lstrip("+")
        country = self._country(bare)
        result: Dict[str, Any] = {
            "input": raw,
            "e164": e164,
            "country_hint": country,
            "length": len(bare),
            "pivots": self._pivots(e164, bare),
            "lookups": {},
        }
        result["lookups"] = self._free_lookups(bare)
        return result

    @staticmethod
    def _normalize(raw: str) -> Optional[str]:
        if not raw:
            return None
        s = re.sub(r"[\s\-().]", "", raw.strip())
        if s.startswith("00"):
            s = "+" + s[2:]
        if not re.match(r"^\+?\d+$", s):
            return None
        return s

    @staticmethod
    def _country(bare: str) -> Optional[str]:
        for length in (3, 2, 1):
            cc = bare[:length]
            if cc in _CC:
                return _CC[cc]
        return None

    @staticmethod
    def _pivots(e164: str, bare: str) -> List[Dict[str, str]]:
        return [
            {"name": "Truecaller (manual)", "url": f"https://www.truecaller.com/search/{bare}"},
            {"name": "Sync.me (manual)", "url": f"https://sync.me/search/?number={bare}"},
            {"name": "WhatsApp wa.me", "url": f"https://wa.me/{bare}"},
            {"name": "Telegram", "url": f"https://t.me/+{bare}"},
            {"name": "Google dork", "url": f"https://www.google.com/search?q=%22{e164}%22+OR+%22{bare}%22"},
        ]

    def _free_lookups(self, bare: str) -> Dict[str, Any]:
        """Best-effort public HTML/API probes (may rate-limit)."""
        out: Dict[str, Any] = {}
        # numverify-style free endpoints are key-gated; use abstractapi-less approach:
        # Check if number appears in public GitHub code (leak pivot)
        try:
            r = self.session.get(
                "https://api.github.com/search/code",
                params={"q": f"{bare} in:file", "per_page": 5},
                timeout=12,
            )
            if r.status_code == 200:
                data = r.json()
                out["github_code_hits"] = data.get("total_count", 0)
                out["github_items"] = [
                    {"repo": i.get("repository", {}).get("full_name"), "path": i.get("path"), "url": i.get("html_url")}
                    for i in (data.get("items") or [])[:5]
                ]
            elif r.status_code == 401:
                out["github_code_hits"] = None
                out["note"] = "GitHub code search needs authenticated token for higher access"
            else:
                out["github_status"] = r.status_code
        except requests.RequestException as exc:
            out["github_error"] = str(exc)
        return out
