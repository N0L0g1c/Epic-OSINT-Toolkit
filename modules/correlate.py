"""Target auto-detection and cross-module correlation."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Set
from urllib.parse import urlparse

_EMAIL = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_IPV6 = re.compile(r"^[0-9a-fA-F:]+$")
_DOMAIN = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
_ONION = re.compile(r"^(?:[a-z2-7]{16}|[a-z2-7]{56})\.onion$", re.I)
_PHONE = re.compile(r"^\+?[1-9]\d{6,14}$")
_USER = re.compile(r"^[A-Za-z0-9_\-.]{2,39}$")
_ETH_ADDR = re.compile(r"^0x[a-fA-F0-9]{40}$")
_ETH_TX = re.compile(r"^0x[a-fA-F0-9]{64}$")
_BTC_ADDR = re.compile(r"^(?:bc1[a-z0-9]{25,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$")
_ENS = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.eth$", re.I)
_TRX_ADDR = re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")
_BTC_TX = re.compile(r"^[a-fA-F0-9]{64}$")
_XRP_ADDR = re.compile(r"^r[1-9A-HJ-NP-Za-km-z]{24,34}$")
_ADA_ADDR = re.compile(r"^addr1[a-z0-9]{50,120}$")
_ADA_STAKE = re.compile(r"^stake1[a-z0-9]{50,120}$")
_DOGE_ADDR = re.compile(r"^D[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}$")
_DASH_ADDR = re.compile(r"^X[1-9A-HJ-NP-Za-km-z]{33}$")
_XMR_ADDR = re.compile(r"^[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}$|^4[0-9AB][1-9A-HJ-NP-Za-km-z]{104}$")
_ZEC_T = re.compile(r"^t[13][a-km-zA-HJ-NP-Z1-9]{33}$")
_ZEC_Z = re.compile(r"^(?:zs1[a-z0-9]{70,90}|zc[a-zA-Z0-9]{90,120})$")


_COMPANY_HINT = re.compile(
    r"\b(?:inc|llc|ltd|corp|corporation|company|co|gmbh|sarl|plc|group|holdings|technologies|tech|labs|limited)\b",
    re.I,
)


def detect_target_type(raw: str) -> str:
    """Return one of: email, ip, url, onion, phone, domain, username, company, person, wallet."""
    t = (raw or "").strip()
    if not t:
        return "username"
    if t.startswith(("http://", "https://")):
        host = urlparse(t).hostname or ""
        if host.endswith(".onion"):
            return "onion"
        return "url"
    if _EMAIL.match(t):
        return "email"
    if (
        _ENS.match(t) or _ETH_ADDR.match(t) or _ETH_TX.match(t) or _BTC_ADDR.match(t)
        or _TRX_ADDR.match(t) or _XRP_ADDR.match(t) or _ADA_ADDR.match(t) or _ADA_STAKE.match(t)
        or _DOGE_ADDR.match(t) or _DASH_ADDR.match(t) or _XMR_ADDR.match(t)
        or _ZEC_T.match(t) or _ZEC_Z.match(t)
    ):
        return "wallet"
    if _BTC_TX.match(t) and len(t) == 64:
        return "wallet"
    if _ONION.match(t):
        return "onion"
    if _IPV4.match(t) or (_IPV6.match(t) and ":" in t):
        return "ip"
    phone_try = re.sub(r"[\s\-().]", "", t)
    if phone_try.startswith("00"):
        phone_try = "+" + phone_try[2:]
    if _PHONE.match(phone_try) and sum(c.isdigit() for c in phone_try) >= 8:
        if not _DOMAIN.match(t):
            return "phone"
    if _DOMAIN.match(t):
        return "domain"
    if " " in t:
        tokens = [x for x in t.split() if x]
        if _COMPANY_HINT.search(t) or len(tokens) >= 4:
            return "company"
        # 2–3 alphabetic tokens → likely a person name
        if 2 <= len(tokens) <= 3 and all(re.match(r"^[\w.\-']+$", x, re.UNICODE) for x in tokens):
            return "person"
        return "company"
    if _USER.match(t):
        return "username"
    return "company"


class Correlator:
    """Extract entities from scan results and build simple link graph."""

    def correlate(self, results: Dict[str, Any]) -> Dict[str, Any]:
        entities: Dict[str, Set[str]] = {
            "emails": set(),
            "domains": set(),
            "ips": set(),
            "usernames": set(),
            "urls": set(),
            "phones": set(),
            "wallets": set(),
        }
        links: List[Dict[str, str]] = []

        target = str(results.get("target") or "")
        ttype = results.get("scan_type") or detect_target_type(target)
        self._add_entity(entities, ttype, target)

        blob = results.get("results") or {}
        self._walk(blob, entities)

        # Link target → each found entity
        root_type = self._map_type(ttype)
        root_val = target
        for etype, values in entities.items():
            for v in values:
                if v == root_val:
                    continue
                links.append({"from": f"{root_type}:{root_val}", "to": f"{etype}:{v}"})

        return {
            "target": target,
            "detected_type": ttype,
            "entities": {k: sorted(v)[:100] for k, v in entities.items()},
            "counts": {k: len(v) for k, v in entities.items()},
            "links": links[:500],
        }

    def _walk(self, obj: Any, entities: Dict[str, Set[str]], depth: int = 0) -> None:
        if depth > 8:
            return
        if isinstance(obj, dict):
            for k, v in obj.items():
                kl = str(k).lower()
                if isinstance(v, str):
                    self._classify_value(v, entities)
                    if "email" in kl:
                        self._add_entity(entities, "email", v)
                    elif "username" in kl or kl in ("login", "user"):
                        self._add_entity(entities, "username", v)
                    elif kl in ("address", "from", "to") or "wallet" in kl:
                        if _ETH_ADDR.match(v) or _BTC_ADDR.match(v) or _TRX_ADDR.match(v) or _ENS.match(v):
                            self._add_entity(entities, "wallet", v)
                else:
                    self._walk(v, entities, depth + 1)
        elif isinstance(obj, list):
            for item in obj[:200]:
                if isinstance(item, str):
                    self._classify_value(item, entities)
                else:
                    self._walk(item, entities, depth + 1)
        elif isinstance(obj, str):
            self._classify_value(obj, entities)

    def _classify_value(self, v: str, entities: Dict[str, Set[str]]) -> None:
        v = v.strip()
        if not v or len(v) > 500:
            return
        if _EMAIL.match(v):
            self._add_entity(entities, "email", v)
            domain = v.split("@", 1)[1]
            self._add_entity(entities, "domain", domain)
        elif v.startswith(("http://", "https://")):
            self._add_entity(entities, "url", v)
            host = urlparse(v).hostname
            if host:
                if host.endswith(".onion"):
                    self._add_entity(entities, "domain", host)
                elif _DOMAIN.match(host):
                    self._add_entity(entities, "domain", host)
                elif _IPV4.match(host):
                    self._add_entity(entities, "ip", host)
        elif _ETH_ADDR.match(v) or _BTC_ADDR.match(v) or _TRX_ADDR.match(v) or _ENS.match(v) \
                or _XRP_ADDR.match(v) or _ADA_ADDR.match(v) or _DOGE_ADDR.match(v) \
                or _DASH_ADDR.match(v) or _XMR_ADDR.match(v) or _ZEC_T.match(v) or _ZEC_Z.match(v):
            self._add_entity(entities, "wallet", v)
        elif _IPV4.match(v):
            self._add_entity(entities, "ip", v)
        elif _DOMAIN.match(v):
            self._add_entity(entities, "domain", v)
        elif _ONION.match(v):
            self._add_entity(entities, "domain", v.lower())

    @staticmethod
    def _add_entity(entities: Dict[str, Set[str]], kind: str, value: str) -> None:
        mapping = {
            "email": "emails",
            "domain": "domains",
            "ip": "ips",
            "username": "usernames",
            "url": "urls",
            "phone": "phones",
            "onion": "domains",
            "company": "usernames",
            "person": "usernames",
            "wallet": "wallets",
        }
        key = mapping.get(kind)
        if key and value:
            entities[key].add(value.strip())

    @staticmethod
    def _map_type(ttype: str) -> str:
        return {
            "email": "emails",
            "domain": "domains",
            "ip": "ips",
            "username": "usernames",
            "url": "urls",
            "phone": "phones",
            "onion": "domains",
            "company": "usernames",
            "person": "usernames",
            "wallet": "wallets",
        }.get(ttype, "usernames")
