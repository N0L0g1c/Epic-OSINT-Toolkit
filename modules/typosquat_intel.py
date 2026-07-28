"""Typosquat / lookalike domain generation + live DNS resolution."""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Set

from modules.net_util import is_safe_host

# Common adjacent QWERTY keys for fat-finger variants
_ADJ = {
    "a": "sqwz", "b": "vghn", "c": "xdfv", "d": "erfcxs", "e": "rdsw",
    "f": "rtgvcd", "g": "tyhbvf", "h": "yujnbg", "i": "uojk", "j": "uiknhm",
    "k": "ioljm", "l": "opk", "m": "njk", "n": "bhjm", "o": "iplk",
    "p": "ol", "q": "wa", "r": "edft", "s": "awedxz", "t": "rfgy",
    "u": "yhji", "v": "cfgb", "w": "qase", "x": "zsdc", "y": "tghu",
    "z": "asx",
}

_HOMO = {
    "a": ("à", "á", "â", "ä", "а"),  # incl. Cyrillic а
    "c": ("ç", "с"),
    "e": ("è", "é", "ê", "ë", "е"),
    "i": ("ì", "í", "î", "ï", "і"),
    "o": ("ò", "ó", "ô", "ö", "о"),
    "p": ("р",),
    "s": ("ś", "š"),
    "x": ("х",),
    "y": ("ÿ", "у"),
}

_TLDS = ("com", "net", "org", "io", "co", "info", "biz", "app", "dev", "xyz", "online", "site")


class TyposquatIntel:
    """Generate lookalike domains and report which ones resolve."""

    def analyze(self, domain: str, resolve: bool = True, limit: int = 200) -> Dict[str, Any]:
        domain = (domain or "").strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0]
        if not domain or "." not in domain or not is_safe_host(domain):
            return {"error": "Invalid domain", "domain": domain}

        parts = domain.rsplit(".", 1)
        if len(parts) != 2:
            return {"error": "Need registrable domain (name.tld)", "domain": domain}
        sld, tld = parts[0], parts[1]
        # multi-level: keep last label as SLD for generation (example.co.uk → weak)
        if "." in sld:
            labels = sld.split(".")
            prefix, sld = ".".join(labels[:-1]) + ".", labels[-1]
        else:
            prefix = ""

        if len(sld) < 2 or len(sld) > 63:
            return {"error": "SLD length out of range", "domain": domain}

        candidates: Set[str] = set()
        for name in self._variants(sld):
            if not name or name == sld or len(name) > 63:
                continue
            candidates.add(f"{prefix}{name}.{tld}")

        # TLD swaps for original SLD only (avoid combinatorial explosion)
        for alt in _TLDS:
            if alt != tld:
                candidates.add(f"{prefix}{sld}.{alt}")

        candidates.discard(domain)
        ordered = sorted(candidates)[: max(20, min(limit, 400))]

        resolved: List[Dict[str, Any]] = []
        if resolve:
            with ThreadPoolExecutor(max_workers=32) as pool:
                futs = {pool.submit(self._resolve, d): d for d in ordered}
                for fut in as_completed(futs):
                    row = fut.result()
                    if row and row.get("ips"):
                        resolved.append(row)
            resolved.sort(key=lambda x: x.get("domain", ""))

        return {
            "domain": domain,
            "sld": sld,
            "tld": tld,
            "generated": len(ordered),
            "candidates": ordered[:100],
            "resolved_count": len(resolved),
            "resolved": resolved[:80],
            "note": "Resolved lookalikes may be legitimate siblings or malicious typosquats — verify manually",
        }

    def _variants(self, sld: str) -> Set[str]:
        out: Set[str] = set()
        # omission
        for i in range(len(sld)):
            out.add(sld[:i] + sld[i + 1:])
        # duplication
        for i in range(len(sld)):
            out.add(sld[:i] + sld[i] + sld[i:])
        # adjacent transposition
        for i in range(len(sld) - 1):
            out.add(sld[:i] + sld[i + 1] + sld[i] + sld[i + 2:])
        # replacement / adjacent keys
        for i, ch in enumerate(sld):
            for alt in _ADJ.get(ch, ""):
                out.add(sld[:i] + alt + sld[i + 1:])
            for alt in _HOMO.get(ch, ()):
                # skip non-ASCII for DNS labels that must be IDNA — encode via idna
                try:
                    label = (sld[:i] + alt + sld[i + 1:]).encode("idna").decode("ascii")
                    out.add(label)
                except (UnicodeError, UnicodeDecodeError):
                    pass
        # hyphen insertion
        for i in range(1, len(sld)):
            out.add(sld[:i] + "-" + sld[i:])
        # hyphen removal
        if "-" in sld:
            out.add(sld.replace("-", ""))
        # bitsquat-ish: flip one alphanumeric (limited)
        for i, ch in enumerate(sld):
            if ch.isalpha():
                out.add(sld[:i] + ("b" if ch != "b" else "d") + sld[i + 1:])
        return {x for x in out if x and all(c.isalnum() or c == "-" for c in x) and not x.startswith("-") and not x.endswith("-")}

    @staticmethod
    def _resolve(host: str) -> Dict[str, Any]:
        if not is_safe_host(host):
            return {"domain": host, "ips": []}
        ips: List[str] = []
        try:
            for info in socket.getaddrinfo(host, None):
                ip = info[4][0]
                if ip and ip not in ips and is_safe_host(ip):
                    ips.append(ip)
        except socket.gaierror:
            return {"domain": host, "ips": []}
        return {"domain": host, "ips": ips[:4]}
