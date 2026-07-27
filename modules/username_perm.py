"""Username / name permutation generator for OSINT pivots."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Set


class UsernamePermIntel:
    """Generate username and email-local-part permutations."""

    LEET = str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"})

    def generate(self, seed: str, years: bool = True, limit: int = 80) -> Dict[str, Any]:
        seed = (seed or "").strip()
        if not seed or len(seed) > 80:
            return {"error": "Invalid seed", "seed": seed}

        parts = self._parts(seed)
        raw: Set[str] = set()

        # base forms
        for p in parts:
            raw.add(p)
            raw.add(p.lower())
            raw.add(p.replace(" ", ""))
            raw.add(p.replace(" ", "."))
            raw.add(p.replace(" ", "_"))
            raw.add(p.replace(" ", "-"))

        if len(parts) >= 2:
            f, l = parts[0], parts[-1]
            combos = [
                f"{f}{l}", f"{f}.{l}", f"{f}_{l}", f"{f}-{l}",
                f"{f[0]}{l}", f"{f[0]}.{l}", f"{f[0]}_{l}",
                f"{f}{l[0]}", f"{l}{f}", f"{l}.{f}",
                f"{f[0]}{l[0]}", f"{l}{f[0]}",
            ]
            for c in combos:
                raw.add(c.lower())

        # leet / suffixes
        base_list = list(raw)
        for b in base_list:
            raw.add(b.translate(self.LEET))
            for s in ("1", "01", "123", "x", "official", "real"):
                raw.add(f"{b}{s}")
            if years:
                for y in ("2020", "2021", "2022", "2023", "2024", "2025", "2026", "99", "00", "01"):
                    raw.add(f"{b}{y}")

        cleaned = []
        seen = set()
        for u in sorted(raw, key=lambda x: (len(x), x)):
            u = re.sub(r"[^a-zA-Z0-9._\-]", "", u)
            if 2 <= len(u) <= 39 and u.lower() not in seen:
                seen.add(u.lower())
                cleaned.append(u)
            if len(cleaned) >= limit:
                break

        return {
            "seed": seed,
            "parts": parts,
            "count": len(cleaned),
            "usernames": cleaned,
            "note": "Feed these into Social / GitHub modules",
        }

    @staticmethod
    def _parts(seed: str) -> List[str]:
        if "@" in seed:
            seed = seed.split("@", 1)[0]
        seed = seed.replace(".", " ").replace("_", " ").replace("-", " ")
        return [p for p in seed.split() if p]
