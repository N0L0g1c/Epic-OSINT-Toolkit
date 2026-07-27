"""
ASCII/ANSI report formatting — turn scan JSON into readable TUI lines.
Each line is (text, style) where style is a Theme tag name.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple

Line = Tuple[str, str]  # text, style: header|section|rule|key|val|bullet|ok|warn|err|dim|meta|blank


def _rule(width: int = 62, char: str = "=") -> Line:
    return (char * width, "rule")


def _blank() -> Line:
    return ("", "blank")


def _hdr(text: str) -> Line:
    return (text, "header")


def _sec(text: str) -> Line:
    return (text, "section")


def _meta(text: str) -> Line:
    return (text, "meta")


def _key(text: str) -> Line:
    return (text, "key")


def _val(text: str) -> Line:
    return (text, "val")


def _bul(text: str) -> Line:
    return (text, "bullet")


def _ok(text: str) -> Line:
    return (text, "ok")


def _warn(text: str) -> Line:
    return (text, "warn")


def _err(text: str) -> Line:
    return (text, "err")


def _dim(text: str) -> Line:
    return (text, "dim")


def _box_title(title: str, width: int = 62) -> List[Line]:
    inner = width - 2
    t = f" {title} "
    pad = max(0, inner - len(t))
    left = pad // 2
    right = pad - left
    return [
        _rule(width, "#"),
        _hdr("#" + (" " * left) + t + (" " * right) + "#"),
        _rule(width, "#"),
    ]


def _section_bar(name: str, width: int = 62) -> List[Line]:
    label = f"[ {name.upper()} ]"
    fill = max(0, width - len(label) - 4)
    return [
        _blank(),
        _sec("+--" + label + "-" * fill + "+"),
    ]


def _kv(key: str, value: Any, indent: int = 0, width: int = 56) -> Line:
    pad = " " * indent
    k = str(key).replace("_", " ")
    v = _fmt_scalar(value)
    dots = max(2, width - indent - len(k) - len(v) - 2)
    return _key(f"{pad}{k} {'.' * dots} {v}")


def _fmt_scalar(value: Any, limit: int = 90) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "YES" if value else "NO"
    if isinstance(value, float):
        return f"{value:.4g}"
    s = str(value).replace("\n", " ").strip()
    if len(s) > limit:
        return s[: limit - 3] + "..."
    return s or "-"


def _emit_value(key: str, value: Any, indent: int = 0, depth: int = 0) -> List[Line]:
    """Recursively emit styled lines for any JSON-ish value."""
    if depth > 6:
        return [_dim(" " * indent + "...")]
    lines: List[Line] = []
    pad = " " * indent

    if value is None or value == "" or value == [] or value == {}:
        return lines

    if isinstance(value, bool):
        sty = _ok if value else _dim
        lines.append(sty(f"{pad}{key.replace('_', ' ')} .... {_fmt_scalar(value)}"))
        return lines

    if isinstance(value, (str, int, float)):
        lines.append(_kv(key, value, indent=indent))
        return lines

    if isinstance(value, list):
        if not value:
            return lines
        # list of scalars
        if all(not isinstance(x, (dict, list)) for x in value):
            lines.append(_key(f"{pad}{key.replace('_', ' ')} ({len(value)})"))
            for item in value[:80]:
                lines.append(_bul(f"{pad}  + {_fmt_scalar(item, 100)}"))
            if len(value) > 80:
                lines.append(_dim(f"{pad}  ... +{len(value) - 80} more"))
            return lines
        # list of dicts / mixed
        lines.append(_key(f"{pad}{key.replace('_', ' ')} ({len(value)})"))
        for i, item in enumerate(value[:40], 1):
            if isinstance(item, dict):
                label = (
                    item.get("name")
                    or item.get("url")
                    or item.get("email")
                    or item.get("login")
                    or item.get("platform")
                    or item.get("onion")
                    or f"#{i}"
                )
                lines.append(_ok(f"{pad}  [{i:02d}] {_fmt_scalar(label, 70)}"))
                for sk, sv in list(item.items())[:12]:
                    if sk in ("name", "url", "email", "login") and sv == label:
                        continue
                    if sv in (None, "", [], {}):
                        continue
                    if isinstance(sv, (dict, list)):
                        lines.extend(_emit_value(str(sk), sv, indent=indent + 4, depth=depth + 1))
                    else:
                        lines.append(_dim(f"{pad}      {str(sk).replace('_', ' ')} : {_fmt_scalar(sv, 70)}"))
            else:
                lines.append(_bul(f"{pad}  + {_fmt_scalar(item)}"))
        if len(value) > 40:
            lines.append(_dim(f"{pad}  ... +{len(value) - 40} more"))
        return lines

    if isinstance(value, dict):
        # Special-case social profiles: only show exists=True
        if key == "profiles" and any(isinstance(v, dict) and "exists" in v for v in value.values()):
            found = [(p, info) for p, info in value.items() if info.get("exists") is True]
            unknown = sum(1 for info in value.values() if isinstance(info, dict) and info.get("exists") is None)
            missing = sum(1 for info in value.values() if isinstance(info, dict) and info.get("exists") is False)
            lines.append(_key(f"{pad}profiles found ({len(found)} / {len(value)})"))
            for p, info in found[:60]:
                url = info.get("url") or ""
                lines.append(_ok(f"{pad}  [*] {p}"))
                if url:
                    lines.append(_dim(f"{pad}      {url}"))
            if missing:
                lines.append(_dim(f"{pad}  (not found on {missing} platforms)"))
            if unknown:
                lines.append(_warn(f"{pad}  (blocked/unknown on {unknown} platforms)"))
            return lines

        lines.append(_key(f"{pad}{key.replace('_', ' ')}"))
        for sk, sv in value.items():
            if sv in (None, "", [], {}):
                continue
            lines.extend(_emit_value(str(sk), sv, indent=indent + 2, depth=depth + 1))
        return lines

    lines.append(_kv(key, value, indent=indent))
    return lines


SECTION_TITLES = {
    "domain": "DOMAIN INTELLIGENCE",
    "social": "SOCIAL MEDIA",
    "github": "GITHUB",
    "website": "WEB CRAWL",
    "emails": "EMAIL DISCOVERY",
    "urls": "URL HUNT",
    "wayback": "WAYBACK ARCHIVE",
    "pastes": "PASTE / LEAK HUNT",
    "ip": "IP INTELLIGENCE",
    "asn": "ASN / NETBLOCKS",
    "phone": "PHONE OSINT",
    "ports": "PORT SCAN",
    "host_intel": "SHODAN / CENSYS",
    "company": "COMPANY / EMPLOYEES",
    "dark_web": "DARK WEB",
    "onion_dirs": "ONION DIRECTORY",
    "dorks": "SEARCH DORKS",
    "buckets": "CLOUD BUCKETS",
    "takeover": "TAKEOVER CHECKS",
    "favicon": "FAVICON HASH",
    "meta": "EXIF / METADATA",
    "correlation": "CORRELATION GRAPH",
}


def format_scan_report(results: Dict[str, Any], saved_path: Optional[str] = None) -> List[Line]:
    """Build a full styled report from a scan results dict."""
    width = 62
    lines: List[Line] = []
    lines.extend(_box_title("EPIC OSINT  ::  INTEL REPORT", width))
    lines.append(_blank())
    lines.append(_meta(f"  TARGET .... {_fmt_scalar(results.get('target'), 40)}"))
    lines.append(_meta(f"  TYPE ...... {_fmt_scalar(results.get('scan_type'), 40)}"))
    lines.append(_meta(f"  TIME ...... {_fmt_scalar(results.get('timestamp'), 40)}"))
    if saved_path:
        lines.append(_ok(f"  SAVED ..... {_fmt_scalar(saved_path, 48)}"))
    lines.append(_rule(width, "-"))

    blob = results.get("results") or {}
    if not blob and any(k in results for k in ("domain", "ip", "social")):
        blob = {k: results[k] for k in results if k not in ("target", "scan_type", "timestamp", "correlation")}

    for section, data in blob.items():
        title = SECTION_TITLES.get(section, section.replace("_", " ").upper())
        lines.extend(_section_bar(title, width))
        if isinstance(data, dict):
            for k, v in data.items():
                if v in (None, "", [], {}):
                    continue
                lines.extend(_emit_value(str(k), v, indent=2, depth=0))
        else:
            lines.extend(_emit_value(section, data, indent=2, depth=0))

    corr = results.get("correlation")
    if corr:
        lines.extend(_section_bar(SECTION_TITLES["correlation"], width))
        for k, v in corr.items():
            if k == "links":
                links = v or []
                lines.append(_key(f"  links ({len(links)})"))
                for link in links[:40]:
                    lines.append(_bul(f"    {link.get('from', '?')}  -->  {link.get('to', '?')}"))
                if len(links) > 40:
                    lines.append(_dim(f"    ... +{len(links) - 40} more"))
            else:
                lines.extend(_emit_value(str(k), v, indent=2, depth=0))

    lines.append(_blank())
    lines.append(_rule(width, "#"))
    lines.append(_hdr("#" + " END OF REPORT ".center(width - 2) + "#"))
    lines.append(_rule(width, "#"))
    return lines


def format_json_file(text: str) -> List[Line]:
    """Parse a saved JSON report into styled lines; fall back to raw text."""
    import json

    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return [(line, "val") for line in text.splitlines()[:2000]]
    if isinstance(data, dict) and ("results" in data or "target" in data):
        return format_scan_report(data)
    # generic object
    lines = list(_box_title("SAVED DATA"))
    if isinstance(data, dict):
        for k, v in data.items():
            lines.extend(_emit_value(str(k), v, indent=2))
    else:
        lines.extend(_emit_value("data", data, indent=2))
    return lines


def plain_text(lines: Iterable[Line]) -> str:
    return "\n".join(t for t, _ in lines)
