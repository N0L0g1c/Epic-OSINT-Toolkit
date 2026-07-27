"""Image / document metadata (EXIF) OSINT."""

from __future__ import annotations

import struct
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import requests

from modules.net_util import DEFAULT_HEADERS, is_safe_url

# Common EXIF tags
_EXIF_TAGS = {
    0x010F: "Make",
    0x0110: "Model",
    0x0112: "Orientation",
    0x0131: "Software",
    0x0132: "DateTime",
    0x010E: "ImageDescription",
    0x9C9B: "XPTitle",
    0x9C9C: "XPComment",
    0x9C9D: "XPAuthor",
    0x8769: "ExifIFD",
    0x8825: "GPSInfo",
    0x9003: "DateTimeOriginal",
    0x9004: "DateTimeDigitized",
    0xA002: "PixelXDimension",
    0xA003: "PixelYDimension",
    0x011A: "XResolution",
    0x011B: "YResolution",
}


class MetaIntel:
    """Extract EXIF / GPS from remote or local JPEG images."""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)

    def analyze(self, target: str) -> Dict[str, Any]:
        raw = (target or "").strip()
        if not raw:
            return {"error": "Empty target"}

        data: Optional[bytes] = None
        source = raw
        if raw.startswith(("http://", "https://")):
            if not is_safe_url(raw):
                return {"error": "Blocked or invalid URL", "target": raw}
            try:
                r = self.session.get(raw, timeout=20, stream=True)
                # bound download
                chunks = []
                size = 0
                for chunk in r.iter_content(65536):
                    chunks.append(chunk)
                    size += len(chunk)
                    if size > 8_000_000:
                        break
                data = b"".join(chunks)
                source = raw
            except requests.RequestException as exc:
                return {"error": str(exc), "target": raw}
        else:
            # local path — only under cwd
            from pathlib import Path
            path = Path(raw).expanduser()
            try:
                resolved = path.resolve()
                resolved.relative_to(Path.cwd().resolve())
            except (ValueError, OSError):
                return {"error": "Local path must be under current working directory"}
            if not resolved.is_file():
                return {"error": "File not found", "path": str(path)}
            data = resolved.read_bytes()[:8_000_000]
            source = str(resolved)

        if not data:
            return {"error": "No data"}

        exif = self._parse_jpeg_exif(data)
        result: Dict[str, Any] = {
            "source": source,
            "size": len(data),
            "type": self._sniff(data),
            "exif": exif or {},
            "gps": self._gps_from_exif(exif) if exif else None,
        }
        if not exif:
            result["note"] = "No EXIF found (non-JPEG or stripped)"
        return result

    @staticmethod
    def _sniff(data: bytes) -> str:
        if data[:3] == b"\xff\xd8\xff":
            return "jpeg"
        if data[:8] == b"\x89PNG\r\n\x1a\n":
            return "png"
        if data[:4] == b"%PDF":
            return "pdf"
        if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
            return "webp"
        return "unknown"

    def _parse_jpeg_exif(self, data: bytes) -> Dict[str, Any]:
        if data[:3] != b"\xff\xd8\xff":
            return {}
        # find APP1 EXIF
        i = 2
        while i + 4 < len(data):
            if data[i] != 0xFF:
                break
            marker = data[i + 1]
            if marker == 0xD9:  # EOI
                break
            length = struct.unpack(">H", data[i + 2 : i + 4])[0]
            if marker == 0xE1:
                seg = data[i + 4 : i + 2 + length]
                if seg.startswith(b"Exif\x00\x00"):
                    return self._parse_tiff_exif(seg[6:])
            i += 2 + length
        return {}

    def _parse_tiff_exif(self, tiff: bytes) -> Dict[str, Any]:
        if len(tiff) < 8:
            return {}
        endian = "<" if tiff[:2] == b"II" else ">"
        if tiff[2:4] != (b"\x2a\x00" if endian == "<" else b"\x00\x2a"):
            return {}
        (offset,) = struct.unpack(endian + "I", tiff[4:8])
        out: Dict[str, Any] = {}
        self._read_ifd(tiff, endian, offset, out, depth=0)
        return out

    def _read_ifd(self, tiff: bytes, endian: str, offset: int, out: Dict[str, Any], depth: int) -> None:
        if depth > 3 or offset + 2 > len(tiff):
            return
        (count,) = struct.unpack(endian + "H", tiff[offset : offset + 2])
        pos = offset + 2
        for _ in range(count):
            if pos + 12 > len(tiff):
                break
            tag, typ, cnt = struct.unpack(endian + "HHI", tiff[pos : pos + 8])
            val_off = tiff[pos + 8 : pos + 12]
            pos += 12
            name = _EXIF_TAGS.get(tag, f"Tag_0x{tag:04X}")
            type_size = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1}.get(typ, 1)
            nbytes = cnt * type_size
            if nbytes <= 4:
                raw = val_off[:nbytes]
            else:
                (vpos,) = struct.unpack(endian + "I", val_off)
                raw = tiff[vpos : vpos + nbytes]
            if tag in (0x8769, 0x8825) and typ == 4 and len(raw) >= 4:
                (sub,) = struct.unpack(endian + "I", raw[:4])
                self._read_ifd(tiff, endian, sub, out, depth + 1)
                continue
            out[name] = self._decode_value(typ, cnt, raw, endian)
        # GPS IFD values already merged via recursive read into out with Tag_ names;
        # also map common GPS if present under GPSInfo pointer handled above.

    @staticmethod
    def _decode_value(typ: int, cnt: int, raw: bytes, endian: str) -> Any:
        try:
            if typ == 2:  # ASCII
                return raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
            if typ == 3 and cnt == 1:
                return struct.unpack(endian + "H", raw[:2])[0]
            if typ == 4 and cnt == 1:
                return struct.unpack(endian + "I", raw[:4])[0]
            if typ == 5 and cnt >= 1:
                nums = []
                for i in range(min(cnt, 3)):
                    a, b = struct.unpack(endian + "II", raw[i * 8 : i * 8 + 8])
                    nums.append(a / b if b else 0)
                return nums[0] if cnt == 1 else nums
            return raw[:64].hex()
        except (struct.error, ZeroDivisionError, ValueError):
            return raw[:32].hex()

    def _gps_from_exif(self, exif: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        # Lightweight: many GPS fields land as Tag_0x0002 etc. Skip if not structured.
        # If DateTime / Make present, still useful without GPS.
        lat = exif.get("GPSLatitude") or exif.get("Tag_0x0002")
        lon = exif.get("GPSLongitude") or exif.get("Tag_0x0004")
        if not lat or not lon:
            return None
        try:
            def _rat(v):
                if isinstance(v, (int, float)):
                    return float(v)
                if isinstance(v, list) and len(v) >= 3:
                    return float(v[0]) + float(v[1]) / 60 + float(v[2]) / 3600
                return None
            la, lo = _rat(lat), _rat(lon)
            if la is None or lo is None:
                return None
            return {
                "lat": la,
                "lon": lo,
                "maps": f"https://maps.google.com/?q={la},{lo}",
            }
        except (TypeError, ValueError):
            return None
