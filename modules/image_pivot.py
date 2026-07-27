"""Reverse-image search pivot URLs."""

from __future__ import annotations

from typing import Any, Dict
from urllib.parse import quote, quote_plus


class ImagePivotIntel:
    """Generate reverse-image search links for an image URL."""

    def pivots(self, image_url: str) -> Dict[str, Any]:
        url = (image_url or "").strip()
        if not url.startswith(("http://", "https://")):
            return {"error": "Need an http(s) image URL", "url": image_url}
        enc = quote(url, safe="")
        enc_plus = quote_plus(url)
        return {
            "image_url": url,
            "pivots": [
                {"name": "Google Lens", "url": f"https://lens.google.com/uploadbyurl?url={enc}"},
                {"name": "Yandex", "url": f"https://yandex.com/images/search?rpt=imageview&url={enc}"},
                {"name": "TinEye", "url": f"https://tineye.com/search?url={enc}"},
                {"name": "Bing Visual", "url": f"https://www.bing.com/images/search?view=detailv2&iss=sbi&form=SBIVSP&sbisrc=UrlPaste&q=imgurl:{enc}"},
                {"name": "Google Images (legacy)", "url": f"https://www.google.com/searchbyimage?image_url={enc_plus}"},
            ],
            "note": "Open pivots manually — no scraping of reverse-image engines",
        }
