"""Screenshot capture via optional system Chromium/Chrome headless."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from modules.net_util import is_safe_url


class ScreenshotIntel:
    """Capture a page screenshot if chrome/chromium is installed."""

    def capture(self, url: str, output_dir: str = "reports/screenshots") -> Dict[str, Any]:
        if not url.startswith("http"):
            url = f"https://{url}"
        if not is_safe_url(url):
            return {"error": "Blocked or invalid URL", "url": url}

        browser = self._find_browser()
        if not browser:
            return {
                "url": url,
                "error": "No Chrome/Chromium found",
                "hint": "Install google-chrome or chromium for screenshots",
                "pivots": [
                    f"https://www.url2png.com/",
                    f"https://urlscan.io/",
                ],
            }

        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        host = (urlparse(url).hostname or "page").replace(".", "_")[:40]
        dest = out / f"shot_{host}.png"

        cmd = [
            browser,
            "--headless=new",
            "--disable-gpu",
            "--no-sandbox",
            "--window-size=1280,720",
            f"--screenshot={dest}",
            url,
        ]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=45, check=False
            )
            if dest.exists() and dest.stat().st_size > 0:
                return {
                    "url": url,
                    "path": str(dest),
                    "size": dest.stat().st_size,
                    "browser": browser,
                }
            return {
                "url": url,
                "error": "Screenshot failed",
                "stderr": (proc.stderr or "")[:300],
                "code": proc.returncode,
            }
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"url": url, "error": str(exc)}

    @staticmethod
    def _find_browser() -> Optional[str]:
        for name in (
            "google-chrome",
            "google-chrome-stable",
            "chromium",
            "chromium-browser",
            "chrome",
        ):
            path = shutil.which(name)
            if path:
                return path
        return None
