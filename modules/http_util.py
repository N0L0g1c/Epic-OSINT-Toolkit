"""Shared HTTP session helpers — UA rotation + simple rate limiting."""

from __future__ import annotations

import random
import threading
import time
from typing import Optional

import requests

from modules.net_util import DEFAULT_HEADERS, UA

_USER_AGENTS = [
    UA,
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
]

_lock = threading.Lock()
_last_request = 0.0
_min_interval = 0.0  # seconds between requests (global soft limit)


def set_rate_limit(requests_per_second: float) -> None:
    """0 = unlimited. e.g. 2.0 → at most 2 req/s."""
    global _min_interval
    _min_interval = 0.0 if requests_per_second <= 0 else 1.0 / requests_per_second


def rotate_headers(extra: Optional[dict] = None) -> dict:
    h = dict(DEFAULT_HEADERS)
    h["User-Agent"] = random.choice(_USER_AGENTS)
    if extra:
        h.update(extra)
    return h


def paced_session() -> requests.Session:
    s = requests.Session()
    s.headers.update(rotate_headers())
    return s


def pace() -> None:
    global _last_request
    if _min_interval <= 0:
        return
    with _lock:
        now = time.monotonic()
        wait = _min_interval - (now - _last_request)
        if wait > 0:
            time.sleep(wait)
        _last_request = time.monotonic()
