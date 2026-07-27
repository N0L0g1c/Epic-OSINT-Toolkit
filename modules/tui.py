"""
Epic OSINT Toolkit — Interactive Terminal UI
Full-terminal split layout: menu left, feature pane right.
Heavy ASCII/ANSI. Pure stdlib (curses).
"""

from __future__ import annotations

import curses
import io
import json
import re
import threading
import traceback
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from modules.tui_style import Line, format_json_file, format_scan_report

# ── Layout thresholds ─────────────────────────────────────────────────────────

SPLIT_MIN_W = 100
SPLIT_MIN_H = 22
LEFT_W = 36

# ── ASCII art ─────────────────────────────────────────────────────────────────

LOGO_HERO = r"""
 _______ ______ _____ _____
|    ___|   __ \     |     |
|    ___|    __/       |   |---.
|_______|___|  |__|__|_____|___|

.-----.-----.-----.-----.-----.
|  _  |__ --|__ --|__ --|__ --|
|_____|_____|_____|_____|_____|

[>=======  O S I N T   T O O L K I T  =======<]
          .:: keyboard recon suite ::.
""".strip("\n")

LOGO_HERO_WIDE = r"""
################################################################
##                                                            ##
##     _______ ______ _____ _____                             ##
##    |    ___|   __ \     |     |                            ##
##    |    ___|    __/       |   |---.                        ##
##    |_______|___|  |__|__|_____|___|                        ##
##                                                            ##
##     .-----.-----.-----.-----.-----.                        ##
##     |  _  |__ --|__ --|__ --|__ --|                        ##
##     |_____|_____|_____|_____|_____|                        ##
##                                                            ##
##         [>=======  O S I N T   T O O L K I T  =======<]    ##
##                   .:: keyboard recon suite ::.             ##
##                                                            ##
##     select a module on the left to begin                   ##
##                                                            ##
################################################################
""".strip("\n")

BANNER_STACKED = r"""
 ##############################################################
 ##  _____ ____ ___ ____    ____ ____ ___ _  _ ___           ##
 ##  |___  |__]  |  |       |  | [__   |  |\ |  |            ##
 ##  |___  |     |  |___    |__| ___]  |  | \|  |            ##
 ##         [>====  OSINT TOOLKIT  ====<]                    ##
 ##############################################################
""".strip("\n")

HELP_FOOTER = "##  Up/Down  |  Enter open  |  Esc/q back  ##"
_TARGET_RE = re.compile(r"^[\w.\-:@/+#%=&?, ]{1,256}$", re.UNICODE)

Rect = Tuple[int, int, int, int]  # y, x, h, w


def _sanitize_target(raw: str) -> Optional[str]:
    value = (raw or "").strip()
    if not value or not _TARGET_RE.match(value):
        return None
    if ".." in value or value.startswith("-"):
        return None
    if value.startswith("/") and not value.startswith(("http://", "https://")):
        return None
    return value


class Theme:
    NORMAL = 0
    TITLE = 1
    HIGHLIGHT = 2
    DIM = 3
    SUCCESS = 4
    WARN = 5
    ERROR = 6
    BORDER = 7
    INPUT = 8
    ACCENT = 9
    SECTION = 10


def _init_colors() -> None:
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(Theme.TITLE, curses.COLOR_GREEN, -1)
    curses.init_pair(Theme.HIGHLIGHT, curses.COLOR_BLACK, curses.COLOR_GREEN)
    curses.init_pair(Theme.DIM, curses.COLOR_WHITE, -1)
    curses.init_pair(Theme.SUCCESS, curses.COLOR_GREEN, -1)
    curses.init_pair(Theme.WARN, curses.COLOR_YELLOW, -1)
    curses.init_pair(Theme.ERROR, curses.COLOR_RED, -1)
    curses.init_pair(Theme.BORDER, curses.COLOR_GREEN, -1)
    curses.init_pair(Theme.INPUT, curses.COLOR_BLACK, curses.COLOR_CYAN)
    curses.init_pair(Theme.ACCENT, curses.COLOR_CYAN, -1)
    curses.init_pair(Theme.SECTION, curses.COLOR_YELLOW, -1)


def _attr(pair: int, bold: bool = False) -> int:
    a = curses.color_pair(pair)
    if bold:
        a |= curses.A_BOLD
    return a


_STYLE_MAP = {
    "header": (Theme.TITLE, True),
    "section": (Theme.SECTION, True),
    "rule": (Theme.BORDER, False),
    "key": (Theme.ACCENT, False),
    "val": (Theme.NORMAL, False),
    "bullet": (Theme.SUCCESS, False),
    "ok": (Theme.SUCCESS, True),
    "warn": (Theme.WARN, True),
    "err": (Theme.ERROR, True),
    "dim": (Theme.DIM, False),
    "meta": (Theme.TITLE, False),
    "blank": (Theme.NORMAL, False),
}


def _style_attr(style: str) -> int:
    pair, bold = _STYLE_MAP.get(style, (Theme.NORMAL, False))
    return _attr(pair, bold)


MenuItem = Tuple[str, str, str]

MAIN_MENU: List[MenuItem] = [
    ("auto", "Auto Scan", "Detect type + full suite"),
    ("full", "Full Scan", "Multi-module scan"),
    ("domain", "Domain Intel", "DNS WHOIS SSL DMARC"),
    ("ip", "IP Intel", "Geo ASN rDNS risk"),
    ("asn", "ASN / Netblocks", "Prefixes peers upstreams"),
    ("related", "Related Domains", "CT SSL same-IP pivots"),
    ("passive", "Passive DNS", "Historical host/IP"),
    ("abuse", "Abuse / DNSBL", "Reputation lists"),
    ("ioc", "IOC Enrich", "VT / OTX / pivots"),
    ("crypto", "Web3 / Crypto", "Wallet ENS tx risk"),
    ("social", "Social Media", "100+ username matrix"),
    ("perms", "Username Perms", "Name/email permutations"),
    ("github", "GitHub", "Profile repos emails"),
    ("crawl", "Web Crawler", "Crawl extract tech"),
    ("jssecrets", "JS Secrets", "Keys paths endpoints"),
    ("screenshot", "Screenshot", "Headless Chrome capture"),
    ("emails", "Email Discover", "Find verify sources"),
    ("emailacct", "Email Accounts", "Holehe-style checks"),
    ("urls", "URL Hunter", "Shorteners Wayback"),
    ("wayback", "Wayback", "Archive.org CDX"),
    ("pastes", "Paste / Leaks", "GitHub code dorks"),
    ("dorks", "Dork Generator", "Google/DDG/Bing packs"),
    ("buckets", "Cloud Buckets", "S3 GCS Azure Spaces"),
    ("takeover", "Takeover Check", "Dangling DNS fingerprints"),
    ("favicon", "Favicon Hash", "mmh3 + Shodan pivot"),
    ("meta", "EXIF / Meta", "Image/PDF metadata"),
    ("imgpivot", "Image Pivots", "Reverse-image URLs"),
    ("phone", "Phone OSINT", "E164 pivots leaks"),
    ("ports", "Port Scanner", "Open ports banners"),
    ("host", "Shodan/Censys", "Host intel APIs"),
    ("employees", "Employees", "Staff + HIBP leaks"),
    ("darkweb", "Dark Web", ".onion analyze"),
    ("onionsearch", "Onion Search", "Ahmia directory"),
    ("torcheck", "Tor Health", "SOCKS proxy check"),
    ("graph", "Graph Export", "JSON + GraphML"),
    ("cases", "Cases", "Investigation folders"),
    ("plugins", "Plugins", "User drop-in modules"),
    ("reports", "Reports", "View / delete saves"),
    ("settings", "Settings", "Format Tor API keys"),
    ("quit", "Quit", "Exit toolkit"),
]

FULL_TYPES = ["domain", "username", "company", "ip", "email", "phone", "onion", "wallet"]
DOMAIN_OPTS = [("dns", "DNS enumeration", True), ("subdomains", "Subdomain discovery", True),
               ("whois", "WHOIS lookup", True), ("ssl", "SSL certificate analysis", True)]
SOCIAL_OPTS = [("search", "Platform search", True), ("email", "Email discovery", True),
               ("associated", "Associated accounts", True)]
GITHUB_OPTS = [("profile", "Profile analysis", True), ("repos", "Repository analysis", True),
               ("email", "Email discovery", True), ("creation", "Creation date", True)]
CRAWL_OPTS = [("crawl", "Page crawl", True), ("directories", "Directory enumeration", True),
              ("tech", "Technology detection", True), ("extract", "Info extraction", True),
              ("comprehensive", "Comprehensive (creepyCrawler)", False),
              ("robots", "Parse robots.txt", True), ("sitemap", "Parse sitemap.xml", True)]
EMAIL_OPTS = [("discover", "Discover emails", True), ("verify", "Verify emails", False),
              ("sources", "Find sources", True)]
URL_OPTS = [("hunt", "Shortened URL hunt", True), ("exposed", "Exposed URL search", True),
            ("urlteam", "URLTeam archives", False)]
PORT_OPTS = [("scan", "Port scan", True)]
EMPLOYEE_OPTS = [("discover", "Discover employees", True), ("check_leaks", "Check credential leaks", True)]
DARKWEB_OPTS = [("analyze", "Analyze .onion", True), ("crawl", "Crawl .onion", False),
                ("map_links", "Map link relationships", False)]


class EpicTUI:
    """Split-pane keyboard OSINT interface."""

    def __init__(self, toolkit: Any):
        self.toolkit = toolkit
        self.settings: Dict[str, Any] = {
            "format": "json",
            "output_dir": str(toolkit.output_dir),
            "use_tor": False,
            "depth": 2,
            "max_pages": 100,
            "ports_range": "common",
            "github_token": "",
            "shodan_key": "",
            "censys_id": "",
            "censys_secret": "",
            "vt_key": "",
            "otx_key": "",
            "etherscan_key": "",
            "rate_limit": "0",
        }
        self.last_results: Optional[Dict] = None
        self.last_filepath: Optional[str] = None
        self.status_msg = ""
        self._stdscr: Optional[Any] = None
        self.menu_idx = 0
        self.panel_title = "HOME"
        self._content: Optional[Rect] = None  # active right/full content rect

    def run(self) -> None:
        curses.wrapper(self._main)

    def _main(self, stdscr) -> None:
        self._stdscr = stdscr
        curses.curs_set(0)
        stdscr.keypad(True)
        stdscr.timeout(-1)
        try:
            curses.curs_set(0)
            # Prefer full terminal; ignore SIGWINCH mid-draw errors
        except curses.error:
            pass
        _init_colors()
        self._screen_main_menu()

    # ── geometry ──────────────────────────────────────────────────────────────

    def _size(self) -> Tuple[int, int]:
        return self._stdscr.getmaxyx()

    def _use_split(self) -> bool:
        h, w = self._size()
        return w >= SPLIT_MIN_W and h >= SPLIT_MIN_H

    def _layout(self) -> Tuple[bool, Optional[Rect], Rect]:
        """Return (split, left_rect|None, content_rect). Content is right pane or full."""
        h, w = self._size()
        foot = 2
        body_h = max(5, h - foot)
        if self._use_split():
            left_w = min(LEFT_W, max(28, w // 3))
            left = (0, 0, body_h, left_w)
            right = (0, left_w, body_h, w - left_w)
            return True, left, right
        return False, None, (0, 0, body_h, w)

    def _inner(self, rect: Rect, title: str = "") -> Rect:
        """Inner drawable area inside a bordered panel."""
        y, x, h, w = rect
        # border uses 1 cell each side; title on top border
        return (y + 2, x + 2, max(1, h - 3), max(1, w - 4))

    # ── primitives ────────────────────────────────────────────────────────────

    def _safe_addstr(self, y: int, x: int, text: str, attr: int = 0) -> None:
        h, w = self._size()
        if y < 0 or y >= h or x >= w or x < 0:
            return
        text = text[: max(0, w - x - 1)]
        try:
            self._stdscr.addstr(y, x, text, attr)
        except curses.error:
            pass

    def _clear(self) -> None:
        self._stdscr.erase()

    def _hline(self, y: int, x: int, width: int, char: str = "#") -> None:
        self._safe_addstr(y, x, char * max(0, width), _attr(Theme.BORDER))

    def _draw_box(self, rect: Rect, title: str = "") -> None:
        y, x, h, w = rect
        if h < 2 or w < 4:
            return
        self._safe_addstr(y, x, "#" + ("=" * (w - 2)) + "#", _attr(Theme.BORDER, True))
        for i in range(1, h - 1):
            self._safe_addstr(y + i, x, "#", _attr(Theme.BORDER))
            self._safe_addstr(y + i, x + w - 1, "#", _attr(Theme.BORDER))
            # clear interior lightly for clean panel
            self._safe_addstr(y + i, x + 1, " " * (w - 2), 0)
        self._safe_addstr(y + h - 1, x, "#" + ("=" * (w - 2)) + "#", _attr(Theme.BORDER, True))
        if title:
            t = f"[ {title} ]"
            self._safe_addstr(y, x + 2, t[: w - 4], _attr(Theme.TITLE, True))

    def _footer(self, text: str = HELP_FOOTER) -> None:
        h, w = self._size()
        self._hline(h - 2, 0, w - 1, "#")
        msg = text
        if self.status_msg:
            msg = f"##  {self.status_msg}  ##"
            self.status_msg = ""
        self._safe_addstr(h - 1, 1, msg[: w - 2], _attr(Theme.DIM))

    def _draw_left_menu(self, left: Rect, idx: int) -> None:
        y, x, h, w = left
        self._draw_box(left, "MODULES")
        iy, ix, ih, iw = self._inner(left)
        self._safe_addstr(iy, ix, "EPIC OSINT", _attr(Theme.SUCCESS, True))
        self._safe_addstr(iy + 1, ix, "-" * min(iw, 20), _attr(Theme.BORDER))
        visible = max(1, ih - 3)
        start = max(0, min(idx - visible // 2, max(0, len(MAIN_MENU) - visible)))
        for i, (_, label, _) in enumerate(MAIN_MENU[start : start + visible]):
            n = start + i
            row = iy + 2 + i
            selected = n == idx
            num = f"{n + 1:02d}"
            if selected:
                line = f">:[{num}] {label}"
                attr = _attr(Theme.HIGHLIGHT, True)
            else:
                line = f"  [{num}] {label}"
                attr = _attr(Theme.NORMAL)
            self._safe_addstr(row, ix, line.ljust(min(iw, w - 4))[:iw], attr)

    def _draw_logo(self, rect: Rect) -> None:
        """Big centered logo in the content pane."""
        self._draw_box(rect, "EPIC OSINT TOOLKIT")
        iy, ix, ih, iw = self._inner(rect)
        art = LOGO_HERO_WIDE if iw >= 66 and ih >= 18 else LOGO_HERO
        lines = art.splitlines()
        # center block
        top = iy + max(0, (ih - len(lines)) // 2)
        for i, line in enumerate(lines):
            if i >= ih:
                break
            x = ix + max(0, (iw - len(line)) // 2)
            style = _attr(Theme.TITLE, True)
            if "OSINT" in line or "TOOLKIT" in line or "EPIC" in line:
                style = _attr(Theme.SUCCESS, True)
            elif line.strip().startswith("#"):
                style = _attr(Theme.BORDER)
            elif "select" in line.lower():
                style = _attr(Theme.DIM)
            self._safe_addstr(top + i, x, line[:iw], style)

    def _paint_shell(self, right_title: str = "HOME", logo: bool = False) -> Rect:
        """
        Draw full-terminal chrome. Returns content inner rect for drawing.
        In split mode: left menu + right panel. Else: stacked full panel.
        """
        self._clear()
        split, left, content = self._layout()
        if split and left:
            self._draw_left_menu(left, self.menu_idx)
            if logo or right_title == "HOME":
                self._draw_logo(content)
                self._content = self._inner(content)
            else:
                self._draw_box(content, right_title)
                self._content = self._inner(content)
        else:
            # stacked: optional mini banner above content
            y, x, h, w = content
            if logo or right_title == "HOME":
                # use full area for logo
                self._draw_logo(content)
                self._content = self._inner(content)
            else:
                # small banner then panel
                blines = BANNER_STACKED.splitlines()
                for i, line in enumerate(blines[: max(0, h // 4)]):
                    self._safe_addstr(y + i, max(0, (w - len(line)) // 2), line, _attr(Theme.TITLE, True))
                used = min(len(blines), max(0, h // 4))
                panel = (y + used, x, h - used, w)
                self._draw_box(panel, right_title)
                self._content = self._inner(panel)
        self.panel_title = right_title
        return self._content

    def _content_write(self, row: int, col: int, text: str, attr: int = 0) -> None:
        if not self._content:
            return
        y, x, h, w = self._content
        if row < 0 or row >= h:
            return
        self._safe_addstr(y + row, x + col, text[: max(0, w - col)], attr)

    def _content_size(self) -> Tuple[int, int]:
        if not self._content:
            return self._size()
        _, _, h, w = self._content
        return h, w

    # ── widgets (content-pane aware) ──────────────────────────────────────────

    def _prompt_input(
        self, row: int, col: int, width: int, initial: str = "", label: str = ""
    ) -> Optional[str]:
        curses.curs_set(1)
        buf = list(initial)
        pos = len(buf)
        cy, cx, _, cw = self._content if self._content else (0, 0, 0, width)
        try:
            while True:
                field = "".join(buf)
                display = field[max(0, pos - width + 1) :][:width]
                pad = " " * (width - len(display))
                if label:
                    self._content_write(row, col, label, _attr(Theme.ACCENT, True))
                    fx = col + len(label)
                else:
                    fx = col
                self._content_write(row, fx, display + pad, _attr(Theme.INPUT))
                try:
                    self._stdscr.move(cy + row, cx + fx + min(pos, width - 1))
                except curses.error:
                    pass
                self._stdscr.refresh()
                ch = self._stdscr.get_wch()
                if ch in ("\n", "\r", curses.KEY_ENTER):
                    return "".join(buf)
                if ch == "\x1b" or ch == curses.KEY_EXIT:
                    return None
                if ch in (curses.KEY_BACKSPACE, "\x7f", "\b"):
                    if pos > 0:
                        del buf[pos - 1]
                        pos -= 1
                elif ch == curses.KEY_LEFT:
                    pos = max(0, pos - 1)
                elif ch == curses.KEY_RIGHT:
                    pos = min(len(buf), pos + 1)
                elif ch == curses.KEY_HOME:
                    pos = 0
                elif ch == curses.KEY_END:
                    pos = len(buf)
                elif ch == curses.KEY_DC:
                    if pos < len(buf):
                        del buf[pos]
                elif isinstance(ch, str) and ch.isprintable() and len(buf) < 256:
                    buf.insert(pos, ch)
                    pos += 1
        finally:
            curses.curs_set(0)

    def _select_list(
        self, title: str, items: List[MenuItem], banner: bool = True
    ) -> Optional[str]:
        """Sub-menu inside the right/content pane (keeps left menu in split mode)."""
        idx = 0
        while True:
            self._paint_shell(title, logo=False)
            ch_, cw = self._content_size()
            self._content_write(0, 0, "Up/Down select · Enter confirm · Esc back", _attr(Theme.DIM))
            visible = max(1, ch_ - 3)
            start = max(0, min(idx - visible // 2, max(0, len(items) - visible)))
            for i, (_, label, desc) in enumerate(items[start : start + visible]):
                n = start + i
                selected = n == idx
                num = f"{n + 1:02d}"
                if selected:
                    line = f"  >:: [{num}] {label}"
                    attr = _attr(Theme.HIGHLIGHT, True)
                else:
                    line = f"      [{num}] {label}"
                    attr = _attr(Theme.NORMAL)
                self._content_write(2 + i, 0, line.ljust(min(40, cw)), attr)
                if selected and desc:
                    self._content_write(2 + i, min(42, cw // 2), f":: {desc}"[: cw // 2], _attr(Theme.DIM))
            self._footer(f"##  {title}  |  Esc back  ##")
            self._stdscr.refresh()
            ch = self._stdscr.getch()
            if ch in (curses.KEY_UP, ord("k")):
                idx = (idx - 1) % len(items)
            elif ch in (curses.KEY_DOWN, ord("j")):
                idx = (idx + 1) % len(items)
            elif ch in (curses.KEY_ENTER, ord("\n"), ord("\r"), ord(" ")):
                return items[idx][0]
            elif ch in (27, ord("q"), ord("Q")):
                return None
            elif ord("1") <= ch <= ord("9"):
                n = ch - ord("1")
                if n < len(items):
                    return items[n][0]

    def _toggle_options(
        self,
        title: str,
        options: List[Tuple[str, str, bool]],
        extra_fields: Optional[List[Tuple[str, str, str]]] = None,
    ) -> Optional[Dict[str, Any]]:
        opts = {k: v for k, _, v in options}
        labels = {k: lab for k, lab, _ in options}
        fields = {k: default for k, _, default in (extra_fields or [])}
        field_labels = {k: lab for k, lab, _ in (extra_fields or [])}
        keys = [k for k, _, _ in options] + [k for k, _, _ in (extra_fields or [])]
        idx = 0
        editing = False

        while True:
            self._paint_shell(title, logo=False)
            ch_, cw = self._content_size()
            self._content_write(0, 0, "Space toggle | Enter edit/run | Esc cancel", _attr(Theme.DIM))
            for i, key in enumerate(keys):
                selected = i == idx
                if key in opts:
                    mark = "[#]" if opts[key] else "[ ]"
                    line = f" {mark}  {labels[key]}"
                else:
                    val = fields[key]
                    shown = val if len(val) <= 36 else val[:33] + "..."
                    line = f"  > {field_labels[key]}: {shown}"
                attr = _attr(Theme.HIGHLIGHT, True) if selected else _attr(Theme.NORMAL)
                self._content_write(2 + i, 0, line.ljust(min(60, cw)), attr)

            cy = 2 + len(keys) + 1
            for j, lab in enumerate((">>:: RUN SCAN", "    Cancel")):
                sel = idx == len(keys) + j
                attr = _attr(Theme.HIGHLIGHT, True) if sel else _attr(Theme.SUCCESS if j == 0 else Theme.DIM)
                self._content_write(cy + j, 0, lab, attr)

            self._footer("##  Space toggle  |  Enter  |  Esc  ##")
            self._stdscr.refresh()

            if editing and keys[idx] in fields:
                new_val = self._prompt_input(
                    2 + idx, 4 + len(field_labels[keys[idx]]),
                    min(36, cw - 20), fields[keys[idx]],
                )
                if new_val is not None:
                    fields[keys[idx]] = new_val.strip()
                editing = False
                continue

            ch = self._stdscr.getch()
            total = len(keys) + 2
            if ch in (curses.KEY_UP, ord("k")):
                idx = (idx - 1) % total
            elif ch in (curses.KEY_DOWN, ord("j")):
                idx = (idx + 1) % total
            elif ch == ord(" "):
                if idx < len(keys) and keys[idx] in opts:
                    opts[keys[idx]] = not opts[keys[idx]]
            elif ch in (curses.KEY_ENTER, ord("\n"), ord("\r")):
                if idx == len(keys):
                    result = dict(opts)
                    result.update(fields)
                    return result
                if idx == len(keys) + 1:
                    return None
                if keys[idx] in fields:
                    editing = True
                elif keys[idx] in opts:
                    opts[keys[idx]] = not opts[keys[idx]]
            elif ch in (27, ord("q")):
                return None

    def _ask_target(self, prompt: str = "Target") -> Optional[str]:
        self._paint_shell("TARGET INPUT", logo=False)
        self._content_write(0, 0, prompt, _attr(Theme.ACCENT, True))
        self._content_write(1, 0, "Type value, Enter confirm, Esc cancel", _attr(Theme.DIM))
        self._footer()
        self._stdscr.refresh()
        _, cw = self._content_size()
        raw = self._prompt_input(3, 0, min(56, cw - 2), "", "> ")
        if raw is None:
            return None
        clean = _sanitize_target(raw)
        if not clean:
            self.status_msg = "Invalid target"
            return None
        return clean

    def _confirm(self, message: str) -> bool:
        self._paint_shell("CONFIRM", logo=False)
        self._content_write(1, 0, message, _attr(Theme.WARN, True))
        self._content_write(3, 0, "[Y] Yes, delete     [N] Cancel", _attr(Theme.ACCENT))
        self._content_write(5, 0, "This cannot be undone.", _attr(Theme.DIM))
        self._footer("##  Y confirm  |  N / Esc cancel  ##")
        self._stdscr.refresh()
        while True:
            ch = self._stdscr.getch()
            if ch in (ord("y"), ord("Y"), curses.KEY_ENTER, ord("\n"), ord("\r")):
                return True
            if ch in (ord("n"), ord("N"), 27, ord("q")):
                return False

    def _scroll_styled(self, title: str, lines: List[Line]) -> None:
        offset = 0
        while True:
            self._paint_shell(title, logo=False)
            ch_, cw = self._content_size()
            view_h = max(1, ch_ - 2)
            for i in range(view_h):
                li = offset + i
                if li >= len(lines):
                    break
                text, style = lines[li]
                self._content_write(i, 0, text[:cw], _style_attr(style))
            total = max(1, len(lines))
            pct = int((offset + 1) / total * 100)
            self._footer(f"##  {title}  line {offset + 1}/{total} ({pct}%)  |  Esc back  ##")
            self._stdscr.refresh()
            ch = self._stdscr.getch()
            if ch in (27, ord("q")):
                return
            elif ch in (curses.KEY_UP, ord("k")):
                offset = max(0, offset - 1)
            elif ch in (curses.KEY_DOWN, ord("j")):
                offset = min(max(0, len(lines) - view_h), offset + 1)
            elif ch == curses.KEY_PPAGE:
                offset = max(0, offset - view_h)
            elif ch == curses.KEY_NPAGE:
                offset = min(max(0, len(lines) - view_h), offset + view_h)
            elif ch == curses.KEY_HOME:
                offset = 0
            elif ch == curses.KEY_END:
                offset = max(0, len(lines) - view_h)

    def _scroll_text(self, title: str, text: Union[str, List[Line]]) -> None:
        if isinstance(text, list):
            self._scroll_styled(title, text)
            return
        self._scroll_styled(title, [(ln, "val") for ln in (text.splitlines() or [""])])

    def _run_with_spinner(self, label: str, fn: Callable[[], Any]) -> Any:
        result: Dict[str, Any] = {"value": None, "error": None, "log": ""}
        done = threading.Event()
        log_buf = io.StringIO()

        def worker() -> None:
            try:
                with redirect_stdout(log_buf), redirect_stderr(log_buf):
                    result["value"] = fn()
            except Exception as exc:
                result["error"] = exc
                result["trace"] = traceback.format_exc()
            finally:
                result["log"] = log_buf.getvalue()
                done.set()

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        frames = ("[*    ]", "[ *   ]", "[  *  ]", "[   * ]", "[    *]", "[   * ]", "[  *  ]", "[ *   ]")
        radar = ("|", "/", "-", "\\")
        i = 0
        self._stdscr.timeout(100)
        try:
            while not done.is_set():
                self._paint_shell("SCANNING", logo=False)
                frame = frames[i % len(frames)]
                spin = radar[i % len(radar)]
                self._content_write(1, 0, f" {spin}  {frame}  {label}", _attr(Theme.WARN, True))
                self._content_write(3, 0, "################################", _attr(Theme.BORDER))
                self._content_write(4, 0, "#  RECON IN PROGRESS...        #", _attr(Theme.TITLE, True))
                self._content_write(5, 0, "################################", _attr(Theme.BORDER))
                log_lines = result.get("log") or log_buf.getvalue()
                last = log_lines.strip().splitlines()[-1] if log_lines.strip() else ""
                if last:
                    _, cw = self._content_size()
                    self._content_write(7, 0, f"> {last}"[:cw], _attr(Theme.DIM))
                self._footer("##  Please wait — cancel mid-scan not supported  ##")
                self._stdscr.refresh()
                self._stdscr.getch()
                i += 1
        finally:
            self._stdscr.timeout(-1)
        thread.join(timeout=0.1)
        if result["error"] is not None:
            raise result["error"]
        return result["value"]

    def _show_results(self, results: Dict) -> None:
        if "correlation" not in results:
            try:
                results["correlation"] = self.toolkit.correlate_results(results)
            except Exception:
                pass
        self.last_results = results
        path = None
        try:
            path = self.toolkit.save_results(results, self.settings["format"])
            self.last_filepath = path
            self.toolkit.output_dir = Path(self.settings["output_dir"])
        except OSError as exc:
            self.status_msg = f"Save failed: {exc}"
        self._scroll_styled("INTEL REPORT", format_scan_report(results, saved_path=path))

    # ── main menu (split-aware) ───────────────────────────────────────────────

    def _screen_main_menu(self) -> None:
        while True:
            if self._use_split():
                self._paint_shell("HOME", logo=True)
                _, _, desc = MAIN_MENU[self.menu_idx]
                self._footer(
                    f"##  [{self.menu_idx + 1:02d}] {MAIN_MENU[self.menu_idx][1]}  —  {desc}  |  Enter open  |  q quit  ##"
                )
            else:
                self._paint_shell("MAIN MENU", logo=False)
                ch_, cw = self._content_size()
                visible = max(1, ch_ - 2)
                start = max(
                    0,
                    min(self.menu_idx - visible // 2, max(0, len(MAIN_MENU) - visible)),
                )
                for i, (_, label, desc) in enumerate(MAIN_MENU[start : start + visible]):
                    n = start + i
                    selected = n == self.menu_idx
                    num = f"{n + 1:02d}"
                    if selected:
                        self._content_write(
                            i, 0,
                            f"  >:: [{num}] {label}".ljust(min(36, cw)),
                            _attr(Theme.HIGHLIGHT, True),
                        )
                        self._content_write(
                            i, min(38, cw // 2), f":: {desc}"[: cw // 2], _attr(Theme.DIM)
                        )
                    else:
                        self._content_write(i, 0, f"      [{num}] {label}", _attr(Theme.NORMAL))
                self._footer("##  Up/Down  |  Enter open  |  q quit  ##")
            self._stdscr.refresh()

            ch = self._stdscr.getch()
            if ch in (curses.KEY_UP, ord("k")):
                self.menu_idx = (self.menu_idx - 1) % len(MAIN_MENU)
            elif ch in (curses.KEY_DOWN, ord("j")):
                self.menu_idx = (self.menu_idx + 1) % len(MAIN_MENU)
            elif ch in (curses.KEY_RESIZE,):
                continue
            elif ch in (ord("q"), ord("Q"), 27):
                return
            elif ch in (curses.KEY_ENTER, ord("\n"), ord("\r"), ord(" ")):
                choice = MAIN_MENU[self.menu_idx][0]
                if choice == "quit":
                    return
                self._dispatch(choice)
            elif ord("1") <= ch <= ord("9"):
                n = ch - ord("1")
                if n < len(MAIN_MENU):
                    self.menu_idx = n
                    choice = MAIN_MENU[n][0]
                    if choice == "quit":
                        return
                    self._dispatch(choice)

    def _dispatch(self, choice: str) -> None:
        dispatch = {
            "auto": self._screen_auto,
            "full": self._screen_full,
            "domain": self._screen_domain,
            "ip": self._screen_ip,
            "asn": self._screen_asn,
            "related": self._screen_related,
            "passive": self._screen_passive,
            "abuse": self._screen_abuse,
            "ioc": self._screen_ioc,
            "crypto": self._screen_crypto,
            "social": self._screen_social,
            "perms": self._screen_perms,
            "github": self._screen_github,
            "crawl": self._screen_crawl,
            "jssecrets": self._screen_jssecrets,
            "screenshot": self._screen_screenshot,
            "emails": self._screen_emails,
            "emailacct": self._screen_email_accounts,
            "urls": self._screen_urls,
            "wayback": self._screen_wayback,
            "pastes": self._screen_pastes,
            "dorks": self._screen_dorks,
            "buckets": self._screen_buckets,
            "takeover": self._screen_takeover,
            "favicon": self._screen_favicon,
            "meta": self._screen_meta,
            "imgpivot": self._screen_imgpivot,
            "phone": self._screen_phone,
            "ports": self._screen_ports,
            "host": self._screen_host,
            "employees": self._screen_employees,
            "darkweb": self._screen_darkweb,
            "onionsearch": self._screen_onion_search,
            "torcheck": self._screen_tor_check,
            "graph": self._screen_graph,
            "cases": self._screen_cases,
            "plugins": self._screen_plugins,
            "reports": self._screen_reports,
            "settings": self._screen_settings,
        }
        handler = dispatch.get(choice)
        if handler:
            handler()

    def _apply_api_keys(self) -> None:
        from modules.host_intel import HostIntel
        from modules.paste_intel import PasteIntel
        from modules.email_intel import EmailIntel
        from modules.ioc_intel import IOCIntel
        from modules.crypto_intel import CryptoIntel
        from modules.http_util import set_rate_limit
        tok = self.settings.get("github_token") or None
        if tok:
            self.toolkit.github_token = tok
            self.toolkit.paste_intel = PasteIntel(github_token=tok)
            self.toolkit.email_intel = EmailIntel(github_token=tok)
        self.toolkit.host_intel = HostIntel(
            shodan_key=self.settings.get("shodan_key") or None,
            censys_id=self.settings.get("censys_id") or None,
            censys_secret=self.settings.get("censys_secret") or None,
        )
        self.toolkit.ioc_intel = IOCIntel(
            vt_key=self.settings.get("vt_key") or None,
            otx_key=self.settings.get("otx_key") or None,
        )
        self.toolkit.crypto_intel = CryptoIntel(
            etherscan_key=self.settings.get("etherscan_key") or None,
        )
        try:
            rl = float(self.settings.get("rate_limit") or 0)
            if rl > 0:
                set_rate_limit(rl)
        except ValueError:
            pass

    def _apply_tor(self) -> None:
        if self.settings.get("use_tor"):
            from modules.dark_web_intel import DarkWebIntel
            self.toolkit.dark_web_intel = DarkWebIntel(use_tor=True)

    # ── feature screens ───────────────────────────────────────────────────────

    def _screen_auto(self) -> None:
        target = self._ask_target("Target (any type)")
        if not target:
            return
        try:
            results = self._run_with_spinner(
                f"Auto scan -> {target}",
                lambda: self.toolkit.run_auto_scan(target),
            )
            self._show_results(results)
        except Exception as exc:
            self._scroll_text("Error", [(str(exc), "err")] + [(ln, "dim") for ln in traceback.format_exc().splitlines()])

    def _screen_full(self) -> None:
        type_items = [(t, t.capitalize(), f"Full {t} scan") for t in FULL_TYPES]
        scan_type = self._select_list("Full Scan — type", type_items)
        if not scan_type:
            return
        target = self._ask_target(f"Target ({scan_type})")
        if not target:
            return
        try:
            results = self._run_with_spinner(
                f"Full {scan_type} -> {target}",
                lambda: self.toolkit.run_full_scan(target, scan_type),
            )
            self._show_results(results)
        except Exception as exc:
            self._scroll_text("Error", f"{exc}\n\n{traceback.format_exc()}")

    def _screen_domain(self) -> None:
        target = self._ask_target("Domain")
        if not target:
            return
        opts = self._toggle_options("Domain Intelligence", DOMAIN_OPTS)
        if not opts:
            return
        try:
            data = self._run_with_spinner(f"Domain -> {target}", lambda: self.toolkit.gather_domain_intel(target, opts))
            self._show_results(self._wrap(target, "domain", {"domain": data}))
        except Exception as exc:
            self._scroll_text("Error", str(exc))

    def _screen_social(self) -> None:
        target = self._ask_target("Username")
        if not target:
            return
        opts = self._toggle_options("Social Media", SOCIAL_OPTS)
        if not opts:
            return
        try:
            data = self._run_with_spinner(f"Social -> {target}", lambda: self.toolkit.gather_social_intel(target, opts))
            self._show_results(self._wrap(target, "username", {"social": data}))
        except Exception as exc:
            self._scroll_text("Error", str(exc))

    def _screen_github(self) -> None:
        target = self._ask_target("GitHub username")
        if not target:
            return
        opts = self._toggle_options("GitHub", GITHUB_OPTS)
        if not opts:
            return
        try:
            data = self._run_with_spinner(f"GitHub -> {target}", lambda: self.toolkit.gather_github_intel(target, opts))
            self._show_results(self._wrap(target, "username", {"github": data}))
        except Exception as exc:
            self._scroll_text("Error", str(exc))

    def _screen_crawl(self) -> None:
        target = self._ask_target("URL or domain")
        if not target:
            return
        extras = [("depth", "Crawl depth", str(self.settings["depth"])),
                  ("max_pages", "Max pages", str(self.settings["max_pages"]))]
        opts = self._toggle_options("Web Crawler", CRAWL_OPTS, extras)
        if not opts:
            return
        url = target if target.startswith("http") else f"https://{target}"
        try:
            depth = int(opts.pop("depth", self.settings["depth"]) or 2)
            max_pages = int(opts.pop("max_pages", self.settings["max_pages"]) or 100)
        except ValueError:
            depth, max_pages = 2, 100
        opts["depth"] = max(1, min(depth, 5))
        opts["max_pages"] = max(1, min(max_pages, 500))
        opts["extract_all"] = bool(opts.get("comprehensive"))
        try:
            data = self._run_with_spinner(f"Crawl -> {url}", lambda: self.toolkit.crawl_website(url, opts))
            self._show_results(self._wrap(target, "url", {"website": data}))
        except Exception as exc:
            self._scroll_text("Error", str(exc))

    def _screen_emails(self) -> None:
        target = self._ask_target("Domain")
        if not target:
            return
        opts = self._toggle_options("Email Discovery", EMAIL_OPTS)
        if not opts:
            return
        try:
            data = self._run_with_spinner(f"Emails -> {target}", lambda: self.toolkit.discover_emails(target, opts))
            self._show_results(self._wrap(target, "domain", {"emails": data}))
        except Exception as exc:
            self._scroll_text("Error", str(exc))

    def _screen_urls(self) -> None:
        target = self._ask_target("Domain")
        if not target:
            return
        opts = self._toggle_options("URL Hunter", URL_OPTS)
        if not opts:
            return
        opts["keywords"] = [target]
        opts["date"] = "latest"
        try:
            data = self._run_with_spinner(f"URLs -> {target}", lambda: self.toolkit.hunt_urls(target, opts))
            self._show_results(self._wrap(target, "domain", {"urls": data}))
        except Exception as exc:
            self._scroll_text("Error", str(exc))

    def _screen_ip(self) -> None:
        target = self._ask_target("IP or hostname")
        if not target:
            return
        try:
            data = self._run_with_spinner(f"IP -> {target}", lambda: self.toolkit.analyze_ip(target, {}))
            self._show_results(self._wrap(target, "ip", {"ip": data}))
        except Exception as exc:
            self._scroll_text("Error", str(exc))

    def _screen_asn(self) -> None:
        target = self._ask_target("IP or ASN (AS15169)")
        if not target:
            return
        try:
            data = self._run_with_spinner(f"ASN -> {target}", lambda: self.toolkit.analyze_asn(target))
            self._show_results(self._wrap(target, "asn", {"asn": data}))
        except Exception as exc:
            self._scroll_text("Error", str(exc))

    def _screen_dorks(self) -> None:
        target = self._ask_target("Target (domain/email/user/...)")
        if not target:
            return
        try:
            data = self._run_with_spinner(f"Dorks -> {target}", lambda: self.toolkit.generate_dorks(target))
            self._show_results(self._wrap(target, "dorks", {"dorks": data}))
        except Exception as exc:
            self._scroll_text("Error", str(exc))

    def _screen_buckets(self) -> None:
        target = self._ask_target("Name / domain slug")
        if not target:
            return
        try:
            data = self._run_with_spinner(f"Buckets -> {target}", lambda: self.toolkit.hunt_buckets(target))
            self._show_results(self._wrap(target, "buckets", {"buckets": data}))
        except Exception as exc:
            self._scroll_text("Error", str(exc))

    def _screen_takeover(self) -> None:
        target = self._ask_target("Domain")
        if not target:
            return
        try:
            data = self._run_with_spinner(f"Takeover -> {target}", lambda: self.toolkit.check_takeovers(target))
            self._show_results(self._wrap(target, "domain", {"takeover": data}))
        except Exception as exc:
            self._scroll_text("Error", str(exc))

    def _screen_favicon(self) -> None:
        target = self._ask_target("URL or domain")
        if not target:
            return
        try:
            data = self._run_with_spinner(f"Favicon -> {target}", lambda: self.toolkit.analyze_favicon(target))
            self._show_results(self._wrap(target, "favicon", {"favicon": data}))
        except Exception as exc:
            self._scroll_text("Error", str(exc))

    def _screen_meta(self) -> None:
        target = self._ask_target("Image URL or local path")
        if not target:
            return
        try:
            data = self._run_with_spinner(f"Meta -> {target}", lambda: self.toolkit.analyze_metadata(target))
            self._show_results(self._wrap(target, "meta", {"meta": data}))
        except Exception as exc:
            self._scroll_text("Error", str(exc))

    def _screen_wayback(self) -> None:
        target = self._ask_target("Domain")
        if not target:
            return
        try:
            data = self._run_with_spinner(
                f"Wayback -> {target}",
                lambda: self.toolkit.hunt_wayback(target, {"limit": 200, "interesting_only": True}),
            )
            self._show_results(self._wrap(target, "domain", {"wayback": data}))
        except Exception as exc:
            self._scroll_text("Error", str(exc))

    def _screen_pastes(self) -> None:
        target = self._ask_target("Query (domain/email/keyword)")
        if not target:
            return
        self._apply_api_keys()
        try:
            data = self._run_with_spinner(f"Pastes -> {target}", lambda: self.toolkit.hunt_pastes(target, {"limit": 30}))
            self._show_results(self._wrap(target, "pastes", {"pastes": data}))
        except Exception as exc:
            self._scroll_text("Error", str(exc))

    def _screen_phone(self) -> None:
        target = self._ask_target("Phone (+E164)")
        if not target:
            return
        try:
            data = self._run_with_spinner(f"Phone -> {target}", lambda: self.toolkit.analyze_phone(target))
            self._show_results(self._wrap(target, "phone", {"phone": data}))
        except Exception as exc:
            self._scroll_text("Error", str(exc))

    def _screen_host(self) -> None:
        target = self._ask_target("IP / host")
        if not target:
            return
        self._apply_api_keys()
        try:
            data = self._run_with_spinner(f"Host -> {target}", lambda: self.toolkit.analyze_host_apis(target))
            self._show_results(self._wrap(target, "ip", {"host_intel": data}))
        except Exception as exc:
            self._scroll_text("Error", str(exc))

    def _screen_onion_search(self) -> None:
        target = self._ask_target("Search query")
        if not target:
            return
        try:
            data = self._run_with_spinner(f"Onion -> {target}", lambda: self.toolkit.search_onion_dirs(target))
            self._show_results(self._wrap(target, "onion", {"onion_dirs": data}))
        except Exception as exc:
            self._scroll_text("Error", str(exc))

    def _screen_ports(self) -> None:
        target = self._ask_target("Host / IP / domain")
        if not target:
            return
        extras = [("ports", "Port range (common/1-1024/...)", self.settings["ports_range"])]
        opts = self._toggle_options("Port Scanner", PORT_OPTS, extras)
        if not opts:
            return
        ports = opts.pop("ports", "common") or "common"
        if not re.match(r"^(common|\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*)$", ports):
            self.status_msg = "Invalid port range"
            return
        opts["ports"] = ports
        try:
            data = self._run_with_spinner(f"Ports -> {target}", lambda: self.toolkit.scan_ports(target, opts))
            self._show_results(self._wrap(target, "ip", {"ports": data}))
        except Exception as exc:
            self._scroll_text("Error", str(exc))

    def _screen_employees(self) -> None:
        target = self._ask_target("Company name")
        if not target:
            return
        extras = [("hibp_api_key", "HIBP API key (optional)", "")]
        opts = self._toggle_options("Employee Intel", EMPLOYEE_OPTS, extras)
        if not opts:
            return
        opts["hibp_api_key"] = opts.get("hibp_api_key") or None
        try:
            data = self._run_with_spinner(f"Company -> {target}", lambda: self.toolkit.analyze_company(target, opts))
            self._show_results(self._wrap(target, "company", {"company": data}))
        except Exception as exc:
            self._scroll_text("Error", str(exc))

    def _screen_darkweb(self) -> None:
        target = self._ask_target(".onion URL")
        if not target:
            return
        extras = [("depth", "Crawl depth", str(self.settings["depth"])), ("max_pages", "Max pages", "50")]
        opts = self._toggle_options("Dark Web", DARKWEB_OPTS, extras)
        if not opts:
            return
        self._apply_tor()
        try:
            opts["depth"] = max(1, min(int(opts.get("depth") or 2), 3))
            opts["max_pages"] = max(1, min(int(opts.get("max_pages") or 50), 100))
        except ValueError:
            opts["depth"], opts["max_pages"] = 2, 50
        try:
            data = self._run_with_spinner(f"Dark web -> {target}", lambda: self.toolkit.analyze_dark_web(target, opts))
            self._show_results(self._wrap(target, "onion", {"dark_web": data}))
        except Exception as exc:
            self._scroll_text("Error", str(exc))

    def _screen_related(self) -> None:
        target = self._ask_target("Domain")
        if not target:
            return
        try:
            data = self._run_with_spinner(f"Related -> {target}", lambda: self.toolkit.find_related_domains(target))
            self._show_results(self._wrap(target, "domain", {"related_domains": data}))
        except Exception as exc:
            self._scroll_text("Error", str(exc))

    def _screen_passive(self) -> None:
        target = self._ask_target("Host or IP")
        if not target:
            return
        try:
            data = self._run_with_spinner(f"Passive DNS -> {target}", lambda: self.toolkit.lookup_passive_dns(target))
            self._show_results(self._wrap(target, "passive_dns", {"passive_dns": data}))
        except Exception as exc:
            self._scroll_text("Error", str(exc))

    def _screen_abuse(self) -> None:
        target = self._ask_target("IP or host")
        if not target:
            return
        try:
            data = self._run_with_spinner(f"Abuse -> {target}", lambda: self.toolkit.check_abuse(target))
            self._show_results(self._wrap(target, "abuse", {"abuse": data}))
        except Exception as exc:
            self._scroll_text("Error", str(exc))

    def _screen_ioc(self) -> None:
        target = self._ask_target("IP / domain / URL / hash")
        if not target:
            return
        self._apply_api_keys()
        try:
            data = self._run_with_spinner(f"IOC -> {target}", lambda: self.toolkit.enrich_ioc(target))
            self._show_results(self._wrap(target, "ioc", {"ioc": data}))
        except Exception as exc:
            self._scroll_text("Error", str(exc))

    def _screen_crypto(self) -> None:
        from modules.crypto_intel import CHAIN_GROUPS
        # Defaults: auto on; evm off (opt-in multi-sweep)
        toggles = [("auto", "Auto (detected chain only)", True)]
        toggles.append(("evm", "EVM — all ETH L1/L2 as one", False))
        for gid, meta in sorted(CHAIN_GROUPS.items()):
            if gid == "evm":
                continue
            toggles.append((gid, meta.get("label") or gid, False))
        toggles.extend([
            ("tokens", "ERC-20 token holdings (Ethplorer)", True),
            ("txs", "ETH tx list (needs Etherscan key)", True),
        ])
        result = self._toggle_options("Web3 chain selection", toggles, [])
        if not result:
            return
        selected = []
        if result.get("auto"):
            selected.append("auto")
        if result.get("evm"):
            selected.append("evm")
        for gid in CHAIN_GROUPS:
            if gid == "evm":
                continue
            if result.get(gid):
                selected.append(gid)
        if not selected:
            selected = ["auto"]
        if len(selected) > 1 and "auto" in selected:
            selected = [s for s in selected if s != "auto"]
        target = self._ask_target("Wallet / ENS / tx hash")
        if not target:
            return
        self._apply_api_keys()
        opts = {
            "tokens": bool(result.get("tokens", True)),
            "txs": bool(result.get("txs", True)),
            "chains": selected,
        }
        try:
            data = self._run_with_spinner(
                f"Web3 [{','.join(selected)}] -> {target}",
                lambda: self.toolkit.analyze_crypto(target, opts),
            )
            self._show_results(self._wrap(target, "wallet", {"crypto": data}))
        except Exception as exc:
            self._scroll_text("Error", str(exc))

    def _screen_perms(self) -> None:
        target = self._ask_target("Name / username / email")
        if not target:
            return
        try:
            data = self._run_with_spinner(f"Perms -> {target}", lambda: self.toolkit.generate_username_perms(target))
            self._show_results(self._wrap(target, "perms", {"perms": data}))
        except Exception as exc:
            self._scroll_text("Error", str(exc))

    def _screen_jssecrets(self) -> None:
        target = self._ask_target("URL or domain")
        if not target:
            return
        url = target if target.startswith("http") else f"https://{target}"
        try:
            data = self._run_with_spinner(f"JS secrets -> {url}", lambda: self.toolkit.mine_js_secrets(url))
            self._show_results(self._wrap(target, "js_secrets", {"js_secrets": data}))
        except Exception as exc:
            self._scroll_text("Error", str(exc))

    def _screen_screenshot(self) -> None:
        target = self._ask_target("URL or domain")
        if not target:
            return
        url = target if target.startswith("http") else f"https://{target}"
        try:
            data = self._run_with_spinner(f"Screenshot -> {url}", lambda: self.toolkit.capture_screenshot(url))
            self._show_results(self._wrap(target, "screenshot", {"screenshot": data}))
        except Exception as exc:
            self._scroll_text("Error", str(exc))

    def _screen_email_accounts(self) -> None:
        target = self._ask_target("Email address")
        if not target:
            return
        try:
            data = self._run_with_spinner(f"Email accounts -> {target}", lambda: self.toolkit.check_email_accounts(target))
            self._show_results(self._wrap(target, "email", {"email_accounts": data}))
        except Exception as exc:
            self._scroll_text("Error", str(exc))

    def _screen_imgpivot(self) -> None:
        target = self._ask_target("Image URL or hash/query")
        if not target:
            return
        try:
            data = self._run_with_spinner(f"Image pivots -> {target}", lambda: self.toolkit.image_pivots(target))
            self._show_results(self._wrap(target, "image", {"image_pivots": data}))
        except Exception as exc:
            self._scroll_text("Error", str(exc))

    def _screen_tor_check(self) -> None:
        self._apply_tor()
        try:
            data = self._run_with_spinner("Tor health", lambda: self.toolkit.tor_health())
            self._show_results(self._wrap("tor", "tor", {"tor_health": data}))
        except Exception as exc:
            self._scroll_text("Error", str(exc))

    def _screen_graph(self) -> None:
        if not self.last_results:
            self.status_msg = "Run a scan first, then export graph"
            return
        try:
            data = self._run_with_spinner(
                "Graph export",
                lambda: self.toolkit.export_graph(self.last_results),
            )
            wrapped = dict(self.last_results)
            wrapped.setdefault("results", {})["graph"] = data
            self._show_results(wrapped)
        except Exception as exc:
            self._scroll_text("Error", str(exc))

    def _screen_cases(self) -> None:
        actions = [
            ("list", "List cases", "Show investigation cases"),
            ("create", "Create case", "New case folder"),
            ("attach", "Attach last scan", "Link last results to a case"),
        ]
        choice = self._select_list("Cases", actions)
        if not choice:
            return
        if choice == "list":
            cases = self.toolkit.cases.list_cases()
            if not cases:
                self.status_msg = "No cases yet"
                return
            lines = [f"{c['id']}  {c['name']}  targets={c['targets']} scans={c['scans']}" for c in cases]
            self._scroll_text("Cases", "\n".join(lines))
        elif choice == "create":
            name = self._ask_target("Case name")
            if not name:
                return
            case = self.toolkit.cases.create(name)
            self._scroll_text("Case created", json.dumps(case, indent=2, default=str))
        elif choice == "attach":
            if not self.last_results or not self.last_filepath:
                self.status_msg = "No scan to attach"
                return
            cid = self._ask_target("Case id")
            if not cid:
                return
            out = self.toolkit.cases.attach_scan(cid, {
                "target": self.last_results.get("target"),
                "scan_type": self.last_results.get("scan_type"),
                "report_path": self.last_filepath,
                "counts": (self.last_results.get("correlation") or {}).get("counts") or {},
            })
            self._scroll_text("Case updated", json.dumps(out, indent=2, default=str))

    def _screen_plugins(self) -> None:
        plugs = self.toolkit.plugins.discover()
        if not plugs:
            self.status_msg = "No plugins in modules/plugins/"
            return
        items = [(p.get("id") or "?", p.get("name") or "?", p.get("description") or p.get("error") or "") for p in plugs]
        pid = self._select_list("Plugins", items)
        if not pid:
            return
        target = self._ask_target("Target for plugin")
        if not target:
            return
        try:
            data = self._run_with_spinner(f"Plugin {pid}", lambda: self.toolkit.run_plugin(pid, target))
            self._show_results(self._wrap(target, "plugin", {"plugin": data}))
        except Exception as exc:
            self._scroll_text("Error", str(exc))

    def _safe_report_path(self, path: Path, out: Path) -> Optional[Path]:
        try:
            resolved = path.resolve()
            resolved.relative_to(out.resolve())
        except (ValueError, OSError):
            return None
        if not resolved.is_file() or not resolved.name.startswith("osint_"):
            return None
        return resolved

    def _screen_reports(self) -> None:
        out = Path(self.settings["output_dir"])
        idx = 0
        while True:
            try:
                files = sorted(out.glob("osint_*.*"), key=lambda p: p.stat().st_mtime, reverse=True)[:50]
            except OSError:
                files = []
            if not files:
                self.status_msg = "No reports found"
                return
            items = [(str(p), p.name, f"{p.stat().st_size} bytes") for p in files]

            self._paint_shell("SAVED REPORTS", logo=False)
            ch_, cw = self._content_size()
            self._content_write(0, 0, "Enter view | d delete | D delete all | Esc back", _attr(Theme.DIM))
            visible = max(1, ch_ - 3)
            idx = max(0, min(idx, len(items) - 1))
            start = max(0, min(idx - visible // 2, max(0, len(items) - visible)))
            for i, (_, label, desc) in enumerate(items[start : start + visible]):
                n = start + i
                selected = n == idx
                num = f"{n + 1:02d}"
                if selected:
                    self._content_write(2 + i, 0, f"  >:: [{num}] {label}".ljust(min(48, cw)), _attr(Theme.HIGHLIGHT, True))
                    self._content_write(2 + i, min(50, cw - 12), desc[:12], _attr(Theme.DIM))
                else:
                    self._content_write(2 + i, 0, f"      [{num}] {label}", _attr(Theme.NORMAL))
            self._footer("##  Enter view  |  d delete  |  D wipe all  |  Esc  ##")
            self._stdscr.refresh()

            ch = self._stdscr.getch()
            if ch in (curses.KEY_UP, ord("k")):
                idx = (idx - 1) % len(items)
            elif ch in (curses.KEY_DOWN, ord("j")):
                idx = (idx + 1) % len(items)
            elif ch in (27, ord("q")):
                return
            elif ch in (curses.KEY_ENTER, ord("\n"), ord("\r"), ord(" ")):
                path = self._safe_report_path(Path(items[idx][0]), out)
                if not path:
                    self.status_msg = "Blocked or missing path"
                    continue
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError as exc:
                    self._scroll_text("Error", str(exc))
                    continue
                if path.suffix.lower() == ".json" or text.lstrip().startswith("{"):
                    self._scroll_styled(path.name, format_json_file(text[:200_000]))
                else:
                    self._scroll_text(path.name, text[:100_000])
            elif ch == ord("d"):
                path = self._safe_report_path(Path(items[idx][0]), out)
                if not path:
                    self.status_msg = "Blocked or missing path"
                    continue
                if self._confirm(f"Delete: {path.name} ?"):
                    try:
                        path.unlink()
                        self.status_msg = f"Deleted {path.name}"
                        idx = max(0, idx - 1)
                    except OSError as exc:
                        self.status_msg = f"Delete failed: {exc}"
            elif ch == ord("D"):
                if self._confirm(f"Delete ALL {len(items)} reports?"):
                    deleted = 0
                    for item_path, _, _ in items:
                        p = self._safe_report_path(Path(item_path), out)
                        if p:
                            try:
                                p.unlink()
                                deleted += 1
                            except OSError:
                                pass
                    self.status_msg = f"Deleted {deleted} report(s)"
                    idx = 0

    def _screen_settings(self) -> None:
        extras = [
            ("format", "Output format (json/txt/html/md)", self.settings["format"]),
            ("output_dir", "Output directory", self.settings["output_dir"]),
            ("depth", "Default crawl depth", str(self.settings["depth"])),
            ("max_pages", "Default max pages", str(self.settings["max_pages"])),
            ("ports_range", "Default port range", self.settings["ports_range"]),
            ("rate_limit", "Rate limit req/s (0=off)", str(self.settings.get("rate_limit") or "0")),
            ("github_token", "GitHub token (optional)", self.settings.get("github_token") or ""),
            ("shodan_key", "Shodan API key", self.settings.get("shodan_key") or ""),
            ("censys_id", "Censys API ID", self.settings.get("censys_id") or ""),
            ("censys_secret", "Censys API secret", self.settings.get("censys_secret") or ""),
            ("vt_key", "VirusTotal API key", self.settings.get("vt_key") or ""),
            ("otx_key", "OTX API key", self.settings.get("otx_key") or ""),
            ("etherscan_key", "Etherscan API key", self.settings.get("etherscan_key") or ""),
        ]
        tor_opts = [("use_tor", "Use Tor proxy for dark web", bool(self.settings["use_tor"]))]
        result = self._toggle_options("Settings", tor_opts, extras)
        if not result:
            return
        fmt = (result.get("format") or "json").lower()
        self.settings["format"] = fmt if fmt in ("json", "txt", "html", "md") else "json"
        out_path = Path(result.get("output_dir") or "reports").expanduser()
        if out_path.is_absolute() and not str(out_path).startswith(str(Path.cwd())):
            out_path = Path("reports")
        self.settings["output_dir"] = str(out_path)
        self.toolkit.output_dir = out_path
        out_path.mkdir(exist_ok=True)
        try:
            self.settings["depth"] = max(1, min(int(result.get("depth") or 2), 5))
            self.settings["max_pages"] = max(1, min(int(result.get("max_pages") or 100), 500))
        except ValueError:
            pass
        self.settings["ports_range"] = result.get("ports_range") or "common"
        self.settings["use_tor"] = bool(result.get("use_tor"))
        self.settings["rate_limit"] = str(result.get("rate_limit") or "0")
        for key in ("github_token", "shodan_key", "censys_id", "censys_secret", "vt_key", "otx_key", "etherscan_key"):
            self.settings[key] = (result.get(key) or "").strip()
        self._apply_tor()
        self._apply_api_keys()
        self.status_msg = "Settings saved"

    @staticmethod
    def _wrap(target: str, scan_type: str, results: Dict) -> Dict:
        from datetime import datetime
        return {
            "target": target,
            "scan_type": scan_type,
            "timestamp": datetime.now().strftime("%Y%m%d_%H%M%S"),
            "results": results,
        }


def launch_tui(toolkit: Any) -> None:
    EpicTUI(toolkit).run()
