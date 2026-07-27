"""
Epic OSINT Toolkit — Interactive Terminal UI
Keyboard-driven menus with ANSI/ASCII art. Pure stdlib (curses).
"""

from __future__ import annotations

import curses
import io
import json
import re
import textwrap
import threading
import traceback
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

# ── ASCII / ANSI art ──────────────────────────────────────────────────────────

BANNER_WIDE = r"""
+====================================================================+
|                                                                    |
|      _____ ____ ___ ____     ____ ____ ___ _  _ ___                |
|      |___  |__]  |  |        |  | [__   |  |\ |  |                 |
|      |___  |     |  |___     |__| ___]  |  | \|  |                 |
|                                                                    |
|                 >>>  O S I N T   T O O L K I T  <<<                |
|                                                                    |
+====================================================================+
""".strip("\n")

BANNER_COMPACT = r"""
+==============================================================+
|   _____ ____ ___ ____    ____ ____ ___ _  _ ___              |
|   |___  |__]  |  |       |  | [__   |  |\ |  |               |
|   |___  |     |  |___    |__| ___]  |  | \|  |               |
|              O S I N T   T O O L K I T                       |
+==============================================================+
""".strip("\n")

HELP_FOOTER = "Up/Down navigate  |  Enter select  |  Esc/q back"

# Safe target patterns (reject shell metacharacters / path tricks)
_TARGET_RE = re.compile(r"^[\w.\-:@/+#%=&?, ]{1,256}$", re.UNICODE)


def _sanitize_target(raw: str) -> Optional[str]:
    value = (raw or "").strip()
    if not value or not _TARGET_RE.match(value):
        return None
    if ".." in value:
        return None
    if value.startswith("-"):
        return None
    if value.startswith("/") and not value.startswith(("http://", "https://")):
        return None
    return value


# ── Color helpers ─────────────────────────────────────────────────────────────

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


def _init_colors() -> None:
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(Theme.TITLE, curses.COLOR_CYAN, -1)
    curses.init_pair(Theme.HIGHLIGHT, curses.COLOR_BLACK, curses.COLOR_GREEN)
    curses.init_pair(Theme.DIM, curses.COLOR_WHITE, -1)
    curses.init_pair(Theme.SUCCESS, curses.COLOR_GREEN, -1)
    curses.init_pair(Theme.WARN, curses.COLOR_YELLOW, -1)
    curses.init_pair(Theme.ERROR, curses.COLOR_RED, -1)
    curses.init_pair(Theme.BORDER, curses.COLOR_CYAN, -1)
    curses.init_pair(Theme.INPUT, curses.COLOR_WHITE, curses.COLOR_BLUE)


def _attr(pair: int, bold: bool = False) -> int:
    a = curses.color_pair(pair)
    if bold:
        a |= curses.A_BOLD
    return a


# ── Menu definitions ──────────────────────────────────────────────────────────

MenuItem = Tuple[str, str, str]  # id, label, description

MAIN_MENU: List[MenuItem] = [
    ("full", "Full Scan", "Comprehensive multi-module scan"),
    ("domain", "Domain Intelligence", "DNS · WHOIS · SSL · subdomains"),
    ("social", "Social Media Intel", "Username search across platforms"),
    ("github", "GitHub Intelligence", "Profile · repos · emails"),
    ("crawl", "Web Crawler", "Crawl · extract · technologies"),
    ("emails", "Email Discovery", "Find & source email addresses"),
    ("urls", "URL Hunter", "Shorteners · exposed URLs"),
    ("ports", "Port Scanner", "Open ports · services · banners"),
    ("employees", "Employee Intel", "Company staff · credential leaks"),
    ("darkweb", "Dark Web Intel", ".onion analysis (optional Tor)"),
    ("reports", "View Reports", "Browse saved scan reports"),
    ("settings", "Settings", "Output format · Tor · paths"),
    ("quit", "Quit", "Exit the toolkit"),
]

DOMAIN_OPTS = [
    ("dns", "DNS enumeration", True),
    ("subdomains", "Subdomain discovery", True),
    ("whois", "WHOIS lookup", True),
    ("ssl", "SSL certificate analysis", True),
]

SOCIAL_OPTS = [
    ("search", "Platform search", True),
    ("email", "Email discovery", True),
    ("associated", "Associated accounts", True),
]

GITHUB_OPTS = [
    ("profile", "Profile analysis", True),
    ("repos", "Repository analysis", True),
    ("email", "Email discovery", True),
    ("creation", "Creation date", True),
]

CRAWL_OPTS = [
    ("crawl", "Page crawl", True),
    ("directories", "Directory enumeration", True),
    ("tech", "Technology detection", True),
    ("extract", "Info extraction", True),
    ("comprehensive", "Comprehensive (creepyCrawler)", False),
    ("robots", "Parse robots.txt", True),
    ("sitemap", "Parse sitemap.xml", True),
]

EMAIL_OPTS = [
    ("discover", "Discover emails", True),
    ("verify", "Verify emails", False),
    ("sources", "Find sources", True),
]

URL_OPTS = [
    ("hunt", "Shortened URL hunt", True),
    ("exposed", "Exposed URL search", True),
    ("urlteam", "URLTeam archives", False),
]

PORT_OPTS = [
    ("scan", "Port scan", True),
]

EMPLOYEE_OPTS = [
    ("discover", "Discover employees", True),
    ("check_leaks", "Check credential leaks", True),
]

DARKWEB_OPTS = [
    ("analyze", "Analyze .onion", True),
    ("crawl", "Crawl .onion", False),
    ("map_links", "Map link relationships", False),
]

FULL_TYPES = ["domain", "username", "company"]


# ── Core TUI ──────────────────────────────────────────────────────────────────

class EpicTUI:
    """Keyboard-navigable OSINT interface."""

    def __init__(self, toolkit: Any):
        self.toolkit = toolkit
        self.settings: Dict[str, Any] = {
            "format": "json",
            "output_dir": str(toolkit.output_dir),
            "use_tor": False,
            "depth": 2,
            "max_pages": 100,
            "ports_range": "common",
        }
        self.last_results: Optional[Dict] = None
        self.last_filepath: Optional[str] = None
        self.status_msg = ""
        self._stdscr: Optional[Any] = None

    # ── public entry ──────────────────────────────────────────────────────────

    def run(self) -> None:
        curses.wrapper(self._main)

    def _main(self, stdscr) -> None:
        self._stdscr = stdscr
        curses.curs_set(0)
        stdscr.keypad(True)
        stdscr.timeout(-1)
        _init_colors()
        self._screen_main_menu()

    # ── drawing primitives ────────────────────────────────────────────────────

    def _size(self) -> Tuple[int, int]:
        return self._stdscr.getmaxyx()

    def _safe_addstr(self, y: int, x: int, text: str, attr: int = 0) -> None:
        h, w = self._size()
        if y < 0 or y >= h or x >= w:
            return
        text = text[: max(0, w - x - 1)]
        try:
            self._stdscr.addstr(y, x, text, attr)
        except curses.error:
            pass

    def _draw_box(self, y: int, x: int, h: int, w: int, title: str = "") -> None:
        attr = _attr(Theme.BORDER)
        max_h, max_w = self._size()
        if y + h > max_h or x + w > max_w or h < 2 or w < 2:
            return
        try:
            win = self._stdscr.derwin(h, w, y, x)
            win.attrset(attr)
            win.border()
            if title:
                t = f" {title} "
                win.addstr(0, 2, t[: w - 4], _attr(Theme.TITLE, True))
        except curses.error:
            pass

    def _clear(self) -> None:
        self._stdscr.erase()

    def _footer(self, text: str = HELP_FOOTER) -> None:
        h, w = self._size()
        self._safe_addstr(h - 1, 1, text[: w - 2], _attr(Theme.DIM))

    def _status(self, msg: str, pair: int = Theme.SUCCESS) -> None:
        h, w = self._size()
        self._safe_addstr(h - 2, 1, " " * (w - 2))
        self._safe_addstr(h - 2, 1, msg[: w - 2], _attr(pair, True))

    def _draw_banner(self) -> int:
        """Draw banner; return next free row."""
        h, w = self._size()
        if w >= 72 and h >= 14:
            lines = BANNER_WIDE.splitlines()
        elif w >= 64:
            lines = BANNER_COMPACT.splitlines()
        else:
            lines = ["=== EPIC OSINT TOOLKIT ==="]
        start = 0
        for i, line in enumerate(lines):
            x = max(0, (w - len(line)) // 2)
            self._safe_addstr(start + i, x, line, _attr(Theme.TITLE, True))
        return start + len(lines) + 1

    # ── input widgets ─────────────────────────────────────────────────────────

    def _prompt_input(
        self,
        y: int,
        x: int,
        width: int,
        initial: str = "",
        label: str = "",
    ) -> Optional[str]:
        """Inline editable field. Returns None on Esc."""
        curses.curs_set(1)
        buf = list(initial)
        pos = len(buf)
        try:
            while True:
                field = "".join(buf)
                display = field[max(0, pos - width + 1) :][:width]
                pad = " " * (width - len(display))
                if label:
                    self._safe_addstr(y, x, label, _attr(Theme.DIM))
                    fx = x + len(label)
                else:
                    fx = x
                self._safe_addstr(y, fx, display + pad, _attr(Theme.INPUT))
                try:
                    self._stdscr.move(y, fx + min(pos, width - 1))
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
        self,
        title: str,
        items: List[MenuItem],
        banner: bool = True,
    ) -> Optional[str]:
        """Arrow-key menu. Returns item id or None if quit/back."""
        idx = 0
        while True:
            self._clear()
            row = self._draw_banner() if banner else 1
            h, w = self._size()
            self._safe_addstr(row, 2, title, _attr(Theme.TITLE, True))
            row += 2

            visible = h - row - 3
            start = max(0, min(idx - visible // 2, max(0, len(items) - visible)))
            for i, (item_id, label, desc) in enumerate(items[start : start + visible]):
                y = row + i
                selected = (start + i) == idx
                prefix = " ▶ " if selected else "   "
                line = f"{prefix}{label}"
                attr = _attr(Theme.HIGHLIGHT, True) if selected else _attr(Theme.NORMAL)
                self._safe_addstr(y, 2, line.ljust(min(40, w - 4)), attr)
                if selected and desc:
                    self._safe_addstr(y, min(44, w // 2), desc[: w - min(44, w // 2) - 2], _attr(Theme.DIM))

            if self.status_msg:
                self._status(self.status_msg)
                self.status_msg = ""
            self._footer()
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
        """
        Toggleable option screen + optional text fields.
        extra_fields: list of (key, label, default)
        Returns dict of options or None on cancel.
        """
        opts = {k: v for k, _, v in options}
        labels = {k: lab for k, lab, _ in options}
        fields = {k: default for k, _, default in (extra_fields or [])}
        field_labels = {k: lab for k, lab, _ in (extra_fields or [])}
        keys = [k for k, _, _ in options] + [k for k, _, _ in (extra_fields or [])]
        idx = 0
        editing = False

        while True:
            self._clear()
            row = 1
            h, w = self._size()
            self._safe_addstr(row, 2, title, _attr(Theme.TITLE, True))
            row += 2
            self._safe_addstr(row, 2, "Space toggle  ·  Enter edit field / confirm  ·  Esc cancel", _attr(Theme.DIM))
            row += 2

            for i, key in enumerate(keys):
                y = row + i
                selected = i == idx
                if key in opts:
                    mark = "[✓]" if opts[key] else "[ ]"
                    line = f" {mark}  {labels[key]}"
                else:
                    val = fields[key]
                    shown = val if len(val) <= 40 else val[:37] + "..."
                    line = f"  {field_labels[key]}: {shown}"
                attr = _attr(Theme.HIGHLIGHT, True) if selected else _attr(Theme.NORMAL)
                self._safe_addstr(y, 2, line.ljust(min(60, w - 4)), attr)

            # Confirm / Cancel rows
            cy = row + len(keys) + 1
            for j, lab in enumerate(("▶ RUN SCAN", "  Cancel")):
                sel = idx == len(keys) + j
                attr = _attr(Theme.HIGHLIGHT, True) if sel else _attr(Theme.SUCCESS if j == 0 else Theme.DIM)
                self._safe_addstr(cy + j, 2, lab, attr)

            self._footer("↑↓ move  ·  Space toggle  ·  Enter run/edit  ·  Esc back")
            self._stdscr.refresh()

            if editing and keys[idx] in fields:
                new_val = self._prompt_input(
                    row + idx,
                    2 + len(field_labels[keys[idx]]) + 2,
                    min(40, w - 20),
                    fields[keys[idx]],
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
                if idx == len(keys):  # RUN
                    result = dict(opts)
                    result.update(fields)
                    return result
                if idx == len(keys) + 1:  # Cancel
                    return None
                if keys[idx] in fields:
                    editing = True
                elif keys[idx] in opts:
                    opts[keys[idx]] = not opts[keys[idx]]
            elif ch in (27, ord("q")):
                return None

    def _ask_target(self, prompt: str = "Target") -> Optional[str]:
        self._clear()
        row = self._draw_banner()
        self._safe_addstr(row, 2, f"{prompt}:", _attr(Theme.TITLE, True))
        self._safe_addstr(row + 1, 2, "Enter value then press Enter. Esc to cancel.", _attr(Theme.DIM))
        self._footer()
        self._stdscr.refresh()
        raw = self._prompt_input(row + 3, 2, min(60, self._size()[1] - 4), "")
        if raw is None:
            return None
        clean = _sanitize_target(raw)
        if not clean:
            self.status_msg = "Invalid target (disallowed characters or empty)"
            return None
        return clean

    def _scroll_text(self, title: str, text: str) -> None:
        lines = []
        h, w = self._size()
        width = max(20, w - 4)
        for paragraph in text.splitlines() or [""]:
            if not paragraph:
                lines.append("")
            else:
                lines.extend(textwrap.wrap(paragraph, width) or [""])
        offset = 0
        while True:
            self._clear()
            self._safe_addstr(0, 2, title[: w - 4], _attr(Theme.TITLE, True))
            view_h = h - 3
            for i in range(view_h):
                li = offset + i
                if li >= len(lines):
                    break
                self._safe_addstr(1 + i, 2, lines[li])
            self._footer("↑↓/PgUp/PgDn scroll  ·  Esc/q back")
            self._status(f"Line {offset + 1}/{max(1, len(lines))}", Theme.DIM)
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

    def _run_with_spinner(self, label: str, fn: Callable[[], Any]) -> Any:
        """Run blocking work off-main with a status animation."""
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
        frames = "|/-\\"
        i = 0
        self._stdscr.timeout(120)
        try:
            while not done.is_set():
                self._clear()
                row = self._draw_banner()
                frame = frames[i % len(frames)]
                self._safe_addstr(row + 2, 2, f" {frame}  {label}", _attr(Theme.WARN, True))
                self._safe_addstr(row + 4, 2, "Working... mid-scan cancel not supported.", _attr(Theme.DIM))
                # show last log line so user sees progress
                log_lines = result.get("log") or log_buf.getvalue()
                last = log_lines.strip().splitlines()[-1] if log_lines.strip() else ""
                if last:
                    self._safe_addstr(row + 6, 2, last[: self._size()[1] - 4], _attr(Theme.DIM))
                self._footer("Please wait")
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
        self.last_results = results
        try:
            fmt = self.settings["format"]
            path = self.toolkit.save_results(results, fmt)
            self.last_filepath = path
            self.toolkit.output_dir = Path(self.settings["output_dir"])
        except OSError as exc:
            path = None
            self.status_msg = f"Save failed: {exc}"

        summary = self._format_summary(results)
        if path:
            summary = f"Saved: {path}\n\n{summary}"
        self._scroll_text("Scan Results", summary)

    def _format_summary(self, results: Dict) -> str:
        lines = [
            f"Target : {results.get('target', '?')}",
            f"Type   : {results.get('scan_type', '?')}",
            f"Time   : {results.get('timestamp', '?')}",
            "",
        ]
        blob = results.get("results") or {}
        for section, data in blob.items():
            lines.append(f"▸ {section.upper()}")
            try:
                pretty = json.dumps(data, indent=2, default=str)
            except (TypeError, ValueError):
                pretty = str(data)
            # keep UI snappy
            if len(pretty) > 8000:
                pretty = pretty[:8000] + "\n… (truncated)"
            lines.append(pretty)
            lines.append("")
        return "\n".join(lines)

    # ── screens ───────────────────────────────────────────────────────────────

    def _screen_main_menu(self) -> None:
        while True:
            choice = self._select_list("MAIN MENU — select a module", MAIN_MENU, banner=True)
            if choice is None or choice == "quit":
                return
            dispatch = {
                "full": self._screen_full,
                "domain": self._screen_domain,
                "social": self._screen_social,
                "github": self._screen_github,
                "crawl": self._screen_crawl,
                "emails": self._screen_emails,
                "urls": self._screen_urls,
                "ports": self._screen_ports,
                "employees": self._screen_employees,
                "darkweb": self._screen_darkweb,
                "reports": self._screen_reports,
                "settings": self._screen_settings,
            }
            handler = dispatch.get(choice)
            if handler:
                handler()

    def _apply_tor(self) -> None:
        if self.settings.get("use_tor"):
            from modules.dark_web_intel import DarkWebIntel
            self.toolkit.dark_web_intel = DarkWebIntel(use_tor=True)

    def _screen_full(self) -> None:
        type_items = [(t, t.capitalize(), f"Full {t} scan") for t in FULL_TYPES]
        scan_type = self._select_list("Full Scan — target type", type_items, banner=False)
        if not scan_type:
            return
        target = self._ask_target(f"Target ({scan_type})")
        if not target:
            return
        try:
            results = self._run_with_spinner(
                f"Full {scan_type} scan → {target}",
                lambda: self.toolkit.run_full_scan(target, scan_type),
            )
            self._show_results(results)
        except Exception as exc:
            self._scroll_text("Error", f"{exc}\n\n{traceback.format_exc()}")

    def _screen_domain(self) -> None:
        target = self._ask_target("Domain")
        if not target:
            return
        opts = self._toggle_options("Domain Intelligence — options", DOMAIN_OPTS)
        if not opts:
            return
        try:
            data = self._run_with_spinner(
                f"Domain intel → {target}",
                lambda: self.toolkit.gather_domain_intel(target, opts),
            )
            self._show_results(self._wrap(target, "domain", {"domain": data}))
        except Exception as exc:
            self._scroll_text("Error", str(exc))

    def _screen_social(self) -> None:
        target = self._ask_target("Username")
        if not target:
            return
        opts = self._toggle_options("Social Media — options", SOCIAL_OPTS)
        if not opts:
            return
        try:
            data = self._run_with_spinner(
                f"Social intel → {target}",
                lambda: self.toolkit.gather_social_intel(target, opts),
            )
            self._show_results(self._wrap(target, "username", {"social": data}))
        except Exception as exc:
            self._scroll_text("Error", str(exc))

    def _screen_github(self) -> None:
        target = self._ask_target("GitHub username")
        if not target:
            return
        opts = self._toggle_options("GitHub — options", GITHUB_OPTS)
        if not opts:
            return
        try:
            data = self._run_with_spinner(
                f"GitHub intel → {target}",
                lambda: self.toolkit.gather_github_intel(target, opts),
            )
            self._show_results(self._wrap(target, "username", {"github": data}))
        except Exception as exc:
            self._scroll_text("Error", str(exc))

    def _screen_crawl(self) -> None:
        target = self._ask_target("URL or domain")
        if not target:
            return
        extras = [
            ("depth", "Crawl depth", str(self.settings["depth"])),
            ("max_pages", "Max pages", str(self.settings["max_pages"])),
        ]
        opts = self._toggle_options("Web Crawler — options", CRAWL_OPTS, extras)
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
            data = self._run_with_spinner(
                f"Crawling → {url}",
                lambda: self.toolkit.crawl_website(url, opts),
            )
            self._show_results(self._wrap(target, "url", {"website": data}))
        except Exception as exc:
            self._scroll_text("Error", str(exc))

    def _screen_emails(self) -> None:
        target = self._ask_target("Domain")
        if not target:
            return
        opts = self._toggle_options("Email Discovery — options", EMAIL_OPTS)
        if not opts:
            return
        try:
            data = self._run_with_spinner(
                f"Emails → {target}",
                lambda: self.toolkit.discover_emails(target, opts),
            )
            self._show_results(self._wrap(target, "domain", {"emails": data}))
        except Exception as exc:
            self._scroll_text("Error", str(exc))

    def _screen_urls(self) -> None:
        target = self._ask_target("Domain")
        if not target:
            return
        opts = self._toggle_options("URL Hunter — options", URL_OPTS)
        if not opts:
            return
        opts["keywords"] = [target]
        opts["date"] = "latest"
        try:
            data = self._run_with_spinner(
                f"URL hunt → {target}",
                lambda: self.toolkit.hunt_urls(target, opts),
            )
            self._show_results(self._wrap(target, "domain", {"urls": data}))
        except Exception as exc:
            self._scroll_text("Error", str(exc))

    def _screen_ports(self) -> None:
        target = self._ask_target("Host / IP / domain")
        if not target:
            return
        extras = [("ports", "Port range (common/1-1024/…)", self.settings["ports_range"])]
        opts = self._toggle_options("Port Scanner — options", PORT_OPTS, extras)
        if not opts:
            return
        ports = opts.pop("ports", "common") or "common"
        # allow only safe port-range tokens
        if not re.match(r"^(common|\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*)$", ports):
            self.status_msg = "Invalid port range"
            return
        opts["ports"] = ports
        try:
            data = self._run_with_spinner(
                f"Port scan → {target}",
                lambda: self.toolkit.scan_ports(target, opts),
            )
            self._show_results(self._wrap(target, "ip", {"ports": data}))
        except Exception as exc:
            self._scroll_text("Error", str(exc))

    def _screen_employees(self) -> None:
        target = self._ask_target("Company name")
        if not target:
            return
        extras = [("hibp_api_key", "HIBP API key (optional)", "")]
        opts = self._toggle_options("Employee Intel — options", EMPLOYEE_OPTS, extras)
        if not opts:
            return
        key = opts.get("hibp_api_key") or None
        opts["hibp_api_key"] = key if key else None
        try:
            data = self._run_with_spinner(
                f"Company intel → {target}",
                lambda: self.toolkit.analyze_company(target, opts),
            )
            self._show_results(self._wrap(target, "company", {"company": data}))
        except Exception as exc:
            self._scroll_text("Error", str(exc))

    def _screen_darkweb(self) -> None:
        target = self._ask_target(".onion URL")
        if not target:
            return
        extras = [
            ("depth", "Crawl depth", str(self.settings["depth"])),
            ("max_pages", "Max pages", "50"),
        ]
        opts = self._toggle_options("Dark Web — options", DARKWEB_OPTS, extras)
        if not opts:
            return
        self._apply_tor()
        try:
            opts["depth"] = max(1, min(int(opts.get("depth") or 2), 3))
            opts["max_pages"] = max(1, min(int(opts.get("max_pages") or 50), 100))
        except ValueError:
            opts["depth"], opts["max_pages"] = 2, 50
        try:
            data = self._run_with_spinner(
                f"Dark web → {target}",
                lambda: self.toolkit.analyze_dark_web(target, opts),
            )
            self._show_results(self._wrap(target, "onion", {"dark_web": data}))
        except Exception as exc:
            self._scroll_text("Error", str(exc))

    def _screen_reports(self) -> None:
        out = Path(self.settings["output_dir"])
        try:
            files = sorted(out.glob("osint_*.*"), key=lambda p: p.stat().st_mtime, reverse=True)
        except OSError:
            files = []
        if not files:
            self.status_msg = "No reports found"
            return
        items = [(str(p), p.name, f"{p.stat().st_size} bytes") for p in files[:50]]
        choice = self._select_list("Saved Reports", items, banner=False)
        if not choice:
            return
        path = Path(choice)
        # stay inside output dir
        try:
            path.resolve().relative_to(out.resolve())
        except ValueError:
            self.status_msg = "Blocked path outside reports dir"
            return
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            self._scroll_text("Error", str(exc))
            return
        if len(text) > 100_000:
            text = text[:100_000] + "\n… (truncated)"
        self._scroll_text(path.name, text)

    def _screen_settings(self) -> None:
        extras = [
            ("format", "Output format (json/txt/html)", self.settings["format"]),
            ("output_dir", "Output directory", self.settings["output_dir"]),
            ("depth", "Default crawl depth", str(self.settings["depth"])),
            ("max_pages", "Default max pages", str(self.settings["max_pages"])),
            ("ports_range", "Default port range", self.settings["ports_range"]),
        ]
        tor_opts = [("use_tor", "Use Tor proxy for dark web", bool(self.settings["use_tor"]))]
        result = self._toggle_options("Settings", tor_opts, extras)
        if not result:
            return
        fmt = (result.get("format") or "json").lower()
        if fmt not in ("json", "txt", "html"):
            fmt = "json"
        self.settings["format"] = fmt
        out = result.get("output_dir") or "reports"
        # prevent path escape into sensitive dirs via weird names
        out_path = Path(out).expanduser()
        if out_path.is_absolute() and not str(out_path).startswith(str(Path.cwd())):
            # allow absolute only under cwd
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
        self._apply_tor()
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
    """Entry point used by osint_toolkit.py."""
    EpicTUI(toolkit).run()
