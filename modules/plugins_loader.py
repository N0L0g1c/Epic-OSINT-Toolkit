"""Simple plugin loader — drop modules/plugins/*.py with register()."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


class PluginLoader:
    """Load optional user plugins from modules/plugins/."""

    def __init__(self, plugin_dir: str = "modules/plugins"):
        self.plugin_dir = Path(plugin_dir)
        self.plugin_dir.mkdir(parents=True, exist_ok=True)
        # ensure package marker
        init = self.plugin_dir / "__init__.py"
        if not init.exists():
            init.write_text('"""User OSINT plugins."""\n', encoding="utf-8")
        self.plugins: Dict[str, Dict[str, Any]] = {}

    def discover(self) -> List[Dict[str, Any]]:
        found = []
        for path in sorted(self.plugin_dir.glob("*.py")):
            if path.name.startswith("_"):
                continue
            try:
                mod = self._load(path)
                meta = getattr(mod, "PLUGIN", None) or {}
                run = getattr(mod, "run", None)
                if not callable(run):
                    continue
                pid = meta.get("id") or path.stem
                self.plugins[pid] = {
                    "id": pid,
                    "name": meta.get("name", path.stem),
                    "description": meta.get("description", ""),
                    "run": run,
                    "path": str(path),
                }
                found.append({k: v for k, v in self.plugins[pid].items() if k != "run"})
            except Exception as exc:
                found.append({"id": path.stem, "error": str(exc)})
        return found

    def run(self, plugin_id: str, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if not self.plugins:
            self.discover()
        plug = self.plugins.get(plugin_id)
        if not plug:
            return {"error": f"Unknown plugin: {plugin_id}"}
        try:
            return plug["run"](target, options or {})
        except Exception as exc:
            return {"error": str(exc), "plugin": plugin_id}

    def _load(self, path: Path):
        name = f"epic_osint_plugin_{path.stem}"
        spec = importlib.util.spec_from_file_location(name, path)
        if not spec or not spec.loader:
            raise ImportError(f"Cannot load {path}")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
        return mod
