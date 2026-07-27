"""Investigation cases — persist multi-target scan sessions."""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

_SAFE = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")


class CaseManager:
    """File-backed investigation cases under cases/."""

    def __init__(self, root: str = "cases"):
        self.root = Path(root)
        self.root.mkdir(exist_ok=True)

    def list_cases(self) -> List[Dict[str, Any]]:
        out = []
        for p in sorted(self.root.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                out.append({
                    "id": p.stem,
                    "name": data.get("name", p.stem),
                    "targets": len(data.get("targets") or []),
                    "scans": len(data.get("scans") or []),
                    "updated": data.get("updated"),
                    "path": str(p),
                })
            except (OSError, ValueError):
                continue
        return out

    def create(self, name: str, targets: Optional[List[str]] = None) -> Dict[str, Any]:
        cid = self._slug(name)
        path = self.root / f"{cid}.json"
        if path.exists():
            return {"error": "Case already exists", "id": cid}
        case = {
            "id": cid,
            "name": name.strip() or cid,
            "created": datetime.utcnow().isoformat() + "Z",
            "updated": datetime.utcnow().isoformat() + "Z",
            "targets": list(targets or []),
            "scans": [],
            "notes": "",
        }
        self._write(path, case)
        return case

    def load(self, case_id: str) -> Dict[str, Any]:
        path = self._path(case_id)
        if not path:
            return {"error": "Invalid case id"}
        if not path.exists():
            return {"error": "Case not found", "id": case_id}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return {"error": str(exc)}

    def add_targets(self, case_id: str, targets: List[str]) -> Dict[str, Any]:
        case = self.load(case_id)
        if case.get("error"):
            return case
        existing = set(case.get("targets") or [])
        for t in targets:
            t = (t or "").strip()
            if t and t not in existing:
                case.setdefault("targets", []).append(t)
                existing.add(t)
        case["updated"] = datetime.utcnow().isoformat() + "Z"
        self._write(self._path(case_id), case)
        return case

    def attach_scan(self, case_id: str, scan_summary: Dict[str, Any]) -> Dict[str, Any]:
        case = self.load(case_id)
        if case.get("error"):
            return case
        case.setdefault("scans", []).append({
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "target": scan_summary.get("target"),
            "scan_type": scan_summary.get("scan_type"),
            "report": scan_summary.get("report_path"),
            "counts": scan_summary.get("counts") or {},
        })
        case["updated"] = datetime.utcnow().isoformat() + "Z"
        # auto-add target
        t = scan_summary.get("target")
        if t and t not in (case.get("targets") or []):
            case.setdefault("targets", []).append(t)
        self._write(self._path(case_id), case)
        return case

    def delete(self, case_id: str) -> Dict[str, Any]:
        path = self._path(case_id)
        if not path or not path.exists():
            return {"error": "Case not found"}
        try:
            path.unlink()
            return {"deleted": case_id}
        except OSError as exc:
            return {"error": str(exc)}

    def import_targets_file(self, case_id: str, filepath: str) -> Dict[str, Any]:
        path = Path(filepath).expanduser()
        try:
            resolved = path.resolve()
            # allow under cwd only
            resolved.relative_to(Path.cwd().resolve())
        except (ValueError, OSError):
            return {"error": "Targets file must be under current working directory"}
        try:
            lines = [
                ln.strip() for ln in resolved.read_text(encoding="utf-8", errors="replace").splitlines()
                if ln.strip() and not ln.strip().startswith("#")
            ]
        except OSError as exc:
            return {"error": str(exc)}
        return self.add_targets(case_id, lines[:500])

    def _slug(self, name: str) -> str:
        s = re.sub(r"[^A-Za-z0-9_\-]+", "-", (name or "case").strip())[:48].strip("-") or "case"
        s = f"{s}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        return s

    def _path(self, case_id: str) -> Optional[Path]:
        if not case_id or not _SAFE.match(case_id):
            return None
        return self.root / f"{case_id}.json"

    @staticmethod
    def _write(path: Path, data: Dict) -> None:
        path.parent.mkdir(exist_ok=True)
        path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
