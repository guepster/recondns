from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, cast


BASE = Path("data")


def _domain_dir(domain: str) -> Path:
    d = BASE / domain
    d.mkdir(parents=True, exist_ok=True)
    return d


def save_snapshot(domain: str, result: dict[str, Any], label: str | None = None) -> Path:
    ts = time.strftime("%Y%m%d_%H%M%S")
    name = f"{ts}.json" if not label else f"{ts}_{label}.json"
    path = _domain_dir(domain) / name
    with path.open("w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2, sort_keys=True)
    return path


def list_snapshots(domain: str) -> list[Path]:
    d = _domain_dir(domain)
    return sorted(p for p in d.glob("*.json") if p.is_file())


def load_snapshot(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Snapshot {path} is not a JSON object")
    return cast(dict[str, Any], data)


def latest_snapshot(domain: str) -> Path | None:
    snaps = list_snapshots(domain)
    return snaps[-1] if snaps else None
