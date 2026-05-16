from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Iterable


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def build_manifest(files: Iterable[Path], manifest_path: str) -> dict[str, str]:
    manifest = {str(path): sha256(path) for path in files if path.exists() and path.is_file()}
    Path(manifest_path).parent.mkdir(parents=True, exist_ok=True)
    Path(manifest_path).write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    return manifest


def validate_manifest(manifest_path: str) -> dict[str, list[str]]:
    path = Path(manifest_path)
    result = {"missing": [], "changed": []}
    if not path.exists():
        return result
    manifest = json.loads(path.read_text(encoding="utf-8"))
    for file_name, expected in manifest.items():
        file_path = Path(file_name)
        if not file_path.exists():
            result["missing"].append(file_name)
        elif sha256(file_path) != expected:
            result["changed"].append(file_name)
    return result
