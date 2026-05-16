from __future__ import annotations

import subprocess
from pathlib import Path


def install_service(name: str, display: str, exe_path: str) -> None:
    subprocess.run(["sc", "create", name, "binPath=", str(Path(exe_path)), "start=", "auto", "DisplayName=", display], check=False)


def start_service(name: str) -> None:
    subprocess.run(["sc", "start", name], check=False)


def stop_delete_service(name: str) -> None:
    subprocess.run(["sc", "stop", name], check=False)
    subprocess.run(["sc", "delete", name], check=False)
