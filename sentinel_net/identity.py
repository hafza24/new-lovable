from __future__ import annotations

import hashlib
import platform
import socket
import uuid
from pathlib import Path


def get_device_id(path: str) -> str:
    device_path = Path(path)
    if device_path.exists():
        value = device_path.read_text(encoding="utf-8").strip()
        if value:
            return value
    seed = "|".join([socket.gethostname(), platform.node(), str(uuid.getnode()), platform.platform()])
    device_id = "sn-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]
    device_path.parent.mkdir(parents=True, exist_ok=True)
    device_path.write_text(device_id, encoding="utf-8")
    return device_id
