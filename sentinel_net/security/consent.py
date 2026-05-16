from __future__ import annotations

import json
import time
from pathlib import Path


def has_interactive_consent(consent_file: str, feature: str, max_age_seconds: int = 300) -> bool:
    path = Path(consent_file)
    if not path.exists():
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        grant = data.get(feature, {})
        return bool(grant.get("approved")) and time.time() - float(grant.get("timestamp", 0)) <= max_age_seconds
    except Exception:
        return False
