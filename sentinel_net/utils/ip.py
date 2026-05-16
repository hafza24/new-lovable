from __future__ import annotations

import requests


def public_ip(timeout: int = 5) -> str:
    try:
        return requests.get("https://api.ipify.org", timeout=timeout).text.strip()
    except Exception:
        return "unknown"
