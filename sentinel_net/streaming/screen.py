from __future__ import annotations

from io import BytesIO
from typing import Optional

from PIL import Image


def capture_screenshot_jpeg(max_width: int = 1280, quality: int = 65) -> Optional[bytes]:
    """Capture a single screenshot frame. Callers must enforce consent first."""
    try:
        import mss
        with mss.mss() as sct:
            shot = sct.grab(sct.monitors[0])
            image = Image.frombytes("RGB", shot.size, shot.rgb)
            if image.width > max_width:
                ratio = max_width / image.width
                image = image.resize((max_width, int(image.height * ratio)))
            buf = BytesIO()
            image.save(buf, format="JPEG", quality=quality)
            return buf.getvalue()
    except Exception:
        return None
