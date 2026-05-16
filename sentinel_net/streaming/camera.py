from __future__ import annotations

from typing import Optional


def capture_camera_jpeg(index: int = 0) -> Optional[bytes]:
    """Capture one webcam frame. Callers must enforce consent first."""
    try:
        import cv2
        ok, frame = cv2.VideoCapture(index).read()
        if not ok:
            return None
        success, encoded = cv2.imencode(".jpg", frame)
        return encoded.tobytes() if success else None
    except Exception:
        return None
