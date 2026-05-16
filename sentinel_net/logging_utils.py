from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path


def configure_logging(name: str, log_dir: str, level: str = "INFO") -> logging.Logger:
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()
    formatter = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
    file_handler = RotatingFileHandler(Path(log_dir) / f"{name}.log", maxBytes=5_000_000, backupCount=5, encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    stream = logging.StreamHandler()
    stream.setFormatter(formatter)
    logger.addHandler(stream)
    return logger
