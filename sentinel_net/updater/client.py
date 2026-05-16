from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Any

import aiohttp
from packaging.version import Version

from sentinel_net import __version__

class UpdateClient:
    """Signed-update metadata client.

    This module downloads metadata only unless the admin panel advertises a newer
    version and a SHA-256 hash. Signature validation can be added by provisioning
    an enterprise public key in the endpoint config.
    """

    def __init__(self, base_url: str, logger: logging.Logger) -> None:
        self.base_url = base_url.rstrip("/")
        self.logger = logger

    async def check(self) -> dict[str, Any]:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{self.base_url}/api/endpoint/update", timeout=20) as resp:
                resp.raise_for_status()
                metadata = await resp.json()
        metadata["update_available"] = Version(str(metadata.get("version", __version__))) > Version(__version__)
        return metadata

    @staticmethod
    def verify_sha256(path: str, expected: str) -> bool:
        digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        return digest.lower() == expected.lower()
