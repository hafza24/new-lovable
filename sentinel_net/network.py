from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Awaitable, Callable

import aiohttp
import websockets
from cryptography.fernet import Fernet

MessageHandler = Callable[[dict[str, Any]], Awaitable[None]]

class SecureChannel:
    """Encrypted transport wrapper for websocket + REST fallback."""

    def __init__(self, config: dict[str, Any], device_id: str, logger: logging.Logger) -> None:
        self.config = config
        self.device_id = device_id
        self.logger = logger
        self.session: aiohttp.ClientSession | None = None
        self.ws: websockets.WebSocketClientProtocol | None = None
        self.connected = False
        # Production deployments should provision this from the admin panel.
        key_material = config.get("channel_key") or Fernet.generate_key().decode("ascii")
        self.fernet = Fernet(key_material.encode("ascii") if isinstance(key_material, str) else key_material)

    async def __aenter__(self) -> "SecureChannel":
        self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30))
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self.ws:
            await self.ws.close()
        if self.session:
            await self.session.close()

    def _headers(self) -> dict[str, str]:
        return {"X-Sentinel-Device": self.device_id, "X-Sentinel-Tenant": self.config.get("tenant_id", ""), "Authorization": f"Bearer {self.config.get('registration_token', '')}"}

    def encode(self, payload: dict[str, Any]) -> str:
        return self.fernet.encrypt(json.dumps(payload, default=str).encode("utf-8")).decode("ascii")

    def decode(self, payload: str) -> dict[str, Any]:
        return json.loads(self.fernet.decrypt(payload.encode("ascii")).decode("utf-8"))

    async def post(self, path: str, payload: dict[str, Any]) -> bool:
        if not self.session:
            self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30))
        url = self.config["base_url"].rstrip("/") + path
        try:
            async with self.session.post(url, json={"payload": self.encode(payload)}, headers=self._headers(), ssl=self.config.get("tls_verify", True)) as resp:
                if resp.status < 300:
                    return True
                self.logger.warning("REST post failed status=%s path=%s", resp.status, path)
        except Exception as exc:
            self.logger.warning("REST post error path=%s error=%s", path, exc)
        return False

    async def connect_ws(self, handler: MessageHandler) -> None:
        uri = self.config["websocket_url"]
        async with websockets.connect(uri, extra_headers=self._headers(), ping_interval=20, ping_timeout=20) as ws:
            self.ws = ws
            self.connected = True
            await ws.send(self.encode({"type": "hello", "device_id": self.device_id}))
            async for raw in ws:
                try:
                    await handler(self.decode(raw))
                except Exception as exc:
                    self.logger.exception("message handler failed: %s", exc)
        self.connected = False

    async def send_ws(self, payload: dict[str, Any]) -> bool:
        if not self.ws:
            return False
        try:
            await self.ws.send(self.encode(payload))
            return True
        except Exception as exc:
            self.logger.warning("websocket send failed: %s", exc)
            self.connected = False
            return False
