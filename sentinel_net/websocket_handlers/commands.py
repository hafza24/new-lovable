from __future__ import annotations

import asyncio
import logging
import os
import subprocess
from typing import Any

import psutil

from sentinel_net.database.store import EndpointStore
from sentinel_net.security.consent import has_interactive_consent

SAFE_TIMEOUT_SECONDS = 30

class RemoteCommandRouter:
    """Audited, policy-limited remote action handler.

    Destructive or privacy-sensitive capabilities are disabled by default and require
    explicit policy plus local interactive consent where applicable.
    """

    def __init__(self, config: dict[str, Any], store: EndpointStore, logger: logging.Logger) -> None:
        self.config = config
        self.store = store
        self.logger = logger

    async def handle(self, message: dict[str, Any]) -> dict[str, Any]:
        command_type = message.get("type")
        payload = message.get("payload", {})
        self.store.audit("INFO", "remote_command_received", {"type": command_type})
        if command_type == "ping":
            return {"type": "pong"}
        if command_type == "process.list":
            return {"type": "process.list.result", "processes": [p.info for p in psutil.process_iter(["pid", "name", "username", "status", "memory_percent"])]}
        if command_type == "process.terminate":
            return self._terminate_process(payload)
        if command_type == "command.exec":
            return await self._exec(payload)
        if command_type in {"screen.stream", "camera.stream", "clipboard.sync", "file.explorer"}:
            return self._privacy_gated(command_type)
        if command_type in {"device.restart", "device.shutdown"}:
            return await self._power(command_type)
        return {"type": "error", "error": f"unsupported command: {command_type}"}

    def _terminate_process(self, payload: dict[str, Any]) -> dict[str, Any]:
        pid = int(payload.get("pid", 0))
        if pid <= 0:
            return {"type": "error", "error": "pid required"}
        proc = psutil.Process(pid)
        proc.terminate()
        return {"type": "process.terminate.result", "pid": pid, "status": "terminated"}

    async def _exec(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not self.config["agent"].get("allow_remote_command", False):
            return {"type": "command.exec.denied", "reason": "remote command disabled by endpoint policy"}
        command = str(payload.get("command", "")).strip()
        allowed = set(self.config["agent"].get("allowed_commands", []))
        executable = command.split()[0].lower() if command else ""
        if executable not in {cmd.lower() for cmd in allowed}:
            return {"type": "command.exec.denied", "reason": "command is not in allowlist"}
        proc = await asyncio.create_subprocess_shell(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=SAFE_TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            proc.kill()
            return {"type": "command.exec.result", "returncode": -1, "stderr": "timeout"}
        return {"type": "command.exec.result", "returncode": proc.returncode, "stdout": stdout.decode(errors="replace")[-16000:], "stderr": stderr.decode(errors="replace")[-16000:]}

    def _privacy_gated(self, feature: str) -> dict[str, Any]:
        feature_key = feature.replace(".", "_")
        if not self.config["features"].get(feature_key, False):
            return {"type": f"{feature}.denied", "reason": "feature disabled by endpoint policy"}
        if self.config["agent"].get("require_interactive_consent_for_streaming", True) and not has_interactive_consent(self.config["paths"]["consent_file"], feature_key):
            return {"type": f"{feature}.denied", "reason": "local interactive consent required"}
        return {"type": f"{feature}.ready", "status": "consented"}

    async def _power(self, command_type: str) -> dict[str, Any]:
        allowed = self.config["agent"].get("allow_remote_restart" if command_type.endswith("restart") else "allow_remote_shutdown", False)
        if not allowed:
            return {"type": f"{command_type}.denied", "reason": "power action disabled by endpoint policy"}
        if os.name == "nt":
            subprocess.Popen(["shutdown", "/r" if command_type.endswith("restart") else "/s", "/t", "60", "/c", "Sentinel Net approved remote power action"])
            return {"type": f"{command_type}.scheduled", "delay_seconds": 60}
        return {"type": f"{command_type}.denied", "reason": "power action only implemented on Windows"}
