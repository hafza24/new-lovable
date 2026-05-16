#!/usr/bin/env python3
"""
Sentinel Net desktop agent.

This module implements the endpoint-side control plane for Sentinel Net.  It is
built for transparent, organization-managed devices: all monitoring and policy
enforcement should be disclosed to the device owner/user and controlled by a
valid tenant enrollment token.  The agent avoids stealth behavior and only
executes auditable, policy-backed commands from the Sentinel Net backend.

Optional runtime packages for a full Windows deployment:
  - psutil       : richer process/network/system telemetry
  - websockets   : realtime command and event transport
  - cryptography : local queue/config encryption
  - aiohttp      : HTTP sync fallback
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import dataclasses
import hashlib
import hmac
import importlib.util
import json
import logging
import os
import platform
import queue
import secrets
import shutil
import signal
import socket
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib import request as urllib_request

APP_NAME = "Sentinel Net"
AGENT_VERSION = "1.0.0"
DEFAULT_API_URL = "https://api.sentinel-net.example.com"
DEFAULT_WS_URL = "wss://api.sentinel-net.example.com/ws/agent"
DEFAULT_DATA_DIR = Path(os.getenv("PROGRAMDATA", str(Path.home()))) / "SentinelNet"
SAFE_REMOTE_ACTIONS = {
    "force_sync",
    "refresh_policy",
    "show_message",
    "request_diagnostics",
    "restart_agent",
    "set_network_mode",
}


@dataclasses.dataclass(slots=True)
class AgentConfig:
    """Runtime configuration loaded from disk and enrollment state."""

    organization_id: str
    device_id: str
    api_url: str = DEFAULT_API_URL
    websocket_url: str = DEFAULT_WS_URL
    enrollment_token: str | None = None
    device_secret: str | None = None
    hostname: str = dataclasses.field(default_factory=socket.gethostname)
    data_dir: Path = DEFAULT_DATA_DIR
    heartbeat_seconds: int = 15
    telemetry_seconds: int = 30
    sync_seconds: int = 120
    log_level: str = "INFO"
    transparent_mode: bool = True

    @property
    def config_path(self) -> Path:
        return self.data_dir / "agent.json"

    @property
    def queue_path(self) -> Path:
        return self.data_dir / "offline-queue.sqlite3"

    @property
    def policy_path(self) -> Path:
        return self.data_dir / "policy.json"

    @property
    def diagnostics_path(self) -> Path:
        return self.data_dir / "diagnostics.json"

    @classmethod
    def load(cls, path: Path | None = None) -> "AgentConfig":
        config_path = path or DEFAULT_DATA_DIR / "agent.json"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        if not config_path.exists():
            device_id = str(uuid.uuid4())
            generated = cls(
                organization_id=os.getenv("SENTINEL_ORG_ID", "unpaired"),
                device_id=device_id,
                api_url=os.getenv("SENTINEL_API_URL", DEFAULT_API_URL),
                websocket_url=os.getenv("SENTINEL_WS_URL", DEFAULT_WS_URL),
                enrollment_token=os.getenv("SENTINEL_ENROLLMENT_TOKEN"),
                device_secret=secrets.token_urlsafe(32),
                data_dir=config_path.parent,
            )
            generated.save()
            return generated

        payload = json.loads(config_path.read_text(encoding="utf-8"))
        payload["data_dir"] = Path(payload.get("data_dir") or config_path.parent)
        return cls(**payload)

    def save(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        payload = dataclasses.asdict(self)
        payload["data_dir"] = str(self.data_dir)
        tmp = self.config_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(self.config_path)


class JsonFormatter(logging.Formatter):
    """Structured logs for forwarding into the Sentinel Net audit pipeline."""

    def format(self, record: logging.LogRecord) -> str:
        event = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            event["exception"] = self.formatException(record.exc_info)
        return json.dumps(event, separators=(",", ":"))


def configure_logging(config: AgentConfig) -> logging.Logger:
    config.data_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("sentinel.agent")
    logger.setLevel(getattr(logging, config.log_level.upper(), logging.INFO))
    logger.handlers.clear()

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(JsonFormatter())
    logger.addHandler(stream_handler)

    file_handler = logging.FileHandler(config.data_dir / "agent.log", encoding="utf-8")
    file_handler.setFormatter(JsonFormatter())
    logger.addHandler(file_handler)
    return logger


class SecureCodec:
    """Encrypts local queue payloads when cryptography is installed; signs otherwise."""

    def __init__(self, secret: str):
        self.secret = secret.encode("utf-8")
        self._fernet: Any | None = None
        if importlib.util.find_spec("cryptography") is not None:
            from cryptography.fernet import Fernet

            digest = hashlib.sha256(self.secret).digest()
            self._fernet = Fernet(base64.urlsafe_b64encode(digest))

    def seal(self, payload: dict[str, Any]) -> str:
        raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        if self._fernet is not None:
            return self._fernet.encrypt(raw).decode("utf-8")
        signature = hmac.new(self.secret, raw, hashlib.sha256).hexdigest()
        return base64.urlsafe_b64encode(signature.encode("ascii") + b"." + raw).decode("ascii")

    def open(self, token: str) -> dict[str, Any]:
        if self._fernet is not None:
            raw = self._fernet.decrypt(token.encode("utf-8"))
            return json.loads(raw.decode("utf-8"))
        decoded = base64.urlsafe_b64decode(token.encode("ascii"))
        signature, raw = decoded.split(b".", 1)
        expected = hmac.new(self.secret, raw, hashlib.sha256).hexdigest().encode("ascii")
        if not hmac.compare_digest(signature, expected):
            raise ValueError("local payload signature mismatch")
        return json.loads(raw.decode("utf-8"))


class OfflineQueue:
    """Durable queue for telemetry, alerts, and audit events created while offline."""

    def __init__(self, path: Path, codec: SecureCodec):
        self.path = path
        self.codec = codec
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._connect().execute(
            """
            CREATE TABLE IF NOT EXISTS events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              kind TEXT NOT NULL,
              payload TEXT NOT NULL,
              created_at TEXT NOT NULL,
              attempts INTEGER NOT NULL DEFAULT 0
            )
            """
        ).connection.commit()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=30)

    def push(self, kind: str, payload: dict[str, Any]) -> None:
        sealed = self.codec.seal(payload)
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO events(kind, payload, created_at) VALUES (?, ?, ?)",
                (kind, sealed, datetime.now(timezone.utc).isoformat()),
            )

    def peek(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT id, kind, payload, created_at, attempts FROM events ORDER BY id LIMIT ?",
                (limit,),
            ).fetchall()
        events = []
        for row_id, kind, payload, created_at, attempts in rows:
            events.append(
                {
                    "id": row_id,
                    "kind": kind,
                    "payload": self.codec.open(payload),
                    "created_at": created_at,
                    "attempts": attempts,
                }
            )
        return events

    def ack(self, ids: Iterable[int]) -> None:
        ids = list(ids)
        if not ids:
            return
        placeholders = ",".join("?" for _ in ids)
        with self._lock, self._connect() as conn:
            conn.execute(f"DELETE FROM events WHERE id IN ({placeholders})", ids)

    def mark_failed(self, ids: Iterable[int]) -> None:
        ids = list(ids)
        if not ids:
            return
        placeholders = ",".join("?" for _ in ids)
        with self._lock, self._connect() as conn:
            conn.execute(f"UPDATE events SET attempts = attempts + 1 WHERE id IN ({placeholders})", ids)

    def size(self) -> int:
        with self._lock, self._connect() as conn:
            (count,) = conn.execute("SELECT COUNT(*) FROM events").fetchone()
        return int(count)


@dataclasses.dataclass(slots=True)
class PolicyDecision:
    allowed: bool
    reason: str
    action: str = "observe"


class PolicyEngine:
    """Local policy evaluator for network, USB, process, camera, and file decisions."""

    def __init__(self, path: Path, logger: logging.Logger):
        self.path = path
        self.logger = logger
        self.policy: dict[str, Any] = {
            "version": 1,
            "network": {"blocked_domains": [], "allowed_domains": [], "categories": []},
            "processes": {"blocked_names": [], "allowed_publishers": []},
            "usb": {"mode": "audit", "approved_serials": []},
            "camera_microphone": {"mode": "audit", "allowed_apps": []},
            "files": {"sensitive_paths": [], "cloud_upload_detection": True},
        }
        self.load()

    def load(self) -> None:
        if self.path.exists():
            self.policy.update(json.loads(self.path.read_text(encoding="utf-8")))

    def update(self, policy: dict[str, Any]) -> None:
        self.policy = policy
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(policy, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(self.path)
        self.logger.info("policy updated to version %s", policy.get("version", "unknown"))

    def domain(self, domain: str) -> PolicyDecision:
        domain = domain.lower().strip(".")
        network = self.policy.get("network", {})
        if domain in {item.lower() for item in network.get("allowed_domains", [])}:
            return PolicyDecision(True, "explicit allowlist")
        if domain in {item.lower() for item in network.get("blocked_domains", [])}:
            return PolicyDecision(False, "blocked domain", "block")
        return PolicyDecision(True, "no matching network restriction")

    def process(self, name: str, publisher: str | None = None) -> PolicyDecision:
        processes = self.policy.get("processes", {})
        if publisher and publisher in processes.get("allowed_publishers", []):
            return PolicyDecision(True, "trusted publisher")
        if name.lower() in {item.lower() for item in processes.get("blocked_names", [])}:
            return PolicyDecision(False, "blocked process", "terminate_with_audit")
        return PolicyDecision(True, "no matching process restriction")

    def usb(self, serial: str | None) -> PolicyDecision:
        usb_policy = self.policy.get("usb", {})
        mode = usb_policy.get("mode", "audit")
        if mode == "allow":
            return PolicyDecision(True, "usb allowed")
        if serial and serial in usb_policy.get("approved_serials", []):
            return PolicyDecision(True, "approved usb device")
        if mode == "block":
            return PolicyDecision(False, "unapproved usb device", "block")
        if mode == "read_only":
            return PolicyDecision(True, "usb read-only policy", "read_only")
        return PolicyDecision(True, "usb audited")


class TelemetryCollector:
    """Collects low-impact endpoint telemetry for dashboard cards and alerts."""

    def __init__(self, config: AgentConfig):
        self.config = config
        self._last_boot = time.time()

    def collect(self) -> dict[str, Any]:
        payload = {
            "device_id": self.config.device_id,
            "organization_id": self.config.organization_id,
            "agent_version": AGENT_VERSION,
            "hostname": self.config.hostname,
            "platform": platform.platform(),
            "os": {"system": platform.system(), "release": platform.release(), "version": platform.version()},
            "network": self._network_snapshot(),
            "health": self._health_snapshot(),
            "processes": self._process_snapshot(limit=40),
            "protections": self._protection_snapshot(),
            "captured_at": datetime.now(timezone.utc).isoformat(),
        }
        return payload

    def diagnostics(self) -> dict[str, Any]:
        return {
            "device_id": self.config.device_id,
            "version": AGENT_VERSION,
            "paths": {
                "data_dir": str(self.config.data_dir),
                "config": str(self.config.config_path),
                "policy": str(self.config.policy_path),
            },
            "disk_free_bytes": shutil.disk_usage(self.config.data_dir).free,
            "python": sys.version,
            "platform": platform.platform(),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    def _health_snapshot(self) -> dict[str, Any]:
        if importlib.util.find_spec("psutil") is not None:
            import psutil

            boot_time = psutil.boot_time()
            return {
                "cpu_percent": psutil.cpu_percent(interval=0.1),
                "ram_percent": psutil.virtual_memory().percent,
                "disk_percent": psutil.disk_usage(str(Path.home())).percent,
                "battery": self._battery(psutil),
                "uptime_seconds": int(time.time() - boot_time),
            }
        return {
            "cpu_percent": None,
            "ram_percent": None,
            "disk_percent": shutil.disk_usage(Path.home()).used / shutil.disk_usage(Path.home()).total * 100,
            "battery": None,
            "uptime_seconds": int(time.time() - self._last_boot),
        }

    def _battery(self, psutil_module: Any) -> dict[str, Any] | None:
        battery = psutil_module.sensors_battery()
        if battery is None:
            return None
        return {"percent": battery.percent, "plugged": battery.power_plugged}

    def _network_snapshot(self) -> dict[str, Any]:
        local_ip = "0.0.0.0"
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect(("8.8.8.8", 80))
            local_ip = probe.getsockname()[0]
        finally:
            probe.close()
        return {
            "local_ip": local_ip,
            "hostname": socket.getfqdn(),
            "internet_status": "connected" if self._can_resolve("example.com") else "degraded",
            "vpn_detected": self._vpn_detected(),
            "wifi_status": "unknown",
            "firewall_status": "managed_by_policy",
        }

    def _can_resolve(self, hostname: str) -> bool:
        try:
            socket.gethostbyname(hostname)
            return True
        except OSError:
            return False

    def _vpn_detected(self) -> bool:
        if importlib.util.find_spec("psutil") is None:
            return False
        import psutil

        suspicious_terms = ("vpn", "tun", "tap", "wireguard", "tailscale", "zerotier")
        return any(any(term in name.lower() for term in suspicious_terms) for name in psutil.net_if_addrs())

    def _process_snapshot(self, limit: int) -> list[dict[str, Any]]:
        if importlib.util.find_spec("psutil") is None:
            return []
        import psutil

        processes: list[dict[str, Any]] = []
        for proc in psutil.process_iter(["pid", "name", "exe", "username", "create_time", "cpu_percent", "memory_info"]):
            info = proc.info
            memory_info = info.get("memory_info")
            processes.append(
                {
                    "pid": info.get("pid"),
                    "name": info.get("name"),
                    "path": info.get("exe"),
                    "user": info.get("username"),
                    "start_time": info.get("create_time"),
                    "cpu_percent": info.get("cpu_percent"),
                    "ram_bytes": getattr(memory_info, "rss", None),
                    "suspicious_score": self._process_risk(info.get("name") or "", info.get("exe") or ""),
                }
            )
            if len(processes) >= limit:
                break
        return processes

    def _process_risk(self, name: str, path: str) -> int:
        indicators = ("miner", "xmrig", "proxy", "keygen", "mimikatz", "tor", "unknown")
        score = 0
        haystack = f"{name} {path}".lower()
        for indicator in indicators:
            if indicator in haystack:
                score += 20
        if path and ("temp" in path.lower() or "appdata" in path.lower()):
            score += 10
        return min(score, 100)

    def _protection_snapshot(self) -> dict[str, Any]:
        return {
            "network_filtering": "active",
            "file_usb_protection": "audit",
            "camera_microphone_monitoring": "audit",
            "live_streaming": "admin_permission_required",
            "transparent_user_notice": self.config.transparent_mode,
        }


class EventBus:
    """Small in-process pub/sub bus used by collectors and the tray bridge."""

    def __init__(self):
        self._subscribers: list[Callable[[dict[str, Any]], None]] = []
        self._recent: deque[dict[str, Any]] = deque(maxlen=200)

    def subscribe(self, callback: Callable[[dict[str, Any]], None]) -> None:
        self._subscribers.append(callback)

    def publish(self, event: dict[str, Any]) -> None:
        event.setdefault("ts", datetime.now(timezone.utc).isoformat())
        self._recent.append(event)
        for callback in list(self._subscribers):
            callback(event)

    def recent(self) -> list[dict[str, Any]]:
        return list(self._recent)


class RealtimeClient:
    """Authenticated WebSocket client with HTTP fallback for offline-first sync."""

    def __init__(self, config: AgentConfig, queue_store: OfflineQueue, logger: logging.Logger):
        self.config = config
        self.queue = queue_store
        self.logger = logger
        self.inbound: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self.connected = asyncio.Event()

    def auth_headers(self) -> dict[str, str]:
        now = str(int(time.time()))
        signature = hmac.new(
            (self.config.device_secret or "").encode("utf-8"),
            f"{self.config.device_id}:{now}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return {
            "X-Sentinel-Device-Id": self.config.device_id,
            "X-Sentinel-Organization-Id": self.config.organization_id,
            "X-Sentinel-Timestamp": now,
            "X-Sentinel-Signature": signature,
        }

    async def run(self) -> None:
        if importlib.util.find_spec("websockets") is None:
            self.logger.warning("websockets package unavailable; realtime channel disabled")
            while True:
                await asyncio.sleep(60)
        from websockets.asyncio.client import connect

        backoff = 1
        while True:
            try:
                ssl_context = ssl.create_default_context()
                async with connect(
                    self.config.websocket_url,
                    additional_headers=self.auth_headers(),
                    ssl=ssl_context if self.config.websocket_url.startswith("wss://") else None,
                    ping_interval=20,
                    ping_timeout=20,
                    max_size=4 * 1024 * 1024,
                ) as websocket:
                    self.connected.set()
                    backoff = 1
                    await websocket.send(json.dumps({"type": "hello", "device_id": self.config.device_id}))
                    consumer = asyncio.create_task(self._consume(websocket))
                    producer = asyncio.create_task(self._produce(websocket))
                    done, pending = await asyncio.wait(
                        {consumer, producer}, return_when=asyncio.FIRST_EXCEPTION
                    )
                    for task in pending:
                        task.cancel()
                    for task in done:
                        task.result()
            except Exception as exc:  # noqa: BLE001 - connection loop must survive transport failures.
                self.connected.clear()
                self.logger.warning("realtime reconnect scheduled: %s", exc)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 60)

    async def _consume(self, websocket: Any) -> None:
        async for raw in websocket:
            self.inbound.put_nowait(json.loads(raw))

    async def _produce(self, websocket: Any) -> None:
        while True:
            events = self.queue.peek(limit=50)
            if events:
                await websocket.send(json.dumps({"type": "event_batch", "events": events}))
                self.queue.ack(event["id"] for event in events)
            await asyncio.sleep(3)

    async def http_post(self, path: str, payload: dict[str, Any]) -> bool:
        body = json.dumps(payload).encode("utf-8")
        url = f"{self.config.api_url.rstrip('/')}/{path.lstrip('/')}"
        headers = {"Content-Type": "application/json", **self.auth_headers()}
        req = urllib_request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib_request.urlopen(req, timeout=15) as response:
                return 200 <= response.status < 300
        except OSError as exc:
            self.logger.warning("http sync failed: %s", exc)
            return False


class SentinelAgent:
    """Coordinates collectors, policy sync, command execution, and health state."""

    def __init__(self, config: AgentConfig):
        self.config = config
        self.logger = configure_logging(config)
        self.codec = SecureCodec(config.device_secret or "local-development-secret")
        self.queue = OfflineQueue(config.queue_path, self.codec)
        self.policy = PolicyEngine(config.policy_path, self.logger)
        self.telemetry = TelemetryCollector(config)
        self.events = EventBus()
        self.realtime = RealtimeClient(config, self.queue, self.logger)
        self.stop_event = asyncio.Event()
        self.status_path = config.data_dir / "status.json"

    async def run(self) -> None:
        self.logger.info("starting Sentinel Net agent %s", AGENT_VERSION)
        self._write_status("starting")
        tasks = [
            asyncio.create_task(self.realtime.run(), name="realtime"),
            asyncio.create_task(self._heartbeat_loop(), name="heartbeat"),
            asyncio.create_task(self._telemetry_loop(), name="telemetry"),
            asyncio.create_task(self._policy_loop(), name="policy-sync"),
            asyncio.create_task(self._command_loop(), name="commands"),
        ]
        self._install_signal_handlers()
        self._write_status("running")
        await self.stop_event.wait()
        self._write_status("stopping")
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self._write_status("stopped")

    def _install_signal_handlers(self) -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, self.stop_event.set)

    async def _heartbeat_loop(self) -> None:
        while True:
            heartbeat = {
                "type": "heartbeat",
                "device_id": self.config.device_id,
                "organization_id": self.config.organization_id,
                "agent_version": AGENT_VERSION,
                "queue_depth": self.queue.size(),
                "status": "online",
                "ts": datetime.now(timezone.utc).isoformat(),
            }
            self.queue.push("heartbeat", heartbeat)
            self._write_status("running", extra={"queue_depth": self.queue.size()})
            await asyncio.sleep(self.config.heartbeat_seconds)

    async def _telemetry_loop(self) -> None:
        while True:
            payload = self.telemetry.collect()
            self.queue.push("telemetry", payload)
            self.events.publish({"type": "telemetry", "summary": payload.get("health", {})})
            await asyncio.sleep(self.config.telemetry_seconds)

    async def _policy_loop(self) -> None:
        while True:
            # Production deployments should replace this with signed delta-policy
            # downloads from /api/agent/policy and signature verification.
            if self.config.policy_path.exists():
                self.policy.load()
            await asyncio.sleep(self.config.sync_seconds)

    async def _command_loop(self) -> None:
        while True:
            command = await self.realtime.inbound.get()
            await self.handle_command(command)

    async def handle_command(self, command: dict[str, Any]) -> None:
        command_type = command.get("type")
        command_id = command.get("id", str(uuid.uuid4()))
        if command_type not in SAFE_REMOTE_ACTIONS:
            self.queue.push(
                "command_rejected",
                {"id": command_id, "type": command_type, "reason": "unsupported_or_unsafe_action"},
            )
            return

        handlers: dict[str, Callable[[dict[str, Any]], Any]] = {
            "force_sync": self._cmd_force_sync,
            "refresh_policy": self._cmd_refresh_policy,
            "show_message": self._cmd_show_message,
            "request_diagnostics": self._cmd_diagnostics,
            "restart_agent": self._cmd_restart_agent,
            "set_network_mode": self._cmd_set_network_mode,
        }
        result = handlers[command_type](command)
        self.queue.push("command_result", {"id": command_id, "type": command_type, "result": result})

    def _cmd_force_sync(self, _command: dict[str, Any]) -> dict[str, Any]:
        return {"queued_events": self.queue.size(), "sync": "scheduled"}

    def _cmd_refresh_policy(self, command: dict[str, Any]) -> dict[str, Any]:
        policy = command.get("policy")
        if isinstance(policy, dict):
            self.policy.update(policy)
            return {"policy_version": policy.get("version"), "updated": True}
        return {"updated": False, "reason": "no policy payload"}

    def _cmd_show_message(self, command: dict[str, Any]) -> dict[str, Any]:
        message = {
            "title": command.get("title", APP_NAME),
            "body": command.get("body", "Your administrator sent a Sentinel Net notification."),
            "severity": command.get("severity", "info"),
            "ts": datetime.now(timezone.utc).isoformat(),
        }
        inbox = self.config.data_dir / "admin-messages.jsonl"
        with inbox.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(message) + "\n")
        self.events.publish({"type": "admin_message", **message})
        return {"delivered_to_tray": True}

    def _cmd_diagnostics(self, _command: dict[str, Any]) -> dict[str, Any]:
        diagnostics = self.telemetry.diagnostics()
        self.config.diagnostics_path.write_text(json.dumps(diagnostics, indent=2), encoding="utf-8")
        self.queue.push("diagnostics", diagnostics)
        return {"path": str(self.config.diagnostics_path)}

    def _cmd_restart_agent(self, _command: dict[str, Any]) -> dict[str, Any]:
        # The watchdog or service manager performs the actual restart after this
        # process exits cleanly.  This keeps restart behavior auditable.
        self.stop_event.set()
        return {"restart_requested": True}

    def _cmd_set_network_mode(self, command: dict[str, Any]) -> dict[str, Any]:
        mode = command.get("mode", "monitor")
        if mode not in {"monitor", "filter", "offline"}:
            return {"updated": False, "reason": "invalid network mode"}
        status = self._read_status()
        status["network_mode"] = mode
        self._write_status(status.get("state", "running"), status)
        return {"network_mode": mode}

    def _write_status(self, state: str, extra: dict[str, Any] | None = None) -> None:
        payload = self._read_status()
        payload.update(
            {
                "state": state,
                "device_id": self.config.device_id,
                "organization_id": self.config.organization_id,
                "version": AGENT_VERSION,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        if extra:
            payload.update(extra)
        tmp = self.status_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(self.status_path)

    def _read_status(self) -> dict[str, Any]:
        if self.status_path.exists():
            return json.loads(self.status_path.read_text(encoding="utf-8"))
        return {}


def enroll(config: AgentConfig, logger: logging.Logger) -> None:
    """Create local enrollment metadata for installer-driven pairing."""

    if config.organization_id == "unpaired" and not config.enrollment_token:
        logger.warning("agent is unpaired; set SENTINEL_ORG_ID and SENTINEL_ENROLLMENT_TOKEN during install")
    config.save()


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Sentinel Net endpoint agent")
    parser.add_argument("--config", type=Path, help="Path to agent.json")
    parser.add_argument("--enroll", action="store_true", help="Write enrollment/configuration and exit")
    parser.add_argument("--diagnostics", action="store_true", help="Write diagnostics and exit")
    return parser


async def async_main(args: argparse.Namespace) -> int:
    config = AgentConfig.load(args.config)
    logger = configure_logging(config)
    if args.enroll:
        enroll(config, logger)
        return 0
    agent = SentinelAgent(config)
    if args.diagnostics:
        config.diagnostics_path.write_text(json.dumps(agent.telemetry.diagnostics(), indent=2), encoding="utf-8")
        return 0
    await agent.run()
    return 0


def main() -> int:
    args = build_arg_parser().parse_args()
    return asyncio.run(async_main(args))


if __name__ == "__main__":
    raise SystemExit(main())
