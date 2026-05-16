#!/usr/bin/env python3
"""
Sentinel Net watchdog service.

The watchdog supervises the visible agent and tray processes for reliability on
managed devices.  It performs health checks, restarts crashed components, writes
service status for the dashboard, and honors user/admin uninstall workflow
signals.  It does not hide processes, bypass user controls, or interfere with
legitimate administrator removal tools.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import logging
import os
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO

APP_NAME = "Sentinel Net"
WATCHDOG_VERSION = "1.0.0"
DEFAULT_DATA_DIR = Path(os.getenv("PROGRAMDATA", str(Path.home()))) / "SentinelNet"
DEFAULT_ROOT = Path(__file__).resolve().parent


@dataclasses.dataclass(slots=True)
class ManagedProcess:
    name: str
    command: list[str]
    required: bool = True
    restart_backoff_seconds: int = 5
    max_backoff_seconds: int = 120
    process: subprocess.Popen[str] | None = None
    restart_count: int = 0
    last_started_at: float = 0
    last_exit_code: int | None = None
    log_handle: TextIO | None = None

    def running(self) -> bool:
        return self.process is not None and self.process.poll() is None


class WatchdogConfig:
    def __init__(self, data_dir: Path, root_dir: Path, tray: bool):
        self.data_dir = data_dir
        self.root_dir = root_dir
        self.tray = tray
        self.status_path = data_dir / "watchdog-status.json"
        self.uninstall_request_path = data_dir / "uninstall-request.json"
        self.restart_request_path = data_dir / "restart-requested.flag"
        self.diagnostics_request_path = data_dir / "diagnostics-requested.flag"
        self.integrity_manifest_path = data_dir / "integrity-manifest.json"

    def processes(self) -> list[ManagedProcess]:
        python = sys.executable
        processes = [
            ManagedProcess("agent", [python, str(self.root_dir / "Agent.py")]),
        ]
        if self.tray:
            processes.append(ManagedProcess("tray", [python, str(self.root_dir / "tray.py")], required=False))
        return processes


class Watchdog:
    """Reliability supervisor for Sentinel Net endpoint components."""

    def __init__(self, config: WatchdogConfig):
        self.config = config
        self.config.data_dir.mkdir(parents=True, exist_ok=True)
        self.logger = self._configure_logging()
        self.processes = config.processes()
        self.stop = threading.Event()

    def _configure_logging(self) -> logging.Logger:
        logger = logging.getLogger("sentinel.watchdog")
        logger.setLevel(logging.INFO)
        logger.handlers.clear()
        formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
        stream = logging.StreamHandler()
        stream.setFormatter(formatter)
        file_handler = logging.FileHandler(self.config.data_dir / "watchdog.log", encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(stream)
        logger.addHandler(file_handler)
        return logger

    def install_signal_handlers(self) -> None:
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda _sig, _frame: self.stop.set())

    def run(self) -> int:
        self.install_signal_handlers()
        self.logger.info("starting Sentinel Net watchdog %s", WATCHDOG_VERSION)
        self.ensure_manifest()
        while not self.stop.is_set():
            self.check_uninstall_request()
            self.check_restart_request()
            self.check_diagnostics_request()
            self.check_integrity()
            for proc in self.processes:
                self.ensure_running(proc)
            self.write_status()
            self.stop.wait(3)
        self.shutdown()
        self.write_status(state="stopped")
        return 0

    def ensure_running(self, proc: ManagedProcess) -> None:
        if proc.running():
            return
        if proc.process is not None:
            proc.last_exit_code = proc.process.poll()
            self.logger.warning("%s exited with code %s", proc.name, proc.last_exit_code)
        delay = min(proc.restart_backoff_seconds * max(proc.restart_count, 1), proc.max_backoff_seconds)
        if proc.last_started_at and time.time() - proc.last_started_at < delay:
            return
        stdout_path = self.config.data_dir / f"{proc.name}.stdout.log"
        proc.log_handle = stdout_path.open("a", encoding="utf-8")
        proc.process = subprocess.Popen(
            proc.command,
            cwd=str(self.config.root_dir),
            stdout=proc.log_handle,
            stderr=subprocess.STDOUT,
            text=True,
        )
        proc.restart_count += 1
        proc.last_started_at = time.time()
        self.logger.info("started %s pid=%s", proc.name, proc.process.pid)

    def check_restart_request(self) -> None:
        if not self.config.restart_request_path.exists():
            return
        self.config.restart_request_path.unlink(missing_ok=True)
        self.logger.info("restart requested by tray/admin workflow")
        for proc in self.processes:
            if proc.name == "agent":
                self.stop_process(proc, timeout=10)

    def check_diagnostics_request(self) -> None:
        if not self.config.diagnostics_request_path.exists():
            return
        self.config.diagnostics_request_path.unlink(missing_ok=True)
        diagnostics = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "watchdog_version": WATCHDOG_VERSION,
            "processes": [self.process_status(proc) for proc in self.processes],
            "integrity": self.integrity_report(),
        }
        (self.config.data_dir / "watchdog-diagnostics.json").write_text(
            json.dumps(diagnostics, indent=2, sort_keys=True), encoding="utf-8"
        )
        self.logger.info("watchdog diagnostics generated")

    def check_uninstall_request(self) -> None:
        if not self.config.uninstall_request_path.exists():
            return
        request = json.loads(self.config.uninstall_request_path.read_text(encoding="utf-8"))
        if request.get("status") == "approved":
            self.logger.info("approved uninstall request observed; stopping supervised components")
            self.stop.set()
        else:
            self.logger.info("uninstall request pending approval")

    def ensure_manifest(self) -> None:
        if self.config.integrity_manifest_path.exists():
            return
        manifest = self.integrity_report()
        self.config.integrity_manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    def check_integrity(self) -> None:
        if not self.config.integrity_manifest_path.exists():
            return
        expected = json.loads(self.config.integrity_manifest_path.read_text(encoding="utf-8"))
        current = self.integrity_report()
        changed = [path for path, digest in expected.items() if current.get(path) != digest]
        if changed:
            self.logger.warning("component integrity changed: %s", ", ".join(changed))

    def integrity_report(self) -> dict[str, str | None]:
        report: dict[str, str | None] = {}
        for filename in ("Agent.py", "tray.py", "watchdog.py"):
            path = self.config.root_dir / filename
            report[filename] = self.sha256(path) if path.exists() else None
        return report

    def sha256(self, path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def process_status(self, proc: ManagedProcess) -> dict[str, object]:
        return {
            "name": proc.name,
            "running": proc.running(),
            "pid": proc.process.pid if proc.process and proc.running() else None,
            "restart_count": proc.restart_count,
            "last_exit_code": proc.last_exit_code,
            "last_started_at": proc.last_started_at,
            "required": proc.required,
        }

    def write_status(self, state: str = "running") -> None:
        payload = {
            "state": state,
            "version": WATCHDOG_VERSION,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "processes": [self.process_status(proc) for proc in self.processes],
        }
        tmp = self.config.status_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(self.config.status_path)

    def stop_process(self, proc: ManagedProcess, timeout: int) -> None:
        if not proc.running():
            return
        assert proc.process is not None
        proc.process.terminate()
        try:
            proc.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.logger.warning("%s did not stop gracefully; killing", proc.name)
            proc.process.kill()
            proc.process.wait(timeout=5)
        if proc.log_handle is not None:
            proc.log_handle.close()
            proc.log_handle = None

    def shutdown(self) -> None:
        self.logger.info("stopping Sentinel Net watchdog")
        for proc in self.processes:
            self.stop_process(proc, timeout=10)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Sentinel Net watchdog service")
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument("--root-dir", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--no-tray", action="store_true", help="Do not supervise the tray application")
    parser.add_argument("--write-manifest", action="store_true", help="Write integrity manifest and exit")
    parser.add_argument("--status", action="store_true", help="Print watchdog status and exit")
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()
    config = WatchdogConfig(args.data_dir, args.root_dir, tray=not args.no_tray)
    watchdog = Watchdog(config)
    if args.write_manifest:
        manifest = watchdog.integrity_report()
        config.integrity_manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        print(config.integrity_manifest_path)
        return 0
    if args.status:
        if config.status_path.exists():
            print(config.status_path.read_text(encoding="utf-8"))
            return 0
        print("watchdog status unavailable")
        return 1
    return watchdog.run()


if __name__ == "__main__":
    raise SystemExit(main())
