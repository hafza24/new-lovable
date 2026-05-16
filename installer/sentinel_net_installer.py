#!/usr/bin/env python3
"""
Sentinel Net Windows installer/repair/uninstall-request utility.

This installer is intentionally transparent and administrator-approved. It does
not hide itself, disable security tooling, bypass user consent, or create
stealth persistence. Operations that modify Windows are only executed with
--apply; otherwise the script runs in dry-run mode and writes the exact plan.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import logging
import os
import platform
import shutil
import socket
import ssl
import subprocess
import sys
import time
import uuid
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

PRODUCT_NAME = "Sentinel Net"
VENDOR_NAME = "SentinelNet"
DEFAULT_VERSION = "1.0.0"
DEFAULT_INSTALL_ROOT = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "SentinelNet"
DEFAULT_DATA_ROOT = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "SentinelNet"
DEFAULT_MANIFEST = Path(__file__).with_name("sentinel_net_payload.json")

APP_DIRS = [
    "Agent",
    "Tray",
    "Watchdog",
    "Services",
    "Logs",
    "Config",
    "Updates",
    "Temp",
    "Drivers",
]

SERVICE_DEFINITIONS = {
    "SentinelNetAgent": {
        "display": "Sentinel Net Agent",
        "binary": r"Agent\sentinel_agent.exe",
        "description": "Core Sentinel Net endpoint policy and telemetry service.",
        "start": "delayed-auto",
    },
    "SentinelNetWatchdog": {
        "display": "Sentinel Net Watchdog",
        "binary": r"Watchdog\sentinel_watchdog.exe",
        "description": "Health monitoring and approved repair orchestration service.",
        "start": "auto",
    },
    "SentinelNetSync": {
        "display": "Sentinel Net Sync",
        "binary": r"Services\sentinel_sync.exe",
        "description": "Cloud/database inventory and policy synchronization service.",
        "start": "delayed-auto",
    },
    "SentinelNetFirewall": {
        "display": "Sentinel Net Firewall Monitor",
        "binary": r"Services\sentinel_firewall_monitor.exe",
        "description": "Firewall policy validation and drift reporting service.",
        "start": "demand",
    },
    "SentinelNetCommandQueue": {
        "display": "Sentinel Net Admin Command Queue",
        "binary": r"Services\sentinel_command_queue.exe",
        "description": "Admin-approved command queue listener for audited response actions.",
        "start": "delayed-auto",
    },
    "SentinelNetCamera": {
        "display": "Sentinel Net Camera Consent Service",
        "binary": r"Services\sentinel_camera_service.exe",
        "description": "Consent-aware camera diagnostics service.",
        "start": "demand",
    },
    "SentinelNetStream": {
        "display": "Sentinel Net Stream Service",
        "binary": r"Services\sentinel_stream_service.exe",
        "description": "Administrator-approved live diagnostics streaming service.",
        "start": "demand",
    },
}

DEPENDENCY_CHECKS = {
    "python": [sys.executable, "--version"],
    "vc_redist_hint": ["where", "vcruntime140.dll"],
    "webview2_hint": ["reg", "query", r"HKLM\SOFTWARE\Microsoft\EdgeUpdate\Clients"],
    "ffmpeg_optional": ["where", "ffmpeg"],
}


@dataclass
class PayloadItem:
    source: str
    destination: str
    sha256: str | None = None
    required: bool = True


@dataclass
class InstallerManifest:
    version: str = DEFAULT_VERSION
    files: list[PayloadItem] = field(default_factory=list)
    configs: dict[str, object] = field(default_factory=dict)
    firewall_ports: list[int] = field(default_factory=lambda: [443])
    registration_url: str | None = None
    organization_id: str | None = None
    pairing_code: str | None = None


class InstallerError(RuntimeError):
    """Raised when an installer operation fails."""


class SentinelNetInstaller:
    def __init__(
        self,
        *,
        mode: str,
        package_type: str,
        source_root: Path,
        install_root: Path,
        data_root: Path,
        manifest_path: Path,
        apply: bool,
        silent: bool,
        quick: bool,
        accept_license: bool,
        keep_logs_on_uninstall: bool,
    ) -> None:
        self.mode = mode
        self.package_type = package_type
        self.source_root = source_root.resolve()
        self.install_root = install_root
        self.data_root = data_root
        self.manifest_path = manifest_path
        self.apply = apply
        self.silent = silent
        self.quick = quick
        self.accept_license = accept_license
        self.keep_logs_on_uninstall = keep_logs_on_uninstall
        self.preexisting_install = self.install_root.exists() or self.data_root.exists()
        self.log_path = self.data_root / "Logs" / "installer.log"
        self.device_id_path = self.data_root / "Config" / "device.json"
        self.manifest = self.load_manifest(manifest_path)
        self.rollback_actions: list[tuple[str, Path]] = []

    def run(self) -> None:
        self.configure_logging()
        self.banner()
        self.run_wizard_if_needed()
        self.validate_admin_intent()
        self.detect_previous_installation()

        if self.mode == "repair":
            self.repair()
        elif self.mode == "upgrade":
            self.upgrade()
        elif self.mode == "uninstall-request":
            self.request_uninstall()
        else:
            self.install()

    def configure_logging(self) -> None:
        if self.apply:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
        handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
        if self.apply or self.log_path.parent.exists():
            handlers.append(logging.FileHandler(self.log_path, encoding="utf-8"))
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(message)s",
            handlers=handlers,
            force=True,
        )

    def banner(self) -> None:
        logging.info("%s installer %s mode=%s package=%s", PRODUCT_NAME, self.manifest.version, self.mode, self.package_type)
        if not self.apply:
            logging.info("DRY RUN: pass --apply from an elevated shell to perform changes")

    def run_wizard_if_needed(self) -> None:
        if self.silent or self.quick or not sys.stdin.isatty():
            if not self.accept_license:
                logging.info("License acceptance is required for production deployment; dry-run continues for planning")
            return

        print("\n=== Sentinel Net Enterprise Setup ===")
        print("This wizard installs transparent, administrator-approved endpoint components.")
        if not self.accept_license:
            accepted = input("Accept the Sentinel Net license agreement? [y/N] ").strip().lower()
            if accepted not in {"y", "yes"}:
                raise InstallerError("License agreement was not accepted")
            self.accept_license = True

        mode = input(f"Install mode [{self.mode}] (fresh/repair/upgrade/uninstall-request): ").strip()
        if mode:
            if mode not in {"fresh", "repair", "upgrade", "uninstall-request"}:
                raise InstallerError(f"Invalid install mode: {mode}")
            self.mode = mode

        install_root = input(f"Install path [{self.install_root}]: ").strip()
        if install_root:
            self.install_root = Path(install_root)
        logging.info("Wizard selected mode=%s install_root=%s", self.mode, self.install_root)

    def validate_admin_intent(self) -> None:
        if not is_windows():
            logging.warning("Windows changes are unavailable on %s; command execution will be skipped", platform.system())
            return
        if not is_admin():
            message = "Administrator privileges are required for service, firewall, registry, and Program Files changes."
            if self.apply:
                raise InstallerError(message)
            logging.warning(message)

    def detect_previous_installation(self) -> None:
        if self.preexisting_install:
            logging.info("Previous installation detected at %s / %s", self.install_root, self.data_root)
        else:
            logging.info("No previous installation detected; fresh install path is available")

    def install(self) -> None:
        self.create_directories()
        self.check_dependencies()
        self.copy_payload()
        self.write_configuration()
        self.register_services()
        self.configure_service_recovery()
        self.create_shortcuts()
        self.create_startup_entry()
        self.add_firewall_rules()
        self.validate_services()
        self.register_device()
        logging.info("Install completed")

    def repair(self) -> None:
        logging.info("Repair mode: restoring files, services, startup entries, firewall rules, and sync state")
        self.create_directories()
        self.check_dependencies()
        self.copy_payload()
        self.write_configuration()
        self.register_services(repair=True)
        self.configure_service_recovery()
        self.create_shortcuts()
        self.create_startup_entry()
        self.add_firewall_rules()
        self.validate_services()
        self.register_device(reconnect=True)
        logging.info("Repair completed")

    def upgrade(self) -> None:
        logging.info("Upgrade mode: staging version %s with rollback checkpoints", self.manifest.version)
        self.create_directories()
        self.snapshot_current_install()
        try:
            self.check_dependencies()
            self.copy_payload()
            self.write_configuration()
            self.register_services(repair=True)
            self.configure_service_recovery()
            self.validate_services()
            self.register_device(reconnect=True)
            logging.info("Upgrade completed")
        except Exception:
            logging.exception("Upgrade failed; starting rollback")
            self.rollback()
            raise

    def request_uninstall(self) -> None:
        request = {
            "request_id": str(uuid.uuid4()),
            "type": "uninstall",
            "status": "pending_admin_approval",
            "device_id": self.get_or_create_device_id()["device_id"],
            "hostname": socket.gethostname(),
            "timestamp": utc_now(),
            "keep_logs": self.keep_logs_on_uninstall,
            "cleanup_plan": [
                "stop Sentinel Net services",
                "remove services",
                "remove startup entries",
                "remove firewall rules",
                "remove shortcuts",
                "remove Program Files payload",
                "remove ProgramData except logs when requested",
                "schedule reboot cleanup for locked files",
            ],
        }
        target = self.data_root / "Config" / "uninstall_request.json"
        self.write_json(target, request)
        self.post_registration_payload("uninstall-request", request, allow_offline=True)
        logging.info("Uninstall request queued for administrator approval: %s", request["request_id"])

    def create_directories(self) -> None:
        for root in (self.install_root, self.data_root):
            for child in APP_DIRS:
                self.mkdir(root / child)
        self.mkdir(self.data_root / "Config" / "Requests")

    def check_dependencies(self) -> None:
        for name, command in DEPENDENCY_CHECKS.items():
            result = self.run_command(command, check=False, capture=True)
            if result == 0:
                logging.info("Dependency check passed: %s", name)
            elif name.endswith("optional") or name.endswith("hint"):
                logging.warning("Dependency check did not find %s; installer may stage or document it", name)
            else:
                raise InstallerError(f"Required dependency check failed: {name}")

    def copy_payload(self) -> None:
        if not self.manifest.files:
            self.write_placeholder_payload()
            return

        for item in self.manifest.files:
            source = (self.source_root / item.source).resolve()
            destination = self.install_root / item.destination
            if not source.exists():
                message = f"Payload missing: {source}"
                if item.required:
                    raise InstallerError(message)
                logging.warning(message)
                continue
            if item.sha256:
                validate_sha256(source, item.sha256)
            self.copy_file(source, destination)

    def write_placeholder_payload(self) -> None:
        """Create transparent placeholder launchers when no signed payload manifest exists."""
        placeholders = {
            "Agent/sentinel_agent.py": "print('Sentinel Net agent placeholder - replace with signed build')\n",
            "Tray/sentinel_tray.py": "print('Sentinel Net tray placeholder - replace with signed build')\n",
            "Watchdog/sentinel_watchdog.py": "print('Sentinel Net watchdog placeholder - replace with signed build')\n",
            "Services/sentinel_sync.py": "print('Sentinel Net sync placeholder - replace with signed build')\n",
            "Services/sentinel_command_queue.py": "print('Sentinel Net command queue placeholder - replace with signed build')\n",
            "Config/install_profile.json": json.dumps({"created_by": "sentinel_net_installer", "version": self.manifest.version}, indent=2),
        }
        for relative, content in placeholders.items():
            self.write_text(self.install_root / relative, content)

    def write_configuration(self) -> None:
        device = self.get_or_create_device_id()
        config = {
            "product": PRODUCT_NAME,
            "version": self.manifest.version,
            "install_root": str(self.install_root),
            "data_root": str(self.data_root),
            "mode": self.mode,
            "package_type": self.package_type,
            "device": device,
            "organization_id": self.manifest.organization_id,
            "security": {
                "transparent_startup": True,
                "admin_approved_cleanup": True,
                "defender_exclusions": "not configured by installer; manage centrally by policy if required",
                "token_storage": "store only encrypted application tokens in production payloads",
            },
            "components": list(SERVICE_DEFINITIONS.keys()),
        }
        self.write_json(self.data_root / "Config" / "install_state.json", config)

    def register_services(self, repair: bool = False) -> None:
        for service, definition in SERVICE_DEFINITIONS.items():
            binary = self.install_root / definition["binary"]
            if not binary.exists():
                logging.warning("Service binary missing for %s: %s", service, binary)
                continue
            if repair:
                self.run_command(["sc.exe", "delete", service], check=False)
                time.sleep(0.5)
            self.run_command(
                [
                    "sc.exe",
                    "create",
                    service,
                    f"binPath=\"{binary}\"",
                    f"DisplayName={definition['display']}",
                    "start=auto" if definition["start"] in {"auto", "delayed-auto"} else "start=demand",
                ],
                check=False,
            )
            self.run_command(["sc.exe", "description", service, definition["description"]], check=False)
            if definition["start"] == "delayed-auto":
                self.run_command(["sc.exe", "config", service, "start=delayed-auto"], check=False)

    def configure_service_recovery(self) -> None:
        for service in SERVICE_DEFINITIONS:
            self.run_command(
                ["sc.exe", "failure", service, "reset=86400", "actions=restart/60000/restart/120000/none/0"],
                check=False,
            )

    def create_shortcuts(self) -> None:
        tray = self.install_root / "Tray" / "sentinel_tray.exe"
        if not tray.exists():
            tray = self.install_root / "Tray" / "sentinel_tray.py"
        shortcut_targets = [
            Path(os.environ.get("PUBLIC", r"C:\Users\Public")) / "Desktop" / "Sentinel Net.lnk",
            Path(os.environ.get("ProgramData", r"C:\ProgramData")) / r"Microsoft\Windows\Start Menu\Programs" / "Sentinel Net.lnk",
        ]
        for shortcut in shortcut_targets:
            self.create_shortcut(shortcut, tray)

    def create_startup_entry(self) -> None:
        tray = self.install_root / "Tray" / "sentinel_tray.exe"
        if not tray.exists():
            tray = self.install_root / "Tray" / "sentinel_tray.py"
        self.run_command(
            [
                "reg.exe",
                "add",
                r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
                "/v",
                "SentinelNetTray",
                "/t",
                "REG_SZ",
                "/d",
                str(tray),
                "/f",
            ],
            check=False,
        )

    def add_firewall_rules(self) -> None:
        binaries = [self.install_root / definition["binary"] for definition in SERVICE_DEFINITIONS.values()]
        for binary in binaries:
            if binary.exists():
                self.run_command(
                    [
                        "netsh",
                        "advfirewall",
                        "firewall",
                        "add",
                        "rule",
                        f"name=Sentinel Net {binary.stem}",
                        "dir=out",
                        "action=allow",
                        f"program={binary}",
                        "enable=yes",
                    ],
                    check=False,
                )
        for port in self.manifest.firewall_ports:
            self.run_command(
                [
                    "netsh",
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    f"name=Sentinel Net TLS {port}",
                    "dir=out",
                    "action=allow",
                    "protocol=TCP",
                    f"remoteport={port}",
                    "enable=yes",
                ],
                check=False,
            )

    def validate_services(self) -> None:
        for service in SERVICE_DEFINITIONS:
            self.run_command(["sc.exe", "query", service], check=False)

    def register_device(self, reconnect: bool = False) -> None:
        device = self.get_or_create_device_id()
        payload = {
            "event": "reconnect" if reconnect else "register",
            "device": device,
            "hostname": socket.gethostname(),
            "os": platform.platform(),
            "ip": best_effort_ip(),
            "version": self.manifest.version,
            "organization_id": self.manifest.organization_id,
            "pairing_code": self.manifest.pairing_code,
            "timestamp": utc_now(),
        }
        self.write_json(self.data_root / "Config" / "last_registration_payload.json", payload)
        self.post_registration_payload("register", payload, allow_offline=True)

    def post_registration_payload(self, event: str, payload: dict[str, object], allow_offline: bool) -> None:
        if not self.manifest.registration_url:
            logging.info("No registration_url configured; %s payload saved locally", event)
            return
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self.manifest.registration_url,
            data=data,
            headers={"Content-Type": "application/json", "User-Agent": "SentinelNetInstaller/1.0"},
            method="POST",
        )
        try:
            context = ssl.create_default_context()
            with urllib.request.urlopen(request, timeout=20, context=context) as response:
                logging.info("Cloud %s sync returned HTTP %s", event, response.status)
        except (urllib.error.URLError, TimeoutError) as exc:
            if allow_offline:
                logging.warning("Cloud %s sync deferred: %s", event, exc)
            else:
                raise InstallerError(f"Cloud {event} sync failed: {exc}") from exc

    def snapshot_current_install(self) -> None:
        if not self.install_root.exists():
            return
        snapshot = self.data_root / "Updates" / f"rollback-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        logging.info("Creating rollback snapshot at %s", snapshot)
        if self.apply:
            if snapshot.exists():
                shutil.rmtree(snapshot)
            shutil.copytree(self.install_root, snapshot)
        self.rollback_actions.append(("restore_tree", snapshot))

    def rollback(self) -> None:
        for action, path in reversed(self.rollback_actions):
            if action == "restore_tree" and path.exists():
                logging.info("Restoring rollback snapshot %s", path)
                if self.apply:
                    if self.install_root.exists():
                        shutil.rmtree(self.install_root)
                    shutil.copytree(path, self.install_root)

    def get_or_create_device_id(self) -> dict[str, str]:
        if self.device_id_path.exists():
            return json.loads(self.device_id_path.read_text(encoding="utf-8"))
        seed = f"{socket.gethostname()}:{uuid.uuid4()}:{time.time_ns()}".encode("utf-8")
        device = {
            "device_id": hashlib.sha256(seed).hexdigest(),
            "created_at": utc_now(),
        }
        self.write_json(self.device_id_path, device)
        return device

    def create_shortcut(self, shortcut: Path, target: Path) -> None:
        powershell = (
            "$s=(New-Object -COM WScript.Shell).CreateShortcut('%s');"
            "$s.TargetPath='%s';$s.WorkingDirectory='%s';$s.Save()"
        ) % (str(shortcut), str(target), str(target.parent))
        self.run_command(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", powershell], check=False)

    def mkdir(self, path: Path) -> None:
        logging.info("mkdir %s", path)
        if self.apply:
            path.mkdir(parents=True, exist_ok=True)

    def copy_file(self, source: Path, destination: Path) -> None:
        logging.info("copy %s -> %s", source, destination)
        if self.apply:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)

    def write_text(self, path: Path, content: str) -> None:
        logging.info("write %s", path)
        if self.apply:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")

    def write_json(self, path: Path, payload: dict[str, object]) -> None:
        self.write_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")

    def run_command(self, command: Iterable[str], *, check: bool = True, capture: bool = False) -> int:
        command_list = [str(part) for part in command]
        logging.info("run %s", subprocess.list2cmdline(command_list))
        if not self.apply or not is_windows():
            return 0
        completed = subprocess.run(
            command_list,
            check=False,
            text=True,
            capture_output=capture,
        )
        if capture and completed.stdout:
            logging.info(completed.stdout.strip())
        if capture and completed.stderr:
            logging.warning(completed.stderr.strip())
        if check and completed.returncode != 0:
            raise InstallerError(f"Command failed ({completed.returncode}): {subprocess.list2cmdline(command_list)}")
        return completed.returncode

    @staticmethod
    def load_manifest(path: Path) -> InstallerManifest:
        if not path.exists():
            return InstallerManifest()
        raw = json.loads(path.read_text(encoding="utf-8"))
        files = [PayloadItem(**item) for item in raw.get("files", [])]
        return InstallerManifest(
            version=raw.get("version", DEFAULT_VERSION),
            files=files,
            configs=raw.get("configs", {}),
            firewall_ports=raw.get("firewall_ports", [443]),
            registration_url=raw.get("registration_url"),
            organization_id=raw.get("organization_id"),
            pairing_code=raw.get("pairing_code"),
        )


def is_windows() -> bool:
    return os.name == "nt"


def is_admin() -> bool:
    if not is_windows():
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def validate_sha256(path: Path, expected: str) -> None:
    digest = hashlib.sha256(path.read_bytes()).hexdigest().lower()
    if digest != expected.lower():
        raise InstallerError(f"SHA-256 mismatch for {path}: expected {expected}, got {digest}")


def best_effort_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Sentinel Net enterprise Windows installer")
    parser.add_argument("--mode", choices=["fresh", "repair", "upgrade", "uninstall-request"], default="fresh")
    parser.add_argument("--package-type", choices=["online", "offline", "bulk"], default="online")
    parser.add_argument("--source-root", type=Path, default=Path.cwd(), help="Folder containing signed payload files")
    parser.add_argument("--install-root", type=Path, default=DEFAULT_INSTALL_ROOT)
    parser.add_argument("--data-root", type=Path, default=DEFAULT_DATA_ROOT)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--apply", action="store_true", help="Perform changes. Without this flag the installer is a dry run.")
    parser.add_argument("--silent", action="store_true", help="Suppress interactive prompts for deployment tooling")
    parser.add_argument("--quick", action="store_true", help="Use defaults for one-click quick install planning/deployment")
    parser.add_argument("--accept-license", action="store_true", help="Record license acceptance for silent or bulk deployment")
    parser.add_argument("--keep-logs-on-uninstall", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    installer = SentinelNetInstaller(
        mode=args.mode,
        package_type=args.package_type,
        source_root=args.source_root,
        install_root=args.install_root,
        data_root=args.data_root,
        manifest_path=args.manifest,
        apply=args.apply,
        silent=args.silent,
        quick=args.quick,
        accept_license=args.accept_license,
        keep_logs_on_uninstall=args.keep_logs_on_uninstall,
    )
    try:
        installer.run()
        return 0
    except InstallerError as exc:
        logging.error("Installer failed: %s", exc)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
