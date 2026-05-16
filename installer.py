from __future__ import annotations

import argparse
import ctypes
import shutil
import subprocess
import sys
from pathlib import Path

from sentinel_net.config import ConfigManager
from sentinel_net.database.store import EndpointStore
from sentinel_net.identity import get_device_id
from sentinel_net.logging_utils import configure_logging
from sentinel_net.monitoring.system import device_info, installed_applications
from sentinel_net.security.integrity import build_manifest

SERVICE_NAMES = ["SentinelNetWatchdog", "SentinelNetAgent", "SentinelNetSync"]

class Installer:
    def __init__(self) -> None:
        self.cm = ConfigManager()
        self.config = self.cm.config
        self.logger = configure_logging("installer", self.config["paths"]["logs"], self.config["agent"].get("log_level", "INFO"))
        self.store = EndpointStore(self.config["paths"]["database"])
        self.source = Path(__file__).resolve().parent
        self.install_dir = Path(self.config["paths"]["program_data"]) / "bin"

    def is_admin(self) -> bool:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    def require_admin(self) -> None:
        if sys.platform.startswith("win") and not self.is_admin():
            raise PermissionError("Administrator rights are required for service and firewall setup")

    def copy_files(self) -> None:
        self.install_dir.mkdir(parents=True, exist_ok=True)
        for name in ["agent.py", "tray.py", "watchdog.py", "installer.py", "requirements.txt"]:
            src = self.source / name
            if src.exists():
                shutil.copy2(src, self.install_dir / name)
        package_dst = self.install_dir / "sentinel_net"
        if package_dst.exists():
            shutil.rmtree(package_dst)
        shutil.copytree(self.source / "sentinel_net", package_dst)
        build_manifest([p for p in self.install_dir.rglob("*") if p.is_file()], self.config["paths"]["integrity_manifest"])

    def register_services(self) -> None:
        if not sys.platform.startswith("win"):
            self.logger.warning("service registration skipped on non-Windows host")
            return
        python = sys.executable
        subprocess.run([python, str(self.install_dir / "watchdog.py"), "install", "--startup", "auto"], check=False)
        subprocess.run([python, str(self.install_dir / "agent.py"), "install", "--startup", "auto"], check=False)
        subprocess.run([python, str(self.install_dir / "watchdog.py"), "start"], check=False)
        subprocess.run([python, str(self.install_dir / "agent.py"), "start"], check=False)

    def configure_startup(self) -> None:
        if not sys.platform.startswith("win"):
            return
        import winreg  # type: ignore
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "SentinelNetTray", 0, winreg.REG_SZ, str(self.install_dir / "SentinelTray.exe"))

    def configure_firewall(self) -> None:
        if sys.platform.startswith("win"):
            subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", "name=Sentinel Net Endpoint", "dir=out", "action=allow", "program=" + str(self.install_dir / "SentinelAgent.exe"), "enable=yes"], check=False)

    def sync_install(self) -> None:
        device_id = get_device_id(self.config["paths"]["device_id"])
        payload = {"device": device_info(device_id), "installed_applications": installed_applications()}
        self.store.enqueue("install.registration", payload)
        self.store.audit("INFO", "install_sync_queued", payload["device"])

    def install(self) -> None:
        self.require_admin()
        self.copy_files()
        self.configure_firewall()
        self.configure_startup()
        self.register_services()
        self.sync_install()
        self.logger.info("installation completed")

    def repair(self) -> None:
        self.copy_files()
        self.register_services()
        self.configure_startup()
        self.store.audit("INFO", "repair_completed", {})

    def uninstall(self, token: str | None) -> None:
        expected = self.config.get("server", "registration_token")
        if not token or token != expected:
            raise PermissionError("valid admin uninstall token required")
        if sys.platform.startswith("win"):
            for svc in SERVICE_NAMES:
                subprocess.run(["sc", "stop", svc], check=False)
                subprocess.run(["sc", "delete", svc], check=False)
        self.store.audit("WARNING", "uninstall_approved", {})
        shutil.rmtree(Path(self.config["paths"]["program_data"]), ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Sentinel Net endpoint installer")
    parser.add_argument("mode", choices=["install", "repair", "uninstall"], nargs="?", default="install")
    parser.add_argument("--token", help="admin approval token for secure uninstall")
    args = parser.parse_args()
    installer = Installer()
    getattr(installer, args.mode)(args.token) if args.mode == "uninstall" else getattr(installer, args.mode)()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
