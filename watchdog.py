from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from pathlib import Path

import psutil

from sentinel_net.config import ConfigManager
from sentinel_net.database.store import EndpointStore
from sentinel_net.logging_utils import configure_logging
from sentinel_net.security.integrity import validate_manifest

try:
    import servicemanager  # type: ignore
    import win32event  # type: ignore
    import win32service  # type: ignore
    import win32serviceutil  # type: ignore
except Exception:  # pragma: no cover
    servicemanager = win32event = win32service = win32serviceutil = None

MODULES = {"agent": "SentinelAgent.exe", "tray": "SentinelTray.exe"}

class SentinelWatchdog:
    def __init__(self) -> None:
        self.cm = ConfigManager()
        self.config = self.cm.config
        self.logger = configure_logging("watchdog", self.config["paths"]["logs"], self.config["agent"].get("log_level", "INFO"))
        self.store = EndpointStore(self.config["paths"]["database"])
        self.base_dir = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent
        self.stop_event = threading.Event()

    def find_process(self, exe_name: str) -> psutil.Process | None:
        for proc in psutil.process_iter(["pid", "name", "exe", "status", "cpu_percent", "memory_info"]):
            try:
                if (proc.info.get("name") or "").lower() == exe_name.lower():
                    return proc
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return None

    def start_module(self, exe_name: str, script_name: str) -> None:
        exe = self.base_dir / exe_name
        if exe.exists():
            subprocess.Popen([str(exe)], creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        else:
            subprocess.Popen([sys.executable, str(self.base_dir / script_name)], creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        self.store.audit("WARNING", "module_restarted", {"module": exe_name})
        self.logger.warning("restarted missing module %s", exe_name)

    def rebuild_missing_configs(self) -> None:
        for key in ("local_config",):
            path = Path(self.config["paths"][key])
            if not path.exists():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps({}, indent=2), encoding="utf-8")
                self.store.audit("WARNING", "config_rebuilt", {"path": str(path)})

    def check(self) -> None:
        self.rebuild_missing_configs()
        integrity = validate_manifest(self.config["paths"]["integrity_manifest"])
        if integrity["missing"] or integrity["changed"]:
            self.store.audit("ERROR", "integrity_failure", integrity)
            self.logger.error("integrity failure: %s", integrity)
        for module, exe in MODULES.items():
            script = f"{module}.py"
            if not self.find_process(exe) and not self.find_process(script):
                self.start_module(exe, script)

    def run(self) -> None:
        self.logger.info("Sentinel Watchdog starting")
        while not self.stop_event.is_set():
            try:
                self.check()
            except Exception as exc:
                self.logger.exception("watchdog check failed: %s", exc)
            self.stop_event.wait(30)
        self.logger.info("Sentinel Watchdog stopped")

    def stop(self) -> None:
        self.stop_event.set()

if win32serviceutil:
    class SentinelWatchdogService(win32serviceutil.ServiceFramework):  # type: ignore[misc]
        _svc_name_ = "SentinelNetWatchdog"
        _svc_display_name_ = "Sentinel Net Watchdog"
        _svc_description_ = "Sentinel Net endpoint health, integrity, and recovery watchdog."

        def __init__(self, args: list[str]) -> None:
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.stop_handle = win32event.CreateEvent(None, 0, 0, None)
            self.watchdog = SentinelWatchdog()

        def SvcStop(self) -> None:
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self.watchdog.stop()
            win32event.SetEvent(self.stop_handle)

        def SvcDoRun(self) -> None:
            servicemanager.LogInfoMsg("SentinelNetWatchdog starting")
            self.watchdog.run()

if __name__ == "__main__":
    if win32serviceutil:
        win32serviceutil.HandleCommandLine(SentinelWatchdogService)
    else:
        SentinelWatchdog().run()
