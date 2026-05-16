from __future__ import annotations

import datetime as dt
import os
import platform
import socket
import subprocess
from typing import Any

import psutil

try:
    import wmi  # type: ignore
except Exception:  # pragma: no cover - optional on non-Windows test hosts
    wmi = None


def _safe(callable_obj, default=None):
    try:
        return callable_obj()
    except Exception:
        return default


def device_info(device_id: str) -> dict[str, Any]:
    return {
        "device_id": device_id,
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "os": platform.platform(),
        "os_release": platform.release(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "python": platform.python_version(),
        "boot_time": dt.datetime.fromtimestamp(psutil.boot_time(), tz=dt.timezone.utc).isoformat(),
    }


def telemetry_snapshot(process_limit: int = 300) -> dict[str, Any]:
    net = psutil.net_io_counters()
    disks = []
    for part in psutil.disk_partitions(all=False):
        usage = _safe(lambda p=part: psutil.disk_usage(p.mountpoint))
        if usage:
            disks.append({"device": part.device, "mountpoint": part.mountpoint, "fstype": part.fstype, "percent": usage.percent, "total": usage.total, "free": usage.free})
    battery = psutil.sensors_battery()
    users = [{"name": u.name, "terminal": u.terminal, "host": u.host, "started": u.started} for u in psutil.users()]
    processes = []
    for proc in psutil.process_iter(["pid", "name", "username", "status", "cpu_percent", "memory_percent", "create_time"]):
        if len(processes) >= process_limit:
            break
        processes.append(proc.info)
    return {
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
        "cpu_percent": psutil.cpu_percent(interval=None),
        "ram": dict(psutil.virtual_memory()._asdict()),
        "swap": dict(psutil.swap_memory()._asdict()),
        "disks": disks,
        "network": {"bytes_sent": net.bytes_sent, "bytes_recv": net.bytes_recv, "packets_sent": net.packets_sent, "packets_recv": net.packets_recv},
        "battery": None if battery is None else dict(battery._asdict()),
        "users": users,
        "uptime_seconds": int(dt.datetime.now().timestamp() - psutil.boot_time()),
        "processes": processes,
    }


def installed_applications() -> list[dict[str, Any]]:
    if os.name != "nt":
        return []
    import winreg  # type: ignore
    roots = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    apps: list[dict[str, Any]] = []
    for hive, path in roots:
        try:
            with winreg.OpenKey(hive, path) as key:
                for i in range(winreg.QueryInfoKey(key)[0]):
                    try:
                        sub = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, sub) as sk:
                            name = winreg.QueryValueEx(sk, "DisplayName")[0]
                            version = _safe(lambda: winreg.QueryValueEx(sk, "DisplayVersion")[0], "")
                            publisher = _safe(lambda: winreg.QueryValueEx(sk, "Publisher")[0], "")
                            apps.append({"name": name, "version": version, "publisher": publisher})
                    except Exception:
                        continue
        except Exception:
            continue
    return apps


def startup_applications() -> list[dict[str, str]]:
    if os.name != "nt":
        return []
    import winreg  # type: ignore
    entries: list[dict[str, str]] = []
    for hive, path in [(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"), (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run")]:
        try:
            with winreg.OpenKey(hive, path) as key:
                for i in range(winreg.QueryInfoKey(key)[1]):
                    name, value, _ = winreg.EnumValue(key, i)
                    entries.append({"name": name, "command": str(value)})
        except Exception:
            continue
    return entries


def security_status() -> dict[str, Any]:
    status: dict[str, Any] = {"firewall": "unknown", "antivirus": [], "critical_services": {}}
    if os.name == "nt":
        fw = _safe(lambda: subprocess.check_output(["netsh", "advfirewall", "show", "allprofiles", "state"], text=True, timeout=10), "")
        status["firewall"] = fw.strip()[-2000:]
        if wmi:
            av_items = _safe(lambda: wmi.WMI(namespace="SecurityCenter2").AntiVirusProduct(), [])
            status["antivirus"] = [{"name": item.displayName, "state": getattr(item, "productState", None)} for item in av_items]
        for service in ("WinDefend", "MpsSvc", "EventLog"):
            svc = _safe(lambda s=service: psutil.win_service_get(s).as_dict())
            status["critical_services"][service] = svc
    return status
