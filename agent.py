from __future__ import annotations

import asyncio
import signal
import time
from pathlib import Path
from typing import Any

from sentinel_net.config import ConfigManager
from sentinel_net.database.store import EndpointStore
from sentinel_net.identity import get_device_id
from sentinel_net.logging_utils import configure_logging
from sentinel_net.monitoring.system import device_info, installed_applications, security_status, startup_applications, telemetry_snapshot
from sentinel_net.network import SecureChannel
from sentinel_net.security.integrity import validate_manifest
from sentinel_net.websocket_handlers.commands import RemoteCommandRouter

try:
    import servicemanager  # type: ignore
    import win32event  # type: ignore
    import win32service  # type: ignore
    import win32serviceutil  # type: ignore
except Exception:  # pragma: no cover
    servicemanager = win32event = win32service = win32serviceutil = None

class SentinelAgent:
    def __init__(self) -> None:
        self.cm = ConfigManager()
        self.config = self.cm.config
        self.logger = configure_logging("agent", self.config["paths"]["logs"], self.config["agent"].get("log_level", "INFO"))
        self.device_id = get_device_id(self.config["paths"]["device_id"])
        self.store = EndpointStore(self.config["paths"]["database"])
        self.router = RemoteCommandRouter(self.config, self.store, self.logger)
        self.stop_event = asyncio.Event()
        self.channel: SecureChannel | None = None

    async def register(self) -> None:
        payload = {"device": device_info(self.device_id), "security": security_status(), "startup": startup_applications()}
        self.store.enqueue("device.register", payload)
        if self.channel:
            await self.channel.post("/api/endpoint/register", payload)

    async def sync_loop(self) -> None:
        inventory_due = 0.0
        integrity_due = 0.0
        while not self.stop_event.is_set():
            try:
                now = time.time()
                payload: dict[str, Any] = {"device_id": self.device_id, "telemetry": telemetry_snapshot(self.config["agent"].get("process_sample_limit", 300)), "security": security_status()}
                if now >= inventory_due:
                    payload["installed_applications"] = installed_applications()
                    payload["startup_applications"] = startup_applications()
                    inventory_due = now + self.config["agent"].get("app_inventory_interval_minutes", 360) * 60
                if now >= integrity_due:
                    payload["integrity"] = validate_manifest(self.config["paths"]["integrity_manifest"])
                    integrity_due = now + self.config["agent"].get("integrity_interval_minutes", 15) * 60
                self.store.enqueue("telemetry", payload)
                await self.flush_queue()
            except Exception as exc:
                self.logger.exception("sync loop failed: %s", exc)
            await asyncio.sleep(self.config["server"].get("sync_seconds", 60))

    async def flush_queue(self) -> None:
        if not self.channel:
            return
        sent: list[int] = []
        for row in self.store.fetch_queue(limit=100):
            payload = {"topic": row["topic"], "payload": row["payload"], "device_id": self.device_id}
            ok = await self.channel.send_ws(payload) if self.channel.connected else False
            if not ok:
                ok = await self.channel.post("/api/endpoint/sync", payload)
            if ok:
                sent.append(row["id"])
            else:
                self.store.mark_attempt(row["id"])
                break
        self.store.delete_queue(sent)

    async def ws_loop(self) -> None:
        retry = self.config["server"].get("retry_initial_seconds", 2)
        async with SecureChannel(self.config["server"], self.device_id, self.logger) as channel:
            self.channel = channel
            await self.register()
            while not self.stop_event.is_set():
                try:
                    await channel.connect_ws(self.handle_message)
                    retry = self.config["server"].get("retry_initial_seconds", 2)
                except Exception as exc:
                    self.logger.warning("websocket disconnected: %s", exc)
                    await asyncio.sleep(retry)
                    retry = min(retry * 2, self.config["server"].get("retry_max_seconds", 120))

    async def handle_message(self, message: dict[str, Any]) -> None:
        response = await self.router.handle(message)
        response["device_id"] = self.device_id
        if self.channel:
            await self.channel.send_ws(response)

    async def run(self) -> None:
        self.logger.info("Sentinel Agent starting device_id=%s", self.device_id)
        tasks = [asyncio.create_task(self.ws_loop()), asyncio.create_task(self.sync_loop())]
        try:
            await self.stop_event.wait()
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            self.logger.info("Sentinel Agent stopped")

    def stop(self) -> None:
        self.stop_event.set()


def main() -> None:
    agent = SentinelAgent()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, agent.stop)
        except NotImplementedError:
            pass
    loop.run_until_complete(agent.run())

if win32serviceutil:
    class SentinelAgentService(win32serviceutil.ServiceFramework):  # type: ignore[misc]
        _svc_name_ = "SentinelNetAgent"
        _svc_display_name_ = "Sentinel Net Agent"
        _svc_description_ = "Transparent Sentinel Net endpoint telemetry and policy sync agent."

        def __init__(self, args: list[str]) -> None:
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.stop_handle = win32event.CreateEvent(None, 0, 0, None)

        def SvcStop(self) -> None:
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self.stop_handle)

        def SvcDoRun(self) -> None:
            servicemanager.LogInfoMsg("SentinelNetAgent starting")
            main()

if __name__ == "__main__":
    if win32serviceutil:
        win32serviceutil.HandleCommandLine(SentinelAgentService)
    else:
        main()
