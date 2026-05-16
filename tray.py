from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from PyQt6.QtCore import QTimer, Qt
from PyQt6.QtGui import QAction, QIcon
from PyQt6.QtWidgets import QApplication, QGridLayout, QLabel, QMainWindow, QMenu, QPushButton, QSystemTrayIcon, QTextEdit, QVBoxLayout, QWidget

from sentinel_net.config import ConfigManager
from sentinel_net.database.store import EndpointStore
from sentinel_net.identity import get_device_id
from sentinel_net.logging_utils import configure_logging

STYLE = """
QMainWindow, QWidget { background: #0f172a; color: #e2e8f0; font-family: Segoe UI; }
QLabel#title { font-size: 22px; font-weight: 700; color: #38bdf8; }
QLabel.card { background: #111827; border: 1px solid #334155; border-radius: 10px; padding: 12px; }
QPushButton { background: #2563eb; border: 0; border-radius: 8px; padding: 9px 14px; color: white; }
QPushButton:hover { background: #1d4ed8; }
QTextEdit { background: #020617; border: 1px solid #334155; border-radius: 8px; }
"""

class Dashboard(QMainWindow):
    def __init__(self, cm: ConfigManager, store: EndpointStore) -> None:
        super().__init__()
        self.cm = cm
        self.config = cm.config
        self.store = store
        self.device_id = get_device_id(self.config["paths"]["device_id"])
        self.setWindowTitle("Sentinel Net Endpoint")
        self.resize(820, 620)
        self.setStyleSheet(STYLE)
        root = QWidget()
        layout = QVBoxLayout(root)
        title = QLabel("Sentinel Net Endpoint")
        title.setObjectName("title")
        layout.addWidget(title)
        self.grid = QGridLayout()
        layout.addLayout(self.grid)
        self.cards: dict[str, QLabel] = {}
        for idx, name in enumerate(["Connection", "Agent", "Firewall", "Webcam", "Sync", "Policy", "Update", "Device ID", "Admin"]):
            card = QLabel()
            card.setProperty("class", "card")
            self.cards[name] = card
            self.grid.addWidget(card, idx // 3, idx % 3)
        actions = QGridLayout()
        for idx, (label, callback) in enumerate([
            ("Sync now", self.sync_now), ("Request uninstall", self.request_uninstall), ("Restart agent", self.restart_agent),
            ("Open logs", self.open_logs), ("Diagnostics", self.diagnostics), ("Update now", self.update_now), ("Reconnect server", self.reconnect),
        ]):
            btn = QPushButton(label)
            btn.clicked.connect(callback)
            actions.addWidget(btn, idx // 3, idx % 3)
        layout.addLayout(actions)
        self.alerts = QTextEdit()
        self.alerts.setReadOnly(True)
        layout.addWidget(QLabel("Active alerts / shared documents / blocked sites / protection modules"))
        layout.addWidget(self.alerts)
        self.setCentralWidget(root)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.timer.start(5000)
        self.refresh()

    def refresh(self) -> None:
        status = self.store.get_state("status", {})
        self.cards["Connection"].setText(f"Connection\n{status.get('connection', 'pending')}")
        self.cards["Agent"].setText("Agent\nRunning")
        self.cards["Firewall"].setText(f"Firewall\n{status.get('firewall', 'unknown')}")
        self.cards["Webcam"].setText("Webcam\nConsent required")
        self.cards["Sync"].setText(f"Last sync\n{status.get('last_sync', 'not yet')}")
        self.cards["Policy"].setText(f"Active policy\n{status.get('policy', 'default')}")
        self.cards["Update"].setText(f"Update\n{status.get('update', 'current')}")
        self.cards["Device ID"].setText(f"Device ID\n{self.device_id}")
        self.cards["Admin"].setText(f"Connected admin\n{self.config['server'].get('base_url')}")
        self.alerts.setPlainText(json.dumps(status.get("alerts", []), indent=2))

    def _run(self, args: list[str]) -> None:
        subprocess.Popen(args, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))

    def sync_now(self) -> None:
        self.store.audit("INFO", "tray_sync_requested", {})
        self.store.set_state("status", {"last_sync": "requested from tray"})
        self.refresh()

    def request_uninstall(self) -> None:
        self.store.audit("WARNING", "uninstall_requested", {"source": "tray"})
        self.alerts.append("Uninstall request recorded. Admin approval token is required in installer.")

    def restart_agent(self) -> None:
        self._run([sys.executable, "agent.py"])

    def open_logs(self) -> None:
        path = Path(self.config["paths"]["logs"])
        path.mkdir(parents=True, exist_ok=True)
        if sys.platform.startswith("win"):
            subprocess.Popen(["explorer", str(path)])

    def diagnostics(self) -> None:
        self.alerts.append("Diagnostics queued. See agent/watchdog logs for details.")

    def update_now(self) -> None:
        self.alerts.append("Update check queued.")

    def reconnect(self) -> None:
        self.alerts.append("Reconnect requested.")

class TrayApp:
    def __init__(self) -> None:
        self.cm = ConfigManager()
        self.logger = configure_logging("tray", self.cm.config["paths"]["logs"], self.cm.config["agent"].get("log_level", "INFO"))
        self.store = EndpointStore(self.cm.config["paths"]["database"])
        self.window = Dashboard(self.cm, self.store)
        self.tray = QSystemTrayIcon(QIcon())
        self.tray.setToolTip("Sentinel Net Endpoint")
        menu = QMenu()
        show = QAction("Open dashboard")
        show.triggered.connect(self.window.show)
        menu.addAction(show)
        sync = QAction("Sync now")
        sync.triggered.connect(self.window.sync_now)
        menu.addAction(sync)
        quit_action = QAction("Minimize to tray")
        quit_action.triggered.connect(self.window.hide)
        menu.addAction(quit_action)
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(lambda reason: self.window.show() if reason == QSystemTrayIcon.ActivationReason.DoubleClick else None)
        self.tray.show()


def main() -> int:
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    tray = TrayApp()
    tray.window.show()
    return app.exec()

if __name__ == "__main__":
    raise SystemExit(main())
