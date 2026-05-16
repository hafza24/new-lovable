#!/usr/bin/env python3
"""
Sentinel Net system tray application.

The tray provides a visible, user-facing control surface for managed endpoints:
status, active protections, admin messages, diagnostics, and consent-aware
support actions.  PySide6 is used when available; otherwise the module falls
back to a small terminal status viewer for service builds and CI.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

APP_NAME = "Sentinel Net"
DEFAULT_DATA_DIR = Path(os.getenv("PROGRAMDATA", str(Path.home()))) / "SentinelNet"
STATUS_COLORS = {
    "running": "#22c55e",
    "starting": "#38bdf8",
    "degraded": "#f59e0b",
    "stopped": "#ef4444",
    "unknown": "#64748b",
}


@dataclass(slots=True)
class TrayState:
    state: str = "unknown"
    device_id: str = "unregistered"
    organization_id: str = "unpaired"
    version: str = "unknown"
    firewall_status: str = "managed"
    wifi_status: str = "unknown"
    internet_status: str = "unknown"
    sync_status: str = "waiting"
    current_policy: str = "default"
    blocked_websites: int = 0
    blocked_files: int = 0
    pending_uploads: int = 0
    active_protections: list[str] = field(default_factory=lambda: [
        "Network filtering",
        "USB audit",
        "File activity audit",
        "Camera and microphone audit",
    ])
    admin_messages: list[dict[str, Any]] = field(default_factory=list)
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class StateRepository:
    """Reads the files written by Agent.py without requiring elevated IPC."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.status_path = data_dir / "status.json"
        self.messages_path = data_dir / "admin-messages.jsonl"
        self.policy_path = data_dir / "policy.json"
        self.diagnostics_path = data_dir / "diagnostics-requested.flag"
        self.restart_path = data_dir / "restart-requested.flag"
        self.uninstall_request_path = data_dir / "uninstall-request.json"

    def load(self) -> TrayState:
        state = TrayState()
        if self.status_path.exists():
            status = json.loads(self.status_path.read_text(encoding="utf-8"))
            state.state = status.get("state", state.state)
            state.device_id = status.get("device_id", state.device_id)
            state.organization_id = status.get("organization_id", state.organization_id)
            state.version = status.get("version", state.version)
            state.pending_uploads = int(status.get("queue_depth", 0))
            state.sync_status = "online" if state.state == "running" else state.state
            state.updated_at = status.get("updated_at", state.updated_at)
        if self.policy_path.exists():
            policy = json.loads(self.policy_path.read_text(encoding="utf-8"))
            state.current_policy = f"v{policy.get('version', 'unknown')}"
            network = policy.get("network", {})
            files = policy.get("files", {})
            state.blocked_websites = len(network.get("blocked_domains", []))
            state.blocked_files = len(files.get("sensitive_paths", []))
        state.admin_messages = self._load_messages(limit=5)
        return state

    def _load_messages(self, limit: int) -> list[dict[str, Any]]:
        if not self.messages_path.exists():
            return []
        lines = self.messages_path.read_text(encoding="utf-8").splitlines()[-limit:]
        return [json.loads(line) for line in lines if line.strip()]

    def request_diagnostics(self) -> None:
        self.diagnostics_path.write_text(datetime.now(timezone.utc).isoformat(), encoding="utf-8")

    def request_restart(self) -> None:
        self.restart_path.write_text(datetime.now(timezone.utc).isoformat(), encoding="utf-8")

    def request_uninstall(self, reason: str) -> None:
        payload = {
            "requested_at": datetime.now(timezone.utc).isoformat(),
            "reason": reason,
            "status": "pending_admin_approval",
        }
        self.uninstall_request_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


class TerminalTray:
    """Non-GUI fallback for CI and server-core Windows images."""

    def __init__(self, repo: StateRepository):
        self.repo = repo

    def run(self) -> int:
        state = self.repo.load()
        print(f"{APP_NAME} tray fallback")
        print(f"Status       : {state.state}")
        print(f"Device       : {state.device_id}")
        print(f"Organization : {state.organization_id}")
        print(f"Policy       : {state.current_policy}")
        print(f"Sync         : {state.sync_status} ({state.pending_uploads} queued)")
        print(f"Protections  : {', '.join(state.active_protections)}")
        if state.admin_messages:
            print("Admin messages:")
            for message in state.admin_messages:
                print(f"- {message.get('title', APP_NAME)}: {message.get('body', '')}")
        return 0


def run_gui(repo: StateRepository) -> int:
    from PySide6.QtCore import QTimer, Qt
    from PySide6.QtGui import QAction, QIcon, QPainter, QPixmap
    from PySide6.QtWidgets import (
        QApplication,
        QFrame,
        QGridLayout,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QMainWindow,
        QMenu,
        QMessageBox,
        QPushButton,
        QSystemTrayIcon,
        QVBoxLayout,
        QWidget,
    )

    class StatusDot(QLabel):
        def set_status(self, status: str) -> None:
            color = STATUS_COLORS.get(status, STATUS_COLORS["unknown"])
            self.setStyleSheet(
                f"border-radius: 7px; min-width: 14px; max-width: 14px; min-height: 14px; "
                f"max-height: 14px; background: {color};"
            )

    class TrayWindow(QMainWindow):
        def __init__(self) -> None:
            super().__init__()
            self.setWindowTitle(f"{APP_NAME} Endpoint")
            self.setMinimumSize(760, 560)
            self.setStyleSheet(STYLESHEET)
            self.status_dot = StatusDot()
            self.status_label = QLabel("Loading")
            self.device_label = QLabel("—")
            self.org_label = QLabel("—")
            self.policy_label = QLabel("—")
            self.sync_label = QLabel("—")
            self.protection_box = QVBoxLayout()
            self.message_box = QVBoxLayout()
            self.reason_input = QLineEdit()
            self.reason_input.setPlaceholderText("Optional reason for administrator")
            self._build()
            self.refresh()

        def _build(self) -> None:
            root = QWidget()
            outer = QVBoxLayout(root)
            outer.setContentsMargins(24, 24, 24, 24)
            outer.setSpacing(18)

            hero = QFrame()
            hero.setObjectName("hero")
            hero_layout = QHBoxLayout(hero)
            title_stack = QVBoxLayout()
            title = QLabel("Sentinel Net")
            title.setObjectName("title")
            subtitle = QLabel("Managed endpoint protection, filtering, and device health")
            subtitle.setObjectName("subtitle")
            title_stack.addWidget(title)
            title_stack.addWidget(subtitle)
            hero_layout.addLayout(title_stack)
            hero_layout.addStretch()
            hero_layout.addWidget(self.status_dot)
            hero_layout.addWidget(self.status_label)
            outer.addWidget(hero)

            cards = QGridLayout()
            cards.addWidget(self._metric_card("Device", self.device_label), 0, 0)
            cards.addWidget(self._metric_card("Organization", self.org_label), 0, 1)
            cards.addWidget(self._metric_card("Policy", self.policy_label), 1, 0)
            cards.addWidget(self._metric_card("Sync", self.sync_label), 1, 1)
            outer.addLayout(cards)

            protection_card = self._panel("Active protections")
            protection_card.layout().addLayout(self.protection_box)
            outer.addWidget(protection_card)

            messages = self._panel("Admin messages")
            messages.layout().addLayout(self.message_box)
            outer.addWidget(messages)

            actions = QHBoxLayout()
            diagnostics = QPushButton("Request diagnostics")
            diagnostics.clicked.connect(self._diagnostics)
            restart = QPushButton("Restart agent")
            restart.clicked.connect(self._restart)
            uninstall = QPushButton("Request uninstall")
            uninstall.clicked.connect(self._uninstall)
            actions.addWidget(diagnostics)
            actions.addWidget(restart)
            actions.addWidget(uninstall)
            outer.addWidget(self.reason_input)
            outer.addLayout(actions)
            self.setCentralWidget(root)

        def _metric_card(self, title: str, value: QLabel) -> QFrame:
            card = QFrame()
            card.setObjectName("card")
            layout = QVBoxLayout(card)
            label = QLabel(title.upper())
            label.setObjectName("eyebrow")
            value.setObjectName("metric")
            value.setTextInteractionFlags(Qt.TextSelectableByMouse)
            layout.addWidget(label)
            layout.addWidget(value)
            return card

        def _panel(self, title: str) -> QFrame:
            panel = QFrame()
            panel.setObjectName("card")
            layout = QVBoxLayout(panel)
            label = QLabel(title)
            label.setObjectName("section")
            layout.addWidget(label)
            return panel

        def refresh(self) -> None:
            state = repo.load()
            self.status_dot.set_status(state.state)
            self.status_label.setText(state.state.upper())
            self.device_label.setText(state.device_id)
            self.org_label.setText(state.organization_id)
            self.policy_label.setText(state.current_policy)
            self.sync_label.setText(f"{state.sync_status} · {state.pending_uploads} queued")
            self._replace_list(
                self.protection_box,
                [
                    *state.active_protections,
                    f"Blocked websites: {state.blocked_websites}",
                    f"Sensitive paths: {state.blocked_files}",
                    f"Internet: {state.internet_status}",
                    f"Firewall: {state.firewall_status}",
                ],
            )
            message_lines = [f"{m.get('title', APP_NAME)} — {m.get('body', '')}" for m in state.admin_messages]
            self._replace_list(self.message_box, message_lines or ["No recent administrator messages."])

        def _replace_list(self, layout: QVBoxLayout, lines: list[str]) -> None:
            while layout.count():
                item = layout.takeAt(0)
                widget = item.widget()
                if widget is not None:
                    widget.deleteLater()
            for line in lines:
                label = QLabel(f"• {line}")
                label.setObjectName("listItem")
                label.setWordWrap(True)
                layout.addWidget(label)

        def _diagnostics(self) -> None:
            repo.request_diagnostics()
            QMessageBox.information(self, APP_NAME, "Diagnostics request queued for the local agent.")

        def _restart(self) -> None:
            repo.request_restart()
            QMessageBox.information(self, APP_NAME, "Agent restart request queued.")

        def _uninstall(self) -> None:
            repo.request_uninstall(self.reason_input.text())
            QMessageBox.information(
                self,
                APP_NAME,
                "Uninstall request submitted for administrator approval.",
            )

    def icon() -> QIcon:
        pixmap = QPixmap(64, 64)
        pixmap.fill(Qt.transparent)
        painter = QPainter(pixmap)
        painter.setBrush(Qt.cyan)
        painter.setPen(Qt.NoPen)
        painter.drawRoundedRect(8, 8, 48, 48, 14, 14)
        painter.end()
        return QIcon(pixmap)

    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    window = TrayWindow()
    tray = QSystemTrayIcon(icon(), app)
    tray.setToolTip(APP_NAME)
    menu = QMenu()
    show_action = QAction("Open Sentinel Net")
    show_action.triggered.connect(window.show)
    diagnostics_action = QAction("Request diagnostics")
    diagnostics_action.triggered.connect(repo.request_diagnostics)
    quit_action = QAction("Quit tray")
    quit_action.triggered.connect(app.quit)
    menu.addAction(show_action)
    menu.addAction(diagnostics_action)
    menu.addSeparator()
    menu.addAction(quit_action)
    tray.setContextMenu(menu)
    tray.activated.connect(lambda reason: window.show() if reason == QSystemTrayIcon.ActivationReason.Trigger else None)
    tray.show()
    window.show()
    timer = QTimer()
    timer.timeout.connect(window.refresh)
    timer.start(5000)
    return app.exec()


STYLESHEET = """
QMainWindow, QWidget { background: #050816; color: #e5eefb; font-family: 'Segoe UI', Arial; }
#hero { border: 1px solid rgba(56, 189, 248, 0.28); border-radius: 22px; padding: 18px;
        background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 rgba(14, 165, 233, 0.28), stop:1 rgba(79, 70, 229, 0.18)); }
#title { font-size: 30px; font-weight: 800; letter-spacing: 1px; }
#subtitle { color: #93a4bb; font-size: 13px; }
#card, QFrame#card { border: 1px solid rgba(148, 163, 184, 0.18); border-radius: 18px; padding: 14px;
                     background: rgba(15, 23, 42, 0.78); }
#eyebrow { color: #38bdf8; font-size: 10px; letter-spacing: 2px; font-weight: 700; }
#metric { font-size: 16px; font-weight: 650; color: #f8fafc; }
#section { font-size: 15px; font-weight: 750; color: #f8fafc; }
#listItem { color: #cbd5e1; line-height: 1.35; }
QPushButton { border: 1px solid rgba(56, 189, 248, 0.35); border-radius: 12px; padding: 10px 14px;
              background: rgba(14, 165, 233, 0.16); color: #e0f2fe; font-weight: 650; }
QPushButton:hover { background: rgba(14, 165, 233, 0.28); }
QLineEdit { border: 1px solid rgba(148, 163, 184, 0.22); border-radius: 12px; padding: 10px;
            background: rgba(15, 23, 42, 0.7); color: #e5eefb; }
"""


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Sentinel Net tray application")
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument("--terminal", action="store_true", help="Use terminal status view even when PySide6 exists")
    parser.add_argument("--open-data-dir", action="store_true", help="Open local Sentinel Net data directory")
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()
    args.data_dir.mkdir(parents=True, exist_ok=True)
    if args.open_data_dir:
        if sys.platform.startswith("win"):
            subprocess.Popen(["explorer", str(args.data_dir)])
        else:
            print(args.data_dir)
        return 0
    repo = StateRepository(args.data_dir)
    if args.terminal or importlib.util.find_spec("PySide6") is None:
        return TerminalTray(repo).run()
    return run_gui(repo)


if __name__ == "__main__":
    raise SystemExit(main())
