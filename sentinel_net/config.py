from __future__ import annotations

import json
import os
import re
from copy import deepcopy
from pathlib import Path
from typing import Any

PACKAGE_ROOT = Path(__file__).resolve().parent
DEFAULT_CONFIG_PATH = PACKAGE_ROOT / "config" / "default.json"


def _expand(value: Any) -> Any:
    if isinstance(value, str):
        def repl(match: re.Match[str]) -> str:
            name = match.group(1)
            fallback = str(Path.home() / "AppData" / "Local") if name.lower() == "programdata" else match.group(0)
            return os.environ.get(name) or os.environ.get(name.upper()) or fallback
        return os.path.expandvars(re.sub(r"%([^%]+)%", repl, value))
    if isinstance(value, dict):
        return {k: _expand(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand(v) for v in value]
    return value


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


class ConfigManager:
    """Loads a secure, layered endpoint configuration.

    Defaults ship with the executable. A machine-local JSON file in ProgramData may
    override those values and environment variables can be used by deployment tools.
    """

    ENV_MAP = {
        "SENTINEL_BASE_URL": ("server", "base_url"),
        "SENTINEL_WS_URL": ("server", "websocket_url"),
        "SENTINEL_TENANT_ID": ("server", "tenant_id"),
        "SENTINEL_REGISTRATION_TOKEN": ("server", "registration_token"),
        "SENTINEL_LOG_LEVEL": ("agent", "log_level"),
    }

    def __init__(self, local_path: str | None = None) -> None:
        with DEFAULT_CONFIG_PATH.open("r", encoding="utf-8") as fh:
            defaults = json.load(fh)
        defaults = _expand(defaults)
        configured_local_path = local_path or defaults["paths"]["local_config"]
        self.local_path = Path(configured_local_path)
        local = self._load_local()
        self.config = deep_merge(defaults, local)
        self._apply_env()
        self.ensure_directories()

    def _load_local(self) -> dict[str, Any]:
        if not self.local_path.exists():
            return {}
        with self.local_path.open("r", encoding="utf-8") as fh:
            return json.load(fh)

    def _apply_env(self) -> None:
        for env, path in self.ENV_MAP.items():
            if env in os.environ and os.environ[env]:
                node = self.config
                for key in path[:-1]:
                    node = node.setdefault(key, {})
                node[path[-1]] = os.environ[env]

    def ensure_directories(self) -> None:
        for key in ("program_data", "logs"):
            Path(self.config["paths"][key]).mkdir(parents=True, exist_ok=True)
        for key in ("database", "device_id", "local_config", "integrity_manifest", "consent_file"):
            Path(self.config["paths"][key]).parent.mkdir(parents=True, exist_ok=True)

    def save_local(self, overrides: dict[str, Any]) -> None:
        self.local_path.parent.mkdir(parents=True, exist_ok=True)
        merged = deep_merge(self._load_local(), overrides)
        with self.local_path.open("w", encoding="utf-8") as fh:
            json.dump(merged, fh, indent=2, sort_keys=True)
        self.config = deep_merge(self.config, overrides)

    def get(self, *keys: str, default: Any = None) -> Any:
        node: Any = self.config
        for key in keys:
            if not isinstance(node, dict) or key not in node:
                return default
            node = node[key]
        return node
