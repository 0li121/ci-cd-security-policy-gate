from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from policy_gate.models import PolicyConfig, SecretScanSettings, Severity


DEFAULT_CONFIG_FILENAMES = (".policy-gate.yml", ".policy-gate.yaml")


def resolve_config_path(repo_root: Path, config_path: Path | None = None) -> Path | None:
    if config_path is not None:
        return config_path
    for candidate in DEFAULT_CONFIG_FILENAMES:
        path = repo_root / candidate
        if path.exists():
            return path
    return None


def load_config(repo_root: Path, config_path: Path | None = None) -> PolicyConfig:
    resolved = resolve_config_path(repo_root, config_path)
    if resolved is None or not resolved.exists():
        return PolicyConfig()

    with resolved.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}

    return parse_config(raw)


def parse_config(raw: dict[str, Any]) -> PolicyConfig:
    min_severity = Severity.from_value(raw.get("min_severity", Severity.HIGH.value))
    ignore_rules = {str(rule_id) for rule_id in raw.get("ignore_rules", [])}
    trusted_action_owners = {
        str(owner).lower() for owner in raw.get("trusted_action_owners", ["actions", "github", "docker"])
    }
    secret_scan_raw = raw.get("secret_scan", {}) or {}
    secret_scan = SecretScanSettings(
        enabled=bool(secret_scan_raw.get("enabled", True)),
        max_file_size_kb=int(secret_scan_raw.get("max_file_size_kb", 256)),
    )
    return PolicyConfig(
        min_severity=min_severity,
        ignore_rules=ignore_rules,
        trusted_action_owners=trusted_action_owners,
        secret_scan=secret_scan,
    )
