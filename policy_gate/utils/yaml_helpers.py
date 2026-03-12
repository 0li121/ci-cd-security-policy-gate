from __future__ import annotations

from typing import Any


def get_yaml_key(mapping: dict[str, Any], key: str) -> Any:
    return mapping.get(key, mapping.get(True if key == "on" else key))
