from __future__ import annotations

from pathlib import Path


def is_text_like_file(path: Path) -> bool:
    return path.suffix.lower() not in {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz"}
