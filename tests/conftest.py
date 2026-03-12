from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture()
def repo_root(tmp_path: Path) -> Path:
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    return tmp_path
