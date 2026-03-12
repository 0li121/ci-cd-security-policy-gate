from __future__ import annotations

from pathlib import Path

from policy_gate.models import PolicyConfig, RepositoryContext


IGNORED_DIR_NAMES = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    "dist",
    "build",
    ".mypy_cache",
    ".pytest_cache",
}


def build_repository_context(root: Path, config: PolicyConfig) -> RepositoryContext:
    workflow_dir = root / ".github" / "workflows"
    workflow_files = sorted(
        [
            *workflow_dir.glob("*.yml"),
            *workflow_dir.glob("*.yaml"),
        ]
    )
    files = discover_files(root)
    return RepositoryContext(root=root, workflow_files=workflow_files, files=files, config=config)


def discover_files(root: Path) -> list[Path]:
    discovered: list[Path] = []
    for path in root.rglob("*"):
        if path.is_dir():
            continue
        if any(part in IGNORED_DIR_NAMES for part in path.parts):
            continue
        discovered.append(path)
    return sorted(discovered)
