from pathlib import Path

from policy_gate.models import PolicyConfig
from policy_gate.repo_discovery import build_repository_context
from policy_gate.rules.missing_lockfiles import MissingLockfilesRule


def test_missing_lockfiles_rule_flags_package_json_without_lockfile(repo_root: Path) -> None:
    (repo_root / "package.json").write_text('{"name": "demo"}', encoding="utf-8")

    context = build_repository_context(repo_root, PolicyConfig())

    findings = MissingLockfilesRule().evaluate(context, [])

    assert len(findings) == 1
    assert findings[0].file_path == "package.json"


def test_missing_lockfiles_rule_skips_when_lockfile_exists(repo_root: Path) -> None:
    (repo_root / "package.json").write_text('{"name": "demo"}', encoding="utf-8")
    (repo_root / "package-lock.json").write_text("{}", encoding="utf-8")

    context = build_repository_context(repo_root, PolicyConfig())

    findings = MissingLockfilesRule().evaluate(context, [])

    assert findings == []
