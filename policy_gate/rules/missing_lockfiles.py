from __future__ import annotations

from pathlib import Path

from policy_gate.findings import build_finding
from policy_gate.models import RepositoryContext, RuleMetadata, Severity, WorkflowDocument
from policy_gate.rules.base import BaseRule


class MissingLockfilesRule(BaseRule):
    metadata = RuleMetadata(
        rule_id="PG005",
        name="missing-lockfiles",
        severity=Severity.MEDIUM,
        description="Detects repositories that define dependencies without a corresponding lockfile.",
        remediation="Commit the package manager lockfile so builds are reproducible and dependency changes are reviewable.",
    )

    def evaluate(
        self, context: RepositoryContext, workflows: list[WorkflowDocument]
    ) -> list:
        findings = []
        files = {path.relative_to(context.root) for path in context.files}

        package_json = Path("package.json")
        if package_json in files and not any(
            Path(name) in files for name in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml")
        ):
            findings.append(
                build_finding(
                    self.metadata,
                    file_path=str(package_json),
                    message="package.json found without npm, Yarn, or pnpm lockfile.",
                )
            )

        pipfile = Path("Pipfile")
        if pipfile in files and Path("Pipfile.lock") not in files:
            findings.append(
                build_finding(
                    self.metadata,
                    file_path=str(pipfile),
                    message="Pipfile found without Pipfile.lock.",
                )
            )

        pyproject = context.root / "pyproject.toml"
        poetry_lock = Path("poetry.lock")
        if pyproject.exists() and poetry_lock not in files and _uses_poetry(pyproject):
            findings.append(
                build_finding(
                    self.metadata,
                    file_path="pyproject.toml",
                    message="Poetry project found without poetry.lock.",
                )
            )

        return findings


def _uses_poetry(pyproject_path: Path) -> bool:
    content = pyproject_path.read_text(encoding="utf-8")
    return "[tool.poetry]" in content
