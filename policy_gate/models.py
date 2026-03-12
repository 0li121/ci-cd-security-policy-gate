from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def ordered(cls) -> list["Severity"]:
        return [cls.LOW, cls.MEDIUM, cls.HIGH, cls.CRITICAL]

    @classmethod
    def from_value(cls, value: str) -> "Severity":
        normalized = value.strip().lower()
        return cls(normalized)

    def rank(self) -> int:
        return self.ordered().index(self)

    def meets_or_exceeds(self, minimum: "Severity") -> bool:
        return self.rank() >= minimum.rank()


@dataclass(frozen=True)
class RuleMetadata:
    rule_id: str
    name: str
    severity: Severity
    description: str
    remediation: str


@dataclass(frozen=True)
class Finding:
    rule_id: str
    rule_name: str
    severity: Severity
    file_path: str
    message: str
    remediation: str
    line: int | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "file_path": self.file_path,
            "message": self.message,
            "remediation": self.remediation,
        }
        if self.line is not None:
            payload["line"] = self.line
        if self.details:
            payload["details"] = self.details
        return payload


@dataclass(frozen=True)
class WorkflowStep:
    name: str | None
    uses: str | None
    run: str | None


@dataclass(frozen=True)
class WorkflowJob:
    job_id: str
    permissions: str | dict[str, Any] | None
    steps: list[WorkflowStep]


@dataclass(frozen=True)
class WorkflowDocument:
    file_path: Path
    name: str
    triggers: Any
    permissions: str | dict[str, Any] | None
    jobs: list[WorkflowJob]
    raw: dict[str, Any]

    @property
    def relative_path(self) -> str:
        return str(self.file_path)


@dataclass(frozen=True)
class SecretScanSettings:
    enabled: bool = True
    max_file_size_kb: int = 256


@dataclass(frozen=True)
class PolicyConfig:
    min_severity: Severity = Severity.HIGH
    ignore_rules: set[str] = field(default_factory=set)
    trusted_action_owners: set[str] = field(
        default_factory=lambda: {"actions", "github", "docker"}
    )
    secret_scan: SecretScanSettings = field(default_factory=SecretScanSettings)


@dataclass(frozen=True)
class RepositoryContext:
    root: Path
    workflow_files: list[Path]
    files: list[Path]
    config: PolicyConfig


@dataclass(frozen=True)
class ScanResult:
    findings: list[Finding]
    blocking_findings: list[Finding]
    parsed_workflows: list[WorkflowDocument]

    @property
    def passed(self) -> bool:
        return not self.blocking_findings
