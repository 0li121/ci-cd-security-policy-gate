from __future__ import annotations

import re

from policy_gate.findings import build_finding
from policy_gate.models import RepositoryContext, RuleMetadata, Severity, WorkflowDocument
from policy_gate.rules.base import BaseRule


UNSAFE_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    (
        "curl-pipe-shell",
        "Pipes remote content from curl directly into a shell.",
        re.compile(r"curl\b[^|\n]*\|\s*(bash|sh)\b", re.IGNORECASE),
    ),
    (
        "wget-pipe-shell",
        "Pipes remote content from wget directly into a shell.",
        re.compile(r"wget\b[^|\n]*\|\s*(bash|sh)\b", re.IGNORECASE),
    ),
    (
        "bash-process-substitution",
        "Executes curl output via process substitution.",
        re.compile(r"(bash|sh)\s*<\(\s*curl\b", re.IGNORECASE),
    ),
    (
        "curl-command-substitution",
        "Executes remote content using command substitution.",
        re.compile(r"(bash|sh)\s+-c\s+[\"']?\$\(\s*curl\b", re.IGNORECASE),
    ),
    (
        "sudo-usage",
        "Uses sudo in CI, which often indicates unnecessary privilege escalation.",
        re.compile(r"\bsudo\b", re.IGNORECASE),
    ),
)


class UnsafeShellCommandsRule(BaseRule):
    metadata = RuleMetadata(
        rule_id="PG004",
        name="unsafe-shell-commands",
        severity=Severity.HIGH,
        description="Detects obviously dangerous shell execution patterns inside workflow steps.",
        remediation="Avoid piping remote content into a shell, remove unnecessary sudo, and validate downloaded artifacts before execution.",
    )

    def evaluate(
        self, context: RepositoryContext, workflows: list[WorkflowDocument]
    ) -> list:
        findings = []
        for workflow in workflows:
            for job in workflow.jobs:
                for step in job.steps:
                    if not step.run:
                        continue
                    for line_number, command_line in enumerate(_iter_command_lines(step.run), start=1):
                        match = _match_unsafe_pattern(command_line)
                        if not match:
                            continue
                        pattern_name, description = match
                        findings.append(
                            build_finding(
                                self.metadata,
                                file_path=workflow.relative_path,
                                message=(
                                    f"{description} Job '{job.job_id}' contains unsafe command: "
                                    f"{command_line}"
                                ),
                                job_id=job.job_id,
                                step_name=step.name,
                                line=line_number,
                                details={
                                    "job_id": job.job_id,
                                    "pattern": pattern_name,
                                    "command": command_line,
                                },
                            )
                        )
        return findings


def _iter_command_lines(command_block: str) -> list[str]:
    lines: list[str] = []
    for raw_line in command_block.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lines.append(stripped)
    return lines


def _match_unsafe_pattern(command_line: str) -> tuple[str, str] | None:
    for pattern_name, description, pattern in UNSAFE_PATTERNS:
        if pattern.search(command_line):
            return pattern_name, description
    return None
