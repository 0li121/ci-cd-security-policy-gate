from __future__ import annotations

import re

from policy_gate.findings import build_finding
from policy_gate.models import RepositoryContext, RuleMetadata, Severity, WorkflowDocument
from policy_gate.rules.base import BaseRule


UNSAFE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("curl-pipe-shell", re.compile(r"curl\b[^|\n]*\|\s*(bash|sh)\b", re.IGNORECASE)),
    ("wget-pipe-shell", re.compile(r"wget\b[^|\n]*\|\s*(bash|sh)\b", re.IGNORECASE)),
    ("bash-process-substitution", re.compile(r"(bash|sh)\s*<\(\s*curl\b", re.IGNORECASE)),
    ("sudo-usage", re.compile(r"\bsudo\b", re.IGNORECASE)),
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
                    for pattern_name, pattern in UNSAFE_PATTERNS:
                        if not pattern.search(step.run):
                            continue
                        findings.append(
                            build_finding(
                                self.metadata,
                                file_path=workflow.relative_path,
                                message=f"Unsafe shell pattern '{pattern_name}' found in job '{job.job_id}'.",
                                details={"job_id": job.job_id, "pattern": pattern_name},
                            )
                        )
                        break
        return findings
