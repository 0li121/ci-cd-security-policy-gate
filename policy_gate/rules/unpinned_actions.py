from __future__ import annotations

import re

from policy_gate.findings import build_finding
from policy_gate.models import RepositoryContext, RuleMetadata, Severity, WorkflowDocument
from policy_gate.rules.base import BaseRule


SHA_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")


class UnpinnedActionsRule(BaseRule):
    metadata = RuleMetadata(
        rule_id="PG002",
        name="unpinned-actions",
        severity=Severity.HIGH,
        description="Detects third-party GitHub Actions that are pinned to mutable tags instead of commit SHAs.",
        remediation="Pin third-party actions to a full commit SHA and review the publisher before use.",
    )

    def evaluate(
        self, context: RepositoryContext, workflows: list[WorkflowDocument]
    ) -> list:
        findings = []
        trusted = context.config.trusted_action_owners
        for workflow in workflows:
            for job in workflow.jobs:
                for step in job.steps:
                    if not step.uses or "/" not in step.uses or "@" not in step.uses:
                        continue
                    action_ref, ref = step.uses.split("@", 1)
                    owner = action_ref.split("/", 1)[0].lower()
                    if owner in trusted:
                        continue
                    if SHA_PATTERN.fullmatch(ref):
                        continue
                    findings.append(
                        build_finding(
                            self.metadata,
                            file_path=workflow.relative_path,
                            message=f"Third-party action '{step.uses}' is not pinned to a commit SHA.",
                            details={"job_id": job.job_id, "action": step.uses},
                        )
                    )
        return findings
