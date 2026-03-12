from __future__ import annotations

from policy_gate.findings import build_finding
from policy_gate.models import RepositoryContext, RuleMetadata, Severity, WorkflowDocument
from policy_gate.rules.base import BaseRule


class PullRequestTargetRule(BaseRule):
    metadata = RuleMetadata(
        rule_id="PG003",
        name="pull-request-target",
        severity=Severity.HIGH,
        description="Detects workflows triggered by pull_request_target, which can expose privileged tokens to untrusted code.",
        remediation="Avoid pull_request_target for workflows that execute code from untrusted pull requests. Prefer pull_request with restricted permissions.",
    )

    def evaluate(
        self, context: RepositoryContext, workflows: list[WorkflowDocument]
    ) -> list:
        findings = []
        for workflow in workflows:
            if not workflow.trigger.has_event("pull_request_target"):
                continue
            severity_message = "Dangerous use of pull_request_target detected."
            if _workflow_executes_code(workflow):
                severity_message = (
                    "Workflow uses pull_request_target and appears to execute repository-controlled code."
                )
            findings.append(
                build_finding(
                    self.metadata,
                    file_path=workflow.relative_path,
                    message=severity_message,
                )
            )
        return findings


def _workflow_executes_code(workflow: WorkflowDocument) -> bool:
    for job in workflow.jobs:
        for step in job.steps:
            if step.run:
                return True
            if step.uses and step.uses.startswith("actions/checkout@"):
                return True
    return False
