from __future__ import annotations

from policy_gate.findings import build_finding
from policy_gate.models import RepositoryContext, RuleMetadata, Severity, WorkflowDocument
from policy_gate.rules.base import BaseRule


class PermissionsWriteAllRule(BaseRule):
    metadata = RuleMetadata(
        rule_id="PG001",
        name="permissions-write-all",
        severity=Severity.HIGH,
        description="Detects workflows or jobs that request write-all permissions.",
        remediation="Set explicit least-privilege permissions instead of using write-all.",
    )

    def evaluate(
        self, context: RepositoryContext, workflows: list[WorkflowDocument]
    ) -> list:
        findings = []
        for workflow in workflows:
            if workflow.permissions == "write-all":
                findings.append(
                    build_finding(
                        self.metadata,
                        file_path=workflow.relative_path,
                        message="Workflow requests write-all permissions.",
                    )
                )
            for job in workflow.jobs:
                if job.permissions == "write-all":
                    findings.append(
                        build_finding(
                            self.metadata,
                            file_path=workflow.relative_path,
                            message=f"Job '{job.job_id}' requests write-all permissions.",
                            details={"job_id": job.job_id},
                        )
                    )
        return findings
