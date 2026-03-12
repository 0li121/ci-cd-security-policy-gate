"""Finding helpers kept separate for interview-friendly structure."""

from policy_gate.models import Finding, RuleMetadata


def build_finding(
    metadata: RuleMetadata,
    *,
    file_path: str,
    message: str,
    remediation: str | None = None,
    line: int | None = None,
    job_id: str | None = None,
    step_name: str | None = None,
    details: dict | None = None,
) -> Finding:
    return Finding(
        rule_id=metadata.rule_id,
        rule_name=metadata.name,
        severity=metadata.severity,
        file_path=file_path,
        message=message,
        remediation=remediation or metadata.remediation,
        line=line,
        job_id=job_id,
        step_name=step_name,
        details=details or {},
    )
