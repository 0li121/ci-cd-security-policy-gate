from __future__ import annotations

from pathlib import Path

from policy_gate.config import load_config
from policy_gate.models import Finding, PolicyConfig, ScanResult, Severity
from policy_gate.parsers.github_actions import parse_workflow_file
from policy_gate.repo_discovery import build_repository_context
from policy_gate.rules import ALL_RULES


def scan_repository(
    target: Path,
    *,
    config_path: Path | None = None,
    min_severity: Severity | None = None,
) -> ScanResult:
    root = target.resolve()
    config = load_config(root, config_path)
    effective_config = _with_overrides(config, min_severity)
    context = build_repository_context(root, effective_config)
    workflows = [parse_workflow_file(path, root) for path in context.workflow_files]

    findings: list[Finding] = []
    for rule_cls in ALL_RULES:
        rule = rule_cls()
        if rule.metadata.rule_id in effective_config.ignore_rules:
            continue
        findings.extend(rule.evaluate(context, workflows))

    findings.sort(key=lambda finding: (finding.severity.rank(), finding.file_path, finding.rule_id))
    blocking = [
        finding
        for finding in findings
        if finding.severity.meets_or_exceeds(effective_config.min_severity)
    ]
    return ScanResult(findings=findings, blocking_findings=blocking, parsed_workflows=workflows)


def _with_overrides(config: PolicyConfig, min_severity: Severity | None) -> PolicyConfig:
    if min_severity is None:
        return config
    return PolicyConfig(
        min_severity=min_severity,
        ignore_rules=config.ignore_rules,
        trusted_action_owners=config.trusted_action_owners,
        secret_scan=config.secret_scan,
    )
