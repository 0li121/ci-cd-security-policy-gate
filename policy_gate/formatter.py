from __future__ import annotations

import json

from policy_gate.models import Finding


def format_findings_text(findings: list[Finding]) -> str:
    if not findings:
        return "No findings detected."

    lines: list[str] = []
    for finding in findings:
        header = f"[{finding.severity.value.upper()}] {finding.rule_id} {finding.file_path}"
        if finding.line is not None:
            header += f":{finding.line}"
        lines.append(header)
        lines.append(f"  {finding.message}")
        lines.append(f"  Remediation: {finding.remediation}")
    return "\n".join(lines)


def format_findings_json(findings: list[Finding]) -> str:
    return json.dumps([finding.to_dict() for finding in findings], indent=2)
