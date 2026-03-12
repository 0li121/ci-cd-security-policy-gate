from __future__ import annotations

import re

from policy_gate.findings import build_finding
from policy_gate.models import RepositoryContext, RuleMetadata, Severity, WorkflowDocument
from policy_gate.rules.base import BaseRule


SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("openai-api-key", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b")),
    (
        "hardcoded-password",
        re.compile(r"(?i)\b(password|api_key|secret)\b\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
    ),
)

BINARY_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".pdf",
    ".zip",
    ".gz",
    ".tar",
    ".jar",
    ".pyc",
}


class CommittedSecretsRule(BaseRule):
    metadata = RuleMetadata(
        rule_id="PG006",
        name="committed-secrets",
        severity=Severity.CRITICAL,
        description="Performs a lightweight scan for obvious secrets committed to the repository.",
        remediation="Remove the secret, rotate it, and move sensitive values into a secure secret manager.",
    )

    def evaluate(
        self, context: RepositoryContext, workflows: list[WorkflowDocument]
    ) -> list:
        if not context.config.secret_scan.enabled:
            return []

        findings = []
        max_bytes = context.config.secret_scan.max_file_size_kb * 1024

        for path in context.files:
            if path.suffix.lower() in BINARY_EXTENSIONS:
                continue
            if path.stat().st_size > max_bytes:
                continue
            content = path.read_text(encoding="utf-8", errors="ignore")
            for pattern_name, pattern in SECRET_PATTERNS:
                match = pattern.search(content)
                if not match:
                    continue
                findings.append(
                    build_finding(
                        self.metadata,
                        file_path=str(path.relative_to(context.root)),
                        message=f"Potential committed secret matched pattern '{pattern_name}'.",
                        details={"pattern": pattern_name},
                    )
                )
                break
        return findings
