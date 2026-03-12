from pathlib import Path

from policy_gate.models import PolicyConfig, SecretScanSettings
from policy_gate.repo_discovery import build_repository_context
from policy_gate.rules.committed_secrets import CommittedSecretsRule


def test_committed_secrets_rule_flags_high_signal_token(repo_root: Path) -> None:
    token = "gh" + "p_1234567890abcdefghijklmnopqrstuvwxyz"
    (repo_root / "app.py").write_text(
        f'token = "{token}"\n',
        encoding="utf-8",
    )

    context = build_repository_context(repo_root, PolicyConfig())

    findings = CommittedSecretsRule().evaluate(context, [])

    assert len(findings) == 1
    assert findings[0].rule_id == "PG006"


def test_committed_secrets_rule_can_be_disabled(repo_root: Path) -> None:
    token = "gh" + "p_1234567890abcdefghijklmnopqrstuvwxyz"
    (repo_root / "app.py").write_text(
        f'token = "{token}"\n',
        encoding="utf-8",
    )

    config = PolicyConfig(secret_scan=SecretScanSettings(enabled=False, max_file_size_kb=256))
    context = build_repository_context(repo_root, config)

    findings = CommittedSecretsRule().evaluate(context, [])

    assert findings == []
