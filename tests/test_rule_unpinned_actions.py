from pathlib import Path

from policy_gate.models import PolicyConfig
from policy_gate.parsers.github_actions import parse_workflow_file
from policy_gate.repo_discovery import build_repository_context
from policy_gate.rules.unpinned_actions import UnpinnedActionsRule


def test_unpinned_actions_rule_flags_mutable_third_party_action(repo_root: Path) -> None:
    workflow_path = repo_root / ".github" / "workflows" / "ci.yml"
    workflow_path.write_text(
        """
name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: vendor/suspicious-action@v1
      - uses: vendor/pinned-action@0123456789abcdef0123456789abcdef01234567
""".strip(),
        encoding="utf-8",
    )

    context = build_repository_context(repo_root, PolicyConfig())
    workflows = [parse_workflow_file(workflow_path, repo_root)]

    findings = UnpinnedActionsRule().evaluate(context, workflows)

    assert len(findings) == 1
    assert findings[0].rule_id == "PG002"
