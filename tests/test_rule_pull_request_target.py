from pathlib import Path

from policy_gate.models import PolicyConfig
from policy_gate.parsers.github_actions import parse_workflow_file
from policy_gate.repo_discovery import build_repository_context
from policy_gate.rules.pull_request_target import PullRequestTargetRule


def test_pull_request_target_rule_flags_dangerous_trigger(repo_root: Path) -> None:
    workflow_path = repo_root / ".github" / "workflows" / "ci.yml"
    workflow_path.write_text(
        """
name: ci
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: make test
""".strip(),
        encoding="utf-8",
    )

    context = build_repository_context(repo_root, PolicyConfig())
    workflows = [parse_workflow_file(workflow_path, repo_root)]

    findings = PullRequestTargetRule().evaluate(context, workflows)

    assert len(findings) == 1
    assert "pull_request_target" in findings[0].message
