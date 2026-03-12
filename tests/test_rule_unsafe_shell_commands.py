from pathlib import Path

from policy_gate.models import PolicyConfig
from policy_gate.parsers.github_actions import parse_workflow_file
from policy_gate.repo_discovery import build_repository_context
from policy_gate.rules.unsafe_shell_commands import UnsafeShellCommandsRule


def test_unsafe_shell_commands_rule_flags_pipe_to_shell(repo_root: Path) -> None:
    workflow_path = repo_root / ".github" / "workflows" / "ci.yml"
    workflow_path.write_text(
        """
name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: curl -sSf https://example.com/install.sh | bash
      - run: echo safe
""".strip(),
        encoding="utf-8",
    )

    context = build_repository_context(repo_root, PolicyConfig())
    workflows = [parse_workflow_file(workflow_path, repo_root)]

    findings = UnsafeShellCommandsRule().evaluate(context, workflows)

    assert len(findings) == 1
    assert findings[0].rule_id == "PG004"
