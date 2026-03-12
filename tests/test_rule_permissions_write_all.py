from pathlib import Path

from policy_gate.models import PolicyConfig
from policy_gate.parsers.github_actions import parse_workflow_file
from policy_gate.repo_discovery import build_repository_context
from policy_gate.rules.permissions_write_all import PermissionsWriteAllRule


def test_permissions_write_all_rule_flags_workflow_and_job(repo_root: Path) -> None:
    workflow_path = repo_root / ".github" / "workflows" / "ci.yml"
    workflow_path.write_text(
        """
name: ci
on: push
permissions: write-all
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions: write-all
    steps:
      - run: echo hi
""".strip(),
        encoding="utf-8",
    )

    context = build_repository_context(repo_root, PolicyConfig())
    workflows = [parse_workflow_file(workflow_path, repo_root)]

    findings = PermissionsWriteAllRule().evaluate(context, workflows)

    assert len(findings) == 2
    assert {finding.rule_id for finding in findings} == {"PG001"}
    assert findings[1].job_id == "deploy"
