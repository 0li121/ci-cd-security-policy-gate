from pathlib import Path

from policy_gate.parsers.github_actions import parse_workflow_file


def test_parse_workflow_handles_on_key(tmp_path: Path) -> None:
    workflow_path = tmp_path / ".github" / "workflows" / "ci.yml"
    workflow_path.parent.mkdir(parents=True)
    workflow_path.write_text(
        """
name: test
on:
  pull_request:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pytest
""".strip(),
        encoding="utf-8",
    )

    workflow = parse_workflow_file(workflow_path, tmp_path)

    assert workflow.name == "test"
    assert workflow.triggers == {"pull_request": None}
    assert workflow.jobs[0].job_id == "build"
    assert workflow.jobs[0].steps[1].run == "pytest"
