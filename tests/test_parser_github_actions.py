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
    assert workflow.trigger.events == ("pull_request",)
    assert workflow.jobs[0].job_id == "build"
    assert workflow.jobs[0].steps[0].step_index == 0
    assert workflow.jobs[0].steps[1].run == "pytest"


def test_parse_workflow_normalizes_list_triggers_and_step_names(tmp_path: Path) -> None:
    workflow_path = tmp_path / ".github" / "workflows" / "release.yml"
    workflow_path.parent.mkdir(parents=True, exist_ok=True)
    workflow_path.write_text(
        """
name: release
on: [push, workflow_dispatch]
jobs:
  publish:
    name: Publish package
    runs-on: ubuntu-latest
    steps:
      - name:  Checkout
        uses: actions/checkout@v4
      - run:  python -m build
""".strip(),
        encoding="utf-8",
    )

    workflow = parse_workflow_file(workflow_path, tmp_path)

    assert workflow.trigger.events == ("push", "workflow_dispatch")
    assert workflow.jobs[0].name == "Publish package"
    assert workflow.jobs[0].steps[0].name == "Checkout"
