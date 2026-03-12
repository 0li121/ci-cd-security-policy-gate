from pathlib import Path

from typer.testing import CliRunner

from policy_gate.cli import app


runner = CliRunner()


def test_cli_scan_returns_non_zero_for_blocking_findings(tmp_path: Path) -> None:
    workflow_path = tmp_path / ".github" / "workflows" / "ci.yml"
    workflow_path.parent.mkdir(parents=True)
    workflow_path.write_text(
        """
name: ci
on: push
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
""".strip(),
        encoding="utf-8",
    )

    result = runner.invoke(app, ["scan", str(tmp_path)])

    assert result.exit_code == 1
    assert "PG001" in result.stdout


def test_cli_scan_json_output(tmp_path: Path) -> None:
    workflow_path = tmp_path / ".github" / "workflows" / "ci.yml"
    workflow_path.parent.mkdir(parents=True)
    workflow_path.write_text(
        """
name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: vendor/action@v1
""".strip(),
        encoding="utf-8",
    )

    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])

    assert result.exit_code == 1
    assert '"rule_id": "PG002"' in result.stdout
