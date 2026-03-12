from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from policy_gate import __version__
from policy_gate.exit_codes import BLOCKING_FINDINGS, SUCCESS
from policy_gate.formatter import format_findings_json, format_findings_text
from policy_gate.models import Severity
from policy_gate.scanner import scan_repository


app = typer.Typer(help="Scan repositories for insecure CI/CD configurations.")


@app.command()
def scan(
    target: Annotated[Path, typer.Argument(exists=True, file_okay=False, dir_okay=True)] = Path("."),
    config: Annotated[Path | None, typer.Option("--config", exists=True, dir_okay=False)] = None,
    min_severity: Annotated[Severity, typer.Option("--min-severity")] = Severity.HIGH,
    output_format: Annotated[str, typer.Option("--format")] = "text",
) -> None:
    if output_format not in {"text", "json"}:
        raise typer.BadParameter("--format must be either 'text' or 'json'")

    result = scan_repository(
        target,
        config_path=config,
        min_severity=min_severity,
    )
    if output_format == "json":
        typer.echo(format_findings_json(result.findings))
    else:
        typer.echo(format_findings_text(result.findings))

    raise typer.Exit(code=SUCCESS if result.passed else BLOCKING_FINDINGS)


@app.callback()
def main_callback(
    version: Annotated[bool | None, typer.Option("--version", help="Show version and exit.")] = None,
) -> None:
    if version:
        typer.echo(__version__)
        raise typer.Exit()


def main() -> None:
    app()


if __name__ == "__main__":
    main()
