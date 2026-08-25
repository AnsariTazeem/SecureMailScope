"""SecureMailScope command-line interface.

Presentation layer only: prerequisite logic lives in `tooling.py`.
"""

from __future__ import annotations

from typing import Annotated

import typer

from securemailscope.models import CheckStatus, DoctorReport
from securemailscope.tooling import collect_doctor_report

EXIT_OK = 0
EXIT_PREREQUISITE_FAILURE = 3

app = typer.Typer(add_completion=False, no_args_is_help=True)


@app.callback()
def _root() -> None:
    """SecureMailScope passive email cryptographic posture analysis."""


@app.command()
def doctor(
    json_output: Annotated[
        bool, typer.Option("--json", help="Print the report as pure JSON without decoration.")
    ] = False,
) -> None:
    """Run deterministic prerequisite checks for the POC environment."""
    report = collect_doctor_report()
    if json_output:
        typer.echo(report.model_dump_json(indent=2))
    else:
        _render_report(report)
    raise typer.Exit(code=EXIT_OK if report.ready else EXIT_PREREQUISITE_FAILURE)


def _render_report(report: DoctorReport) -> None:
    for check in report.checks:
        marker = "PASS" if check.status is CheckStatus.PASS else "FAIL"
        typer.echo(f"[{marker}] {check.id}: {check.requirement}")
        typer.echo(f"        observed: {check.observed}")
    verdict = "READY" if report.ready else "NOT READY"
    typer.echo("")
    typer.echo(
        f"doctor: {verdict} (schema_version={report.schema_version}, checks={len(report.checks)})"
    )


if __name__ == "__main__":
    app()
