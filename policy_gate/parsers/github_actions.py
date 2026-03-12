from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from policy_gate.models import WorkflowDocument, WorkflowJob, WorkflowStep


def parse_workflow_file(path: Path, repo_root: Path) -> WorkflowDocument:
    with path.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}

    if not isinstance(raw, dict):
        raise ValueError(f"Workflow file {path} did not parse to a mapping")

    # PyYAML follows YAML 1.1 rules and can coerce `on` into boolean True.
    triggers = raw.get("on", raw.get(True))
    jobs_raw = raw.get("jobs", {}) or {}
    jobs: list[WorkflowJob] = []

    for job_id, job_data in jobs_raw.items():
        if not isinstance(job_data, dict):
            continue
        steps_raw = job_data.get("steps", []) or []
        steps = [_normalize_step(step) for step in steps_raw if isinstance(step, dict)]
        jobs.append(
            WorkflowJob(
                job_id=str(job_id),
                permissions=job_data.get("permissions"),
                steps=steps,
            )
        )

    return WorkflowDocument(
        file_path=path.relative_to(repo_root),
        name=str(raw.get("name", path.name)),
        triggers=triggers,
        permissions=raw.get("permissions"),
        jobs=jobs,
        raw=raw,
    )


def _normalize_step(step: dict[str, Any]) -> WorkflowStep:
    return WorkflowStep(
        name=step.get("name"),
        uses=step.get("uses"),
        run=step.get("run"),
    )
