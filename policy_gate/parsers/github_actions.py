from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from policy_gate.models import WorkflowDocument, WorkflowJob, WorkflowStep, WorkflowTrigger


def parse_workflow_file(path: Path, repo_root: Path) -> WorkflowDocument:
    with path.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}

    if not isinstance(raw, dict):
        raise ValueError(f"Workflow file {path} did not parse to a mapping")

    # PyYAML follows YAML 1.1 rules and can coerce `on` into boolean True.
    triggers_raw = raw.get("on", raw.get(True))
    jobs_raw = raw.get("jobs", {}) or {}
    jobs: list[WorkflowJob] = []

    for job_id, job_data in jobs_raw.items():
        if not isinstance(job_data, dict):
            continue
        steps_raw = job_data.get("steps", []) or []
        steps = [
            _normalize_step(index, step)
            for index, step in enumerate(steps_raw)
            if isinstance(step, dict)
        ]
        jobs.append(
            WorkflowJob(
                job_id=str(job_id),
                name=_normalize_optional_string(job_data.get("name")),
                permissions=job_data.get("permissions"),
                steps=steps,
            )
        )

    return WorkflowDocument(
        file_path=path.relative_to(repo_root),
        name=str(raw.get("name", path.name)),
        trigger=_normalize_trigger(triggers_raw),
        permissions=raw.get("permissions"),
        jobs=jobs,
        raw=raw,
    )


def _normalize_step(step_index: int, step: dict[str, Any]) -> WorkflowStep:
    return WorkflowStep(
        step_index=step_index,
        name=_normalize_optional_string(step.get("name")),
        uses=_normalize_optional_string(step.get("uses")),
        run=_normalize_optional_string(step.get("run")),
    )


def _normalize_trigger(triggers_raw: Any) -> WorkflowTrigger:
    if isinstance(triggers_raw, str):
        events = (triggers_raw,)
    elif isinstance(triggers_raw, list):
        events = tuple(str(item) for item in triggers_raw)
    elif isinstance(triggers_raw, dict):
        events = tuple(str(key) for key in triggers_raw.keys())
    else:
        events = ()
    return WorkflowTrigger(events=events, raw=triggers_raw)


def _normalize_optional_string(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        normalized = value.strip()
        return normalized or None
    return str(value)
