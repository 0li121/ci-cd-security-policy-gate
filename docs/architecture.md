# Architecture

## Design Goals

- Keep the MVP small enough for one developer to ship in 10 to 14 days.
- Make the code easy to explain during an interview.
- Separate repository discovery, parsing, rule evaluation, formatting, and CLI concerns.
- Favor clear rule logic over heavy abstractions.

## High-Level Flow

1. The CLI parses arguments and loads repository configuration.
2. Repository discovery identifies workflow files and candidate files for secret and lockfile checks.
3. The GitHub Actions parser normalizes workflow YAML into stable Python dataclasses.
4. Rule modules evaluate the repository context and return normalized findings.
5. The scanner aggregates findings and determines whether blocking severity thresholds were met.
6. The formatter renders findings as text or JSON.

## Package Layout

- `policy_gate/cli.py`
  Entry point and argument handling.
- `policy_gate/config.py`
  Loads `.policy-gate.yml` and normalizes config values.
- `policy_gate/repo_discovery.py`
  Finds workflow files and repository files while skipping common generated directories.
- `policy_gate/parsers/github_actions.py`
  Safely parses GitHub Actions YAML and normalizes triggers, jobs, and steps.
- `policy_gate/rules/`
  Small, independent rule implementations with explicit metadata.
- `policy_gate/scanner.py`
  Orchestrates config, discovery, parsing, rule execution, and blocking decisions.
- `policy_gate/formatter.py`
  Converts normalized findings to human-readable or JSON output.

## Why a Rule-Based Design

This project is intentionally not a generic policy engine. A simple rule interface keeps the codebase easy to extend without introducing unnecessary complexity for an MVP. Each rule has:

- A stable rule ID
- A severity
- A description
- Remediation guidance
- A small `evaluate()` method

That structure is enough to demonstrate practical security engineering without building a framework.

## Known MVP Constraints

- GitHub Actions parsing is schema-light and intentionally conservative.
- Secret scanning uses a few high-signal regexes instead of a full entropy engine.
- The tool focuses on repository-local risk signals and does not call external APIs.
