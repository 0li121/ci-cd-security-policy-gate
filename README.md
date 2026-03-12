# CI/CD Security Policy Gate

CI/CD Security Policy Gate is a Python CLI tool that scans GitHub repositories for insecure CI/CD configurations, especially GitHub Actions workflows, and fails the pipeline when dangerous settings are detected.

## Why this project exists

Modern software delivery pipelines are part of the attack surface. Misconfigured GitHub Actions workflows, overly broad permissions, unpinned third-party actions, and unsafe execution patterns can all create security risk.

This tool is designed to demonstrate practical security engineering through policy-as-code controls for CI/CD.

## MVP goals

- Scan GitHub Actions workflows
- Detect insecure CI/CD patterns
- Report findings with remediation guidance
- Fail CI when blocking issues are present
- Integrate cleanly into GitHub Actions

## Planned checks

- overly broad permissions
- unpinned third-party actions
- dangerous pull_request_target usage
- unsafe shell commands
- missing lockfiles
- lightweight committed secret detection

## Status

Initial scaffold in progress.
