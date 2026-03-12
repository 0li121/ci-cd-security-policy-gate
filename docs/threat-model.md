# Threat Model

## Scope

`policy-gate` focuses on CI/CD security issues that can be identified from repository contents, especially GitHub Actions workflow definitions and adjacent software delivery files.

## Primary Assets

- Repository contents
- GitHub Actions runner execution environment
- `GITHUB_TOKEN` and other CI secrets
- Release artifacts and deployment credentials
- Dependency integrity and build reproducibility

## Threats Addressed

### Excessive Workflow Privileges

If a workflow or job requests `write-all`, a compromise in that job can lead to code tampering, issue manipulation, release abuse, or repository persistence.

### Mutable Third-Party Actions

Actions pinned to tags such as `@v1` can change over time. If a third-party publisher is compromised, the workflow can silently execute attacker-controlled code.

### `pull_request_target` Abuse

`pull_request_target` runs in the context of the base repository and may expose privileged tokens to logic influenced by an untrusted pull request. This is a common path to token theft and repository compromise.

### Unsafe Shell Execution

Patterns like `curl | bash` or `wget | sh` execute remote content directly and reduce auditability. `sudo` in CI can also increase blast radius and often indicates weak hardening.

### Missing Lockfiles

Without lockfiles, builds are less reproducible and dependency updates become harder to review. That increases software supply chain risk.

### Committed Secrets

Leaked tokens or hardcoded secrets can provide direct access to infrastructure, source control, or AI systems.

## Deliberate Non-Goals for MVP

- Full workflow semantic execution modeling
- Cross-repository trust analysis
- SBOM generation
- Cryptographic signature verification for actions
- Comprehensive secret scanning comparable to dedicated tools like Gitleaks

Those are valid future directions, but they would distract from the core policy-gate use case in a 10 to 14 day build.
