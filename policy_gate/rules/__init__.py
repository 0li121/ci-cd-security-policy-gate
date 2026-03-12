from policy_gate.rules.committed_secrets import CommittedSecretsRule
from policy_gate.rules.missing_lockfiles import MissingLockfilesRule
from policy_gate.rules.permissions_write_all import PermissionsWriteAllRule
from policy_gate.rules.pull_request_target import PullRequestTargetRule
from policy_gate.rules.unpinned_actions import UnpinnedActionsRule
from policy_gate.rules.unsafe_shell_commands import UnsafeShellCommandsRule

ALL_RULES = [
    PermissionsWriteAllRule,
    UnpinnedActionsRule,
    PullRequestTargetRule,
    UnsafeShellCommandsRule,
    MissingLockfilesRule,
    CommittedSecretsRule,
]
