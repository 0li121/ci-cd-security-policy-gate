from __future__ import annotations

from abc import ABC, abstractmethod

from policy_gate.models import Finding, RepositoryContext, RuleMetadata, WorkflowDocument


class BaseRule(ABC):
    metadata: RuleMetadata

    @abstractmethod
    def evaluate(
        self, context: RepositoryContext, workflows: list[WorkflowDocument]
    ) -> list[Finding]:
        raise NotImplementedError
