"""Rule contract.

Every rule answers one question about one call site and cites one obligation.
Rules see a language-neutral `FileModel`, never a Python AST — that is what
lets the same two rules run over Python and TypeScript without either of them
knowing which is which.

Rules that need whole-repo knowledge (does this endpoint eventually reach a
model?) receive it through `repo`, so the analyzer stays the only thing that
touches disk.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

from ..callgraph import RepoModel
from ..filemodel import CallRef, FileModel, FunctionModel
from ..models import CodeFinding, LegalReference
from .. import providers


@dataclass
class RuleContext:
    """Everything a rule may look at for a single file."""
    file: FileModel
    # Reachability across the whole repository. None for single-file analysis,
    # where a rule must fall back to claims it can make from one file alone.
    repo: Optional[RepoModel] = None

    @property
    def path(self) -> str:
        return self.file.path

    @property
    def source(self) -> str:
        return self.file.source

    @property
    def imports(self) -> set[str]:
        return self.file.imports

    @property
    def calls(self) -> list[CallRef]:
        return self.file.all_calls()

    @property
    def chain_context(self) -> bool:
        """This file builds an LLM object, so chain verbs count as generation."""
        return providers.constructs_llm(tuple(c.callee for c in self.calls))

    def is_generation(self, callee: str) -> bool:
        """Generated content — what Article 50 is about."""
        return providers.is_generation_call(callee, self.chain_context)

    @property
    def ml_context(self) -> bool:
        """This file loads or uses a trained model."""
        return providers.uses_ml(
            self.file.imports, tuple(call.callee for call in self.calls),
        )

    def is_inference(self, callee: str) -> bool:
        """Any model asked for an output — what Articles 12 and 14 are about."""
        return providers.is_inference_call(callee, self.chain_context, self.ml_context)

    @property
    def uses_provider(self) -> bool:
        """Evidence of a model provider, from imports or from call shape."""
        if providers.uses_provider(
            self.file.imports, tuple(call.callee for call in self.calls)
        ):
            return True
        # A LangChain file may name no provider module directly, and a
        # classical model has no provider at all.
        return self.chain_context or self.ml_context

    def occurrence_of(self, func: FunctionModel, call: CallRef) -> int:
        """Index of this call among identical calls in the same function.

        Two identical calls in one function would otherwise collapse to the
        same fingerprint and one would silently disappear.
        """
        seen = 0
        for other in func.calls:
            if other is call:
                return seen
            if other.callee == call.callee:
                seen += 1
        return seen


class Rule(ABC):
    """One rule = one rule_id = one obligation."""

    rule_id: str
    severity: str = "medium"
    title: str = ""
    # True where the rule reads an obligation rather than matching its plain
    # words. Advisory findings are reported but never fail a build — a noisy
    # gate discredits the precise rules sitting beside it.
    advisory: bool = False
    # What this rule knowingly cannot see. Stated here rather than in a
    # document, so a reviewer reads the same list the code is written against.
    limitations: tuple[str, ...] = ()

    @property
    @abstractmethod
    def legal(self) -> LegalReference:
        """The obligation this rule cites, quoted rather than paraphrased."""

    @abstractmethod
    def analyze(self, ctx: RuleContext) -> list[CodeFinding]:
        """Return findings for one file. Must not raise on odd input."""


def registry() -> list[Rule]:
    """Rules in the order they should run.

    Ordered by how unambiguous the underlying legal text is, not by how useful
    the rule feels — a noisy rule discredits the precise ones next to it.
    """
    from .art5_practices import (
        Article5BiometricCategorisation,
        Article5FacialScraping,
        Article5LiveBiometricId,
        Article5PredictivePolicing,
        Article5SocialScoring,
    )
    from .art5_signals import Article5EmotionSignal
    from .art10_data_governance import Article10DataGovernance
    from .art12_logging import Article12Logging
    from .art14_oversight import Article14Oversight
    from .art50_transparency import Article50Disclosure

    # Explicit-text rules first, then the advisory ones that read an obligation.
    return [
        Article50Disclosure(),
        Article12Logging(),
        Article14Oversight(),
        Article10DataGovernance(),
        Article5EmotionSignal(),
        Article5FacialScraping(),
        Article5BiometricCategorisation(),
        Article5SocialScoring(),
        Article5PredictivePolicing(),
        Article5LiveBiometricId(),
    ]
