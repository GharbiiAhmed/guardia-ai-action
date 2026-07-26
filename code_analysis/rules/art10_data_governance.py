"""GA-ART10-001 — a model is trained with no fairness testing anywhere in the repo.

Advisory, for a reason worth stating plainly: this is an **absence claim over a
whole repository**, the weakest kind of evidence this package produces. Every
other rule points at a line and says what is there. This one says something is
*not* anywhere — and the testing might live in a separate repo, a notebook, a
data pipeline, or a vendor's report. Being wrong about that is cheap to do and
expensive to say.

So the claim is scoped to what was actually checked: "no bias or fairness test
was found in the scanned files", not "you do not test for bias".
"""
from __future__ import annotations

from .. import fingerprint
from ..models import CodeFinding, LegalReference
from .base import Rule, RuleContext

# Calls that train or fine-tune a model. `.fit(` is by far the most common and
# is also used by scalers and vectorisers, so the rule leans on the repo-level
# absence rather than on this list being exact.
# `fit_transform` is absent on purpose: it belongs to encoders, scalers and
# vectorisers far more often than to models. `le.fit_transform(...)` on a
# LabelEncoder was the only false positive this rule produced on a real repo.
_TRAINING_CALLS = (
    "fit", "train", "fine_tune", "finetune",
    "train_model", "trainer.train", "sft_trainer.train",
)

# Objects that `.fit()` belongs to without any model being trained. Matched on
# the receiver, so `scaler.fit(X)` is preprocessing while `model.fit(X, y)` is
# not.
_PREPROCESSORS = (
    "encoder", "scaler", "vectorizer", "vectoriser", "imputer", "normalizer",
    "normaliser", "tokenizer", "tokeniser", "binarizer", "discretizer",
    "transformer", "pca", "svd", "selector", "le", "ohe", "tfidf", "cv",
)

_TRAINING_MODULES = {
    "sklearn", "scikit-learn", "torch", "tensorflow", "keras", "transformers",
    "xgboost", "lightgbm", "catboost", "peft", "trl", "jax", "flax",
}

# Evidence that fairness is tested somewhere. Deliberately broad — the cost of
# missing it is a false accusation about a control that does exist.
_FAIRNESS_MARKERS = (
    "fairlearn", "aif360", "aequitas", "fairness", "bias", "disparate",
    "demographic_parity", "equalized_odds", "equal_opportunity",
    "disparity", "protected_attribute", "sensitive_attribute", "subgroup",
)


def _is_training_call(callee: str) -> bool:
    parts = callee.lower().rsplit(".", 1)
    tail = parts[-1]
    if tail not in _TRAINING_CALLS:
        return False
    receiver = parts[0] if len(parts) > 1 else ""
    return not any(name == receiver or name in receiver for name in _PREPROCESSORS)


class Article10DataGovernance(Rule):
    rule_id = "GA-ART10-001"
    severity = "medium"
    advisory = True
    title = "Model training with no fairness testing found in the repository"

    limitations = (
        "An absence claim over a repository — the weakest evidence this tool "
        "produces. Testing held in another repository, a notebook, a data pipeline or "
        "a supplier's report is invisible.",
        "It detects the presence of training code, not the quality or governance of "
        "the data, which is what Article 10 actually requires.",
        "Telling a model from a preprocessing step relies on naming conventions.",
    )

    @property
    def legal(self) -> LegalReference:
        return LegalReference(
            article="Article 10",
            paragraph="2",
            text=(
                "Training, validation and testing data sets shall be subject to data "
                "governance and management practices appropriate for the intended purpose "
                "of the high-risk AI system."
            ),
            source_url="https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32024R1689",
            text_verified=True,
            recital="Recitals 66–70",
            standard_ref="ISO/IEC 42001:2023 A.7.4",
            reviewed_by=None,
        )

    def analyze(self, ctx: RuleContext) -> list[CodeFinding]:
        # Whether the repository tests fairness anywhere is a repo-level fact,
        # so without the repo model this rule has nothing it can honestly say.
        if ctx.repo is None:
            return []
        if ctx.repo.fairness_tested:
            return []
        if not (_TRAINING_MODULES & ctx.imports):
            return []

        # Training scripts frequently have no functions at all — the whole file
        # runs top to bottom. `credit_scoring_project/train_models.py` calls
        # `model.fit(...)` at module level and was invisible until this.
        scopes: list[tuple[str, list]] = [
            (func.qualname, func.calls) for func in ctx.file.functions
        ]
        if ctx.file.module_calls:
            scopes.append(("<module>", ctx.file.module_calls))

        findings: list[CodeFinding] = []
        for symbol, calls in scopes:
            training = next(
                (call for call in calls if _is_training_call(call.callee)),
                None,
            )
            if training is None:
                continue

            findings.append(CodeFinding(
                rule_id=self.rule_id,
                fingerprint=fingerprint.compute(
                    rule_id=self.rule_id,
                    path=ctx.path,
                    qualname=symbol,
                    callee=training.callee,
                    occurrence=0,
                ),
                file=ctx.path,
                line=training.line,
                end_line=training.end_line,
                column=training.col,
                symbol=symbol,
                snippet=training.snippet,
                claim=(
                    f"`{training.callee}` trains a model inside `{symbol}`, and no "
                    f"bias or fairness test was found in the files scanned. Testing held "
                    f"in another repository, a notebook or a supplier's report would not "
                    f"be visible here."
                ),
                legal=self.legal,
                severity=self.severity,
                confidence="low",
                advisory=True,
                fix=None,
            ))
        return findings


def repo_tests_fairness(text: str) -> bool:
    """Does this file show any sign of fairness testing?"""
    lowered = text.lower()
    return any(marker in lowered for marker in _FAIRNESS_MARKERS)
