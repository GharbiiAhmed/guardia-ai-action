"""Types for the code analysis layer.

Kept inside the package rather than in models/schemas.py so the analyzer is
self-contained: the GitHub Action vendors this directory and needs nothing
from the rest of the backend but pydantic. They are re-exported from
models.schemas so API code can keep importing them from the usual place.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field


CodeSeverity = Literal["critical", "high", "medium", "low", "info"]
FindingConfidence = Literal["high", "medium", "low"]


class LegalReference(BaseModel):
    """The legal half of a finding, deliberately kept apart from the code half.

    A finding never asserts "you are violating Article 50". It states a fact
    about the code (CodeFinding.claim) and quotes the obligation (text here);
    the inference between the two belongs to the reader. That is both more
    honest and far less exposed than issuing a verdict.
    """
    article: str
    paragraph: Optional[str] = None
    text: str                                # verbatim obligation
    source_url: str
    # False until the quote has been checked against the consolidated text on
    # EUR-Lex. Never ship a rule reading `True` that nobody actually checked.
    text_verified: bool = False
    recital: Optional[str] = None
    standard_ref: Optional[str] = None       # e.g. "ISO/IEC 42001:2023 A.6.2.6"
    regulation_version: str = "Regulation (EU) 2024/1689"
    # Stays empty until counsel signs off. Surfaced in the UI as-is: an honest
    # account of how much review each rule has actually had.
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[datetime] = None

    @property
    def citation(self) -> str:
        """'Article 12(1)', and 'Article 5(1)(f)' for a lettered subpoint.

        Built here rather than at each call site, which is how one rendering
        came out as 'Article 5(1(f))'.
        """
        if not self.paragraph:
            return self.article
        if "(" in self.paragraph:
            return f"{self.article}({self.paragraph.replace('(', ')(', 1)}"
        return f"{self.article}({self.paragraph})"


class SuggestedFix(BaseModel):
    """A concrete change, narrow enough to fit a GitHub review suggestion."""
    description: str
    start_line: int
    end_line: int
    replacement: str                         # replaces [start_line, end_line]
    confidence: FindingConfidence = "medium"


class CodeFinding(BaseModel):
    rule_id: str                             # 'GA-ART50-001'
    fingerprint: str                         # stable across reformatting
    file: str
    line: int
    end_line: int
    column: int = 0
    symbol: str                              # enclosing qualname
    snippet: str
    claim: str                               # what was observed in the code
    legal: LegalReference                    # what the law requires
    severity: CodeSeverity = "medium"
    confidence: FindingConfidence = "medium"
    fix: Optional[SuggestedFix] = None
    suppressed: bool = False
    suppression_reason: Optional[str] = None
    # Present when the baseline was taken. Distinct from `suppressed`: nobody
    # accepted this risk, it simply predates adoption of the scanner.
    baselined: bool = False
    # Rules resting on an interpretation rather than on explicit text never
    # gate CI, whatever their severity. Article 14 is the first of these.
    advisory: bool = False


class CodeScanResult(BaseModel):
    findings: list[CodeFinding] = Field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    # Tests, examples and docs — excluded by default, counted so the
    # exclusion is visible rather than silent.
    files_out_of_scope: int = 0
    rules_run: list[str] = Field(default_factory=list)
    suppressed_count: int = 0
    duration_ms: int = 0
    generated_at: datetime = Field(default_factory=datetime.utcnow)
