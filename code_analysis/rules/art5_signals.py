"""GA-ART5-001 — emotion inference reachable from a workplace or education path.

**This rule never decides anything.** Article 5 is a prohibition carrying the
Act's highest penalties, and whether a system infers emotions "in the areas of
workplace and education institutions" depends on who the subjects are, what the
deployer uses it for, and whether the medical-or-safety exception applies. None
of that is in a syntax tree, and a scanner that guessed would be both wrong and
dangerous — for the customer, who might act on it, and for us.

What it does instead is surface a coincidence worth a human's attention: a
library that infers emotions, imported in a file whose path or content points at
hiring or schooling. The finding is phrased as a question, never a verdict, and
it is advisory so it can never fail a build.
"""
from __future__ import annotations

from .. import fingerprint
from ..models import CodeFinding, LegalReference
from .base import Rule, RuleContext

# Libraries whose purpose is inferring affect or emotion from a person.
_EMOTION_LIBRARIES = {
    "fer", "deepface", "py-feat", "feat", "hume", "affectiva", "morphcast",
    "residual_masking_network", "emotion_recognition", "pyaudioanalysis",
    "opensmile", "speechbrain",
}

# Model or capability names that indicate the same thing without a named library.
_EMOTION_MARKERS = (
    "emotion", "affect_recognition", "facial_expression", "microexpression",
    "sentiment_from_face", "engagement_score", "attention_score",
    "stress_detection", "mood_detection",
)

# The FER-2013 label set, which almost every facial-emotion model emits. An HR
# interview bot loaded its classifier with `keras.load_model` and mapped the
# outputs through a dictionary of exactly these words — no named library
# anywhere, so detection by import saw nothing at all.
_EMOTION_LABELS = {
    "angry", "anger", "disgust", "disgusted", "fear", "fearful", "happy",
    "happiness", "sad", "sadness", "surprise", "surprised", "neutral",
    "contempt",
}

# Enough of the vocabulary to be the label set rather than a coincidence. Three
# is deliberate: "happy" and "sad" turn up in plenty of unrelated code, all
# seven together do not.
_LABEL_THRESHOLD = 3


# Labels alone are not inference. langchain ships a 700-word list for generating
# random names containing "happy", "sad" and "fear", next to nouns like
# "student" — enough to trip both signals while classifying nothing. Emotion
# inference needs something that runs a model over a face or a voice.
_MODEL_MODULES = {
    "cv2", "keras", "tensorflow", "tf", "torch", "torchvision", "mediapipe",
    "dlib", "onnxruntime", "PIL", "sklearn", "librosa", "moviepy",
}


def _infers_emotion_from_labels(strings, imports: set[str], callees) -> bool:
    """Does this file map the outputs of a model onto emotion labels?"""
    if not (_MODEL_MODULES & {name.split(".")[0] for name in imports}):
        return False
    if not any(
        callee.rsplit(".", 1)[-1] in {"predict", "predict_proba", "load_model", "forward"}
        for callee in callees
        if callee
    ):
        return False

    seen = {
        value.strip().lower()
        for value in strings
        if isinstance(value, str) and len(value) < 20
    }
    return len(seen & _EMOTION_LABELS) >= _LABEL_THRESHOLD

# Context suggesting the workplace or an education institution.
_WORKPLACE_MARKERS = (
    "employee", "employer", "workplace", "hiring", "recruit", "candidate",
    "applicant", "interview", "hr_", "/hr/", "staff", "worker", "onboarding",
    "performance_review", "appraisal",
)

_EDUCATION_MARKERS = (
    "student", "pupil", "school", "classroom", "exam", "proctor", "invigilat",
    "university", "lecture", "course_attendance", "learner", "teacher",
)


def _context_of(text: str) -> str | None:
    lowered = text.lower()
    if any(marker in lowered for marker in _WORKPLACE_MARKERS):
        return "the workplace"
    if any(marker in lowered for marker in _EDUCATION_MARKERS):
        return "an education setting"
    return None


class Article5EmotionSignal(Rule):
    rule_id = "GA-ART5-001"
    severity = "high"
    advisory = True
    title = "Emotion inference alongside workplace or education context — needs review"

    limitations = (
        "Emotion inference is recognised either by a named library or by a file "
        "mapping model outputs onto the standard emotion labels. A classifier "
        "using its own vocabulary is missed.",
        "This rule decides nothing. Whether Article 5(1)(f) applies depends on who the "
        "subjects are, what the deployer uses the system for, and whether the medical "
        "or safety exception applies — none of which is in the code.",
        "Context is inferred from file paths and identifiers, so a workplace system "
        "with neutral naming is missed and an unrelated one with suggestive naming is "
        "flagged.",
        "Only emotion inference under Article 5(1)(f) is covered. The other prohibited "
        "practices in Article 5 are not addressed at all.",
    )

    @property
    def legal(self) -> LegalReference:
        return LegalReference(
            article="Article 5",
            paragraph="1(f)",
            text=(
                "the placing on the market, the putting into service for this specific "
                "purpose, or the use of AI systems to infer emotions of a natural person "
                "in the areas of workplace and education institutions, except where the "
                "use of the AI system is intended to be put in place or into the market "
                "for medical or safety reasons"
            ),
            source_url="https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32024R1689",
            text_verified=True,
            recital="Recital 44",
            standard_ref=None,
            reviewed_by=None,
        )

    def analyze(self, ctx: RuleContext) -> list[CodeFinding]:
        library = next(
            (name for name in ctx.imports
             if name.lower() in _EMOTION_LIBRARIES
             or any(marker in name.lower() for marker in _EMOTION_MARKERS)),
            None,
        )
        if library is None and _infers_emotion_from_labels(
            ctx.file.user_strings,
            ctx.imports,
            tuple(call.callee for call in ctx.calls),
        ):
            library = "a facial emotion classifier"
        if library is None:
            return []

        # Context can come from the path or from the identifiers in the file.
        context = _context_of(ctx.path) or _context_of(ctx.source)
        if context is None:
            return []

        first = ctx.file.functions[0] if ctx.file.functions else None
        line = first.line if first else 1

        return [CodeFinding(
            rule_id=self.rule_id,
            fingerprint=fingerprint.compute(
                rule_id=self.rule_id,
                path=ctx.path,
                qualname=first.name if first else "<module>",
                callee=library,
                occurrence=0,
            ),
            file=ctx.path,
            line=line,
            end_line=line,
            column=0,
            symbol=first.qualname if first else "<module>",
            snippet="",
            claim=(
                f"{library} infers emotion, and this file references {context}. "
                f"Article 5(1)(f) prohibits emotion inference in workplaces and "
                f"education institutions outside medical or safety uses — whether that "
                f"applies here depends on who the subjects are and what the system is "
                f"for, which this scan cannot determine. Needs a human decision."
            ),
            legal=self.legal,
            severity=self.severity,
            confidence="low",
            advisory=True,
            fix=None,
        )]
