"""Three more Article 5 prohibitions, as signals for a human to weigh.

Everything in this module follows the same rule as GA-ART5-001: it decides
nothing. Article 5 carries the Act's highest penalty tier, and every one of
these prohibitions turns on purpose, subjects and context — none of which is in
a syntax tree. A scanner that announced a prohibited practice would be wrong
often and expensively.

What it can do is notice a coincidence a person should look at: a face
recognition library next to a web scraper, a biometric pipeline next to
protected characteristics, an aggregate score over people compared across
unrelated domains. Each finding names what it saw and asks.
"""
from __future__ import annotations

from .. import fingerprint
from ..models import CodeFinding, LegalReference
from .base import Rule, RuleContext

_SOURCE = "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32024R1689"

# Libraries whose purpose is recognising or comparing faces.
_FACE_LIBRARIES = {
    "face_recognition", "facenet", "facenet_pytorch", "insightface", "deepface",
    "dlib", "mtcnn", "retinaface", "arcface", "openface", "cvlib",
}

# Fetching images from the open web at volume.
_SCRAPING_MARKERS = (
    "scrape", "scraper", "crawl", "spider", "bulk_download", "harvest",
    "beautifulsoup", "bs4", "selenium", "playwright", "requests_html",
)

# The characteristics Article 5(1)(g) names, plus the words code tends to use.
_PROTECTED_MARKERS = (
    "race", "ethnicity", "ethnic", "skin_tone", "skintone",
    "political", "trade_union", "union_membership",
    "religion", "religious", "belief",
    "sexual_orientation", "sexuality", "sex_life", "gender_identity",
)

# Aggregating people into a single figure that follows them around.
# Predicting who will offend, from who they are.
_OFFENCE_MARKERS = (
    "recidivism", "reoffend", "re_offend", "crime_risk", "criminal_risk",
    "offender_score", "predictive_polic", "crime_predict", "arrest_predict",
    "propensity_to_offend", "criminal_propensity",
)

# Identifying people from biometrics as they pass a camera.
_LIVE_BIOMETRIC_MARKERS = (
    "cctv", "surveillance", "live_feed", "realtime_face", "real_time_face",
    "video_stream", "rtsp", "camera_feed", "public_space", "crowd_scan",
)

_SCORE_MARKERS = (
    "social_score", "citizen_score", "trust_score", "reputation_score",
    "behaviour_score", "behavior_score", "risk_score", "conduct_score",
    "compliance_score",
)


def _mentions(ctx: RuleContext, markers) -> str | None:
    """The first marker this file mentions, in code or in a string."""
    haystack = (ctx.path + "\n" + ctx.code_text).lower()
    return next((m for m in markers if m in haystack), None)


def _uses_faces(ctx: RuleContext) -> str | None:
    roots = {name.split(".")[0].lower() for name in ctx.imports}
    named = next((lib for lib in _FACE_LIBRARIES if lib in roots), None)
    if named:
        return named
    lowered = (ctx.path + "\n" + ctx.code_text).lower()
    if "face_encodings" in lowered or "face_landmarks" in lowered or "facenet" in lowered:
        return "a face recognition pipeline"
    return None


class _Article5Signal(Rule):
    """Shared shape: two coincident signals, and a question rather than a verdict."""

    advisory = True
    severity = "high"
    paragraph = ""
    quote = ""
    recital = ""

    @property
    def legal(self) -> LegalReference:
        return LegalReference(
            article="Article 5",
            paragraph=self.paragraph,
            text=self.quote,
            source_url=_SOURCE,
            text_verified=True,
            recital=self.recital,
            standard_ref=None,
            reviewed_by=None,
        )

    def _finding(self, ctx: RuleContext, callee: str, claim: str) -> CodeFinding:
        first = ctx.file.functions[0] if ctx.file.functions else None
        line = first.line if first else 1
        return CodeFinding(
            rule_id=self.rule_id,
            fingerprint=fingerprint.compute(
                rule_id=self.rule_id, path=ctx.path,
                qualname=first.name if first else "<module>",
                callee=callee, occurrence=0,
            ),
            file=ctx.path,
            line=line,
            end_line=line,
            column=0,
            symbol=first.qualname if first else "<module>",
            snippet="",
            claim=claim,
            legal=self.legal,
            severity=self.severity,
            confidence="low",
            advisory=True,
            fix=None,
        )


class Article5FacialScraping(_Article5Signal):
    rule_id = "GA-ART5-002"
    title = "Face recognition alongside web scraping — needs review"
    paragraph = "1(e)"
    recital = "Recital 43"
    quote = (
        "the placing on the market, the putting into service for this specific "
        "purpose, or the use of AI systems that create or expand facial recognition "
        "databases through the untargeted scraping of facial images from the "
        "internet or CCTV footage"
    )
    limitations = (
        "Scraping and face recognition in one repository is a coincidence, not a "
        "finding. Whether images are collected untargeted, and whether a database "
        "is being built from them, is not visible in code.",
        "A pipeline assembled across several repositories is missed entirely.",
    )

    def analyze(self, ctx: RuleContext) -> list[CodeFinding]:
        faces = _uses_faces(ctx)
        scraping = _mentions(ctx, _SCRAPING_MARKERS)
        if not (faces and scraping):
            return []
        return [self._finding(
            ctx, faces,
            f"This file uses {faces} and also references `{scraping}`. Article "
            f"5(1)(e) prohibits building or expanding facial recognition databases "
            f"by untargeted scraping of facial images — whether that is what these "
            f"two things are doing together depends on where the images come from "
            f"and what is kept, which this scan cannot determine. Needs a human "
            f"decision.",
        )]


class Article5BiometricCategorisation(_Article5Signal):
    rule_id = "GA-ART5-003"
    title = "Biometric processing alongside protected characteristics — needs review"
    paragraph = "1(g)"
    recital = "Recital 30"
    quote = (
        "the placing on the market, the putting into service for this specific "
        "purpose, or the use of biometric categorisation systems that categorise "
        "individually natural persons based on their biometric data to deduce or "
        "infer their race, political opinions, trade union membership, religious or "
        "philosophical beliefs, sex life or sexual orientation; this prohibition "
        "does not cover any labelling or filtering of lawfully acquired biometric "
        "datasets, such as images, based on biometric data or categorizing of "
        "biometric data in the area of law enforcement"
    )
    limitations = (
        "The prohibition is about inferring a characteristic from biometric data. "
        "A file that mentions both may be measuring fairness across those groups, "
        "which is the opposite of the concern.",
        "The carve-out for lawfully acquired datasets and law enforcement cannot "
        "be evaluated from code.",
    )

    def analyze(self, ctx: RuleContext) -> list[CodeFinding]:
        faces = _uses_faces(ctx)
        protected = _mentions(ctx, _PROTECTED_MARKERS)
        if not (faces and protected):
            return []
        return [self._finding(
            ctx, faces,
            f"This file uses {faces} and also references `{protected}`. Article "
            f"5(1)(g) prohibits inferring characteristics such as this one from a "
            f"person's biometric data — whether that is happening here, or whether "
            f"the two are unrelated or part of fairness testing, this scan cannot "
            f"determine. Needs a human decision.",
        )]


class Article5SocialScoring(_Article5Signal):
    rule_id = "GA-ART5-004"
    title = "An aggregate score over people — needs review"
    paragraph = "1(c)"
    recital = "Recital 31"
    quote = (
        "the placing on the market, the putting into service or the use of AI "
        "systems for the evaluation or classification of natural persons or groups "
        "of persons over a certain period of time based on their social behaviour "
        "or known, inferred or predicted personal or personality characteristics, "
        "with the social score leading to either or both of the following: "
        "(i) detrimental or unfavourable treatment of certain natural persons or "
        "groups of persons in social contexts that are unrelated to the contexts in "
        "which the data was originally generated or collected; (ii) detrimental or "
        "unfavourable treatment of certain natural persons or groups of persons "
        "that is unjustified or disproportionate to their social behaviour or its "
        "gravity"
    )
    limitations = (
        "A score over people is not prohibited. The prohibition turns on the score "
        "being used against them in an unrelated context, or disproportionately — "
        "neither of which is in the code. Credit scoring in its own context is "
        "high-risk under Annex III, not prohibited.",
        "Named by convention: a score computed under a different name is missed.",
    )

    def analyze(self, ctx: RuleContext) -> list[CodeFinding]:
        score = _mentions(ctx, _SCORE_MARKERS)
        if not score:
            return []
        if not ctx.ml_context and not ctx.uses_provider:
            # A column named `risk_score` in a schema is not an AI system.
            return []
        return [self._finding(
            ctx, score,
            f"This file computes `{score}` over people using a model. Article "
            f"5(1)(c) prohibits scoring people on social behaviour or personal "
            f"characteristics where the score is then used against them in an "
            f"unrelated context or disproportionately — whether either applies "
            f"depends on how the score is used, which this scan cannot determine. "
            f"Scoring within its own context is high-risk under Annex III rather "
            f"than prohibited. Needs a human decision.",
        )]


class Article5PredictivePolicing(_Article5Signal):
    rule_id = "GA-ART5-005"
    title = "Predicting criminal offending from profiling — needs review"
    paragraph = "1(d)"
    recital = "Recital 42"
    quote = (
        "the placing on the market, the putting into service for this specific "
        "purpose, or the use of an AI system for making risk assessments of natural "
        "persons in order to assess or predict the risk of a natural person "
        "committing a criminal offence, based solely on the profiling of a natural "
        "person or on assessing their personality traits and characteristics; this "
        "prohibition shall not apply to AI systems used to support the human "
        "assessment of the involvement of a person in a criminal activity, which is "
        "already based on objective and verifiable facts directly linked to a "
        "criminal activity"
    )
    limitations = (
        "The prohibition turns on the prediction being based *solely* on profiling "
        "or personality traits. A model using objective facts linked to a specific "
        "criminal activity is expressly outside it, and which of the two this is "
        "cannot be read from a call site.",
        "Detection is by naming convention: a model predicting offending under "
        "another name is missed.",
    )

    def analyze(self, ctx: RuleContext) -> list[CodeFinding]:
        marker = _mentions(ctx, _OFFENCE_MARKERS)
        if not marker:
            return []
        if not ctx.ml_context and not ctx.uses_provider:
            return []
        return [self._finding(
            ctx, marker,
            f"This file references `{marker}` and runs a model over people. "
            f"Article 5(1)(d) prohibits predicting whether someone will commit a "
            f"criminal offence where that rests solely on profiling or personality "
            f"traits, and expressly permits systems supporting a human assessment "
            f"grounded in objective facts about a specific criminal activity. "
            f"Which of those this is cannot be read from the code. Needs a human "
            f"decision.",
        )]


class Article5LiveBiometricId(_Article5Signal):
    rule_id = "GA-ART5-006"
    title = "Live biometric identification in a public space — needs review"
    paragraph = "1(h)"
    recital = "Recitals 32-37"
    quote = (
        "the use of 'real-time' remote biometric identification systems in publicly "
        "accessible spaces for the purposes of law enforcement, unless and in so far "
        "as such use is strictly necessary for one of the following objectives: "
        "(i) the targeted search for specific victims of abduction, trafficking in "
        "human beings or sexual exploitation of human beings, as well as the search "
        "for missing persons; (ii) the prevention of a specific, substantial and "
        "imminent threat to the life or physical safety of natural persons or a "
        "genuine and present or genuine and foreseeable threat of a terrorist "
        "attack; (iii) the localisation or identification of a person suspected of "
        "having committed a criminal offence, for the purpose of conducting a "
        "criminal investigation or prosecution or executing a criminal penalty for "
        "offences referred to in Annex II and punishable in the Member State "
        "concerned by a custodial sentence or a detention order for a maximum "
        "period of at least four years."
    )
    limitations = (
        "This prohibition applies to law enforcement use in publicly accessible "
        "spaces, with three exceptions and a judicial authorisation regime. None of "
        "that is visible in code - a building's own access control uses the same "
        "libraries and is not covered at all.",
        "The word 'real-time' is doing heavy lifting in the text and cannot be "
        "distinguished from batch processing at a call site.",
    )

    def analyze(self, ctx: RuleContext) -> list[CodeFinding]:
        faces = _uses_faces(ctx)
        live = _mentions(ctx, _LIVE_BIOMETRIC_MARKERS)
        if not (faces and live):
            return []
        return [self._finding(
            ctx, faces,
            f"This file uses {faces} and also references `{live}`. Article 5(1)(h) "
            f"restricts real-time remote biometric identification in publicly "
            f"accessible spaces for law enforcement, subject to three narrow "
            f"exceptions and prior authorisation. Whether this is law enforcement, "
            f"whether the space is publicly accessible and whether it is real-time "
            f"are all outside what this scan can see - access control on your own "
            f"premises uses the same libraries and is not covered. Needs a human "
            f"decision.",
        )]
