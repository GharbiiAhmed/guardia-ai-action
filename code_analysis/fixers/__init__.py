"""Codemods that produce a concrete diff for a finding.

Every fixer here is deterministic. No model is involved: a compliance tool that
guesses at a patch is worse than one that offers none, and a wrong fix merged
under a compliance banner is the most expensive mistake this product can make.

Fixers are also allowed — expected — to decline. Returning None when the code
shape is not one we can transform safely is the normal case, not a failure.
"""
from .art50 import build_disclosure_fix
from .art50_js import build_disclosure_fix as build_js_disclosure_fix

__all__ = ["build_disclosure_fix", "build_js_disclosure_fix"]
