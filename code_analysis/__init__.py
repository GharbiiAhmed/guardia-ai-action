"""Layer 1 — compliance evidence derived from source code.

Turns "the customer ticked a box saying they log inference events" into "no
logging call exists in the scope of this inference call, at this line, on this
commit". Everything downstream — remediation, the audit trail, Annex IV — gets
better inputs as a result.
"""
from .analyzer import analyze_source, analyze_workspace

__all__ = ["analyze_source", "analyze_workspace"]
