"""
services/risk/verdict.py

Deterministic verdict assignment from risk_score + confidence.

DESIGN RULES:
    - Verdict is derived ONLY from risk_score and confidence.
    - No LLM. No ML. No external calls.
    - All thresholds are configuration constants with a single source of truth.
    - Low confidence → INCONCLUSIVE regardless of risk score.
    - INCONCLUSIVE does NOT mean BENIGN. It means "insufficient evidence."
    - Budget exhaustion / resource stops must NOT produce BENIGN.

VERDICT MATRIX:

    risk_score ≥ 75 AND confidence ≥ 0.60  → MALICIOUS
    risk_score ≥ 40 AND confidence ≥ 0.50  → SUSPICIOUS
    risk_score <  40 AND confidence ≥ 0.60  → BENIGN
    confidence <  MIN_CONFIDENCE_FOR_VERDICT → INCONCLUSIVE

Priority order (evaluated top-to-bottom):
    1. If confidence < MIN_CONFIDENCE_FOR_VERDICT → INCONCLUSIVE
    2. If risk_score ≥ MALICIOUS_RISK_THRESHOLD   → MALICIOUS
    3. If risk_score ≥ SUSPICIOUS_RISK_THRESHOLD  → SUSPICIOUS
    4. Otherwise (low risk + sufficient confidence) → BENIGN

NOTE on INCONCLUSIVE:
    INCONCLUSIVE means: "We could not establish sufficient confidence in
    the evidence to reach a verdict." It is used when:
      - Evidence is too sparse (low completeness)
      - Too many unresolved conflicts
      - Investigation stopped early (budget/iterations/no-tools)
      - Tool failures left significant evidence gaps

    It does NOT mean the email is safe. Treat as SUSPICIOUS for operational
    response unless further investigation is possible.
"""

from __future__ import annotations

from app.contracts.risk import Verdict

# ---------------------------------------------------------------------------
# Verdict thresholds — single source of truth
# ---------------------------------------------------------------------------

# Minimum confidence required to assign any definitive verdict.
# Below this, the verdict is INCONCLUSIVE regardless of risk.
MIN_CONFIDENCE_FOR_VERDICT: float = 0.35

# Risk score thresholds (scale: 0–100)
MALICIOUS_RISK_THRESHOLD: float = 75.0
SUSPICIOUS_RISK_THRESHOLD: float = 40.0
# Anything below SUSPICIOUS_RISK_THRESHOLD with sufficient confidence → BENIGN


def assign_verdict(risk_score: float, confidence: float) -> Verdict:
    """
    Assign a Verdict from risk_score and confidence.

    Parameters
    ----------
    risk_score : float
        0–100 score from the Risk Engine scoring module.
    confidence : float
        0–1 confidence score from the confidence module.

    Returns
    -------
    Verdict
        One of MALICIOUS / SUSPICIOUS / BENIGN / INCONCLUSIVE.
    """
    # Priority 1: insufficient confidence → always INCONCLUSIVE
    if confidence < MIN_CONFIDENCE_FOR_VERDICT:
        return Verdict.INCONCLUSIVE

    # Priority 2: high risk + sufficient confidence → MALICIOUS
    if risk_score >= MALICIOUS_RISK_THRESHOLD:
        return Verdict.MALICIOUS

    # Priority 3: medium risk + sufficient confidence → SUSPICIOUS
    if risk_score >= SUSPICIOUS_RISK_THRESHOLD:
        return Verdict.SUSPICIOUS

    # Priority 4: low risk + sufficient confidence → BENIGN
    return Verdict.BENIGN


def is_resource_stop(stop_reason) -> bool:
    """
    Return True if the stop reason represents resource exhaustion
    rather than a semantic completion (e.g. confidence target reached).

    Used by the result factory to enforce the security invariant that
    resource stops cannot produce Verdict.BENIGN.
    """
    from app.contracts.result import RESOURCE_STOP_REASONS
    return stop_reason in RESOURCE_STOP_REASONS


def assign_verdict_with_stop_guard(
    risk_score: float,
    confidence: float,
    stop_reason=None,
) -> Verdict:
    """
    Assign verdict while enforcing the resource-stop security invariant.

    If the investigation stopped due to a resource limit AND the normal
    verdict assignment would produce BENIGN, override to INCONCLUSIVE.

    This prevents the following dangerous equivalence:
        "ran out of time to investigate" == "email is safe"

    Parameters
    ----------
    risk_score : float
    confidence : float
    stop_reason : Optional[StopReason]
        If provided, the stop reason is used to enforce the invariant.

    Returns
    -------
    Verdict
    """
    verdict = assign_verdict(risk_score, confidence)

    if stop_reason is not None and is_resource_stop(stop_reason):
        if verdict == Verdict.BENIGN:
            # Override: we didn't finish investigating — cannot say "safe"
            return Verdict.INCONCLUSIVE

    return verdict
