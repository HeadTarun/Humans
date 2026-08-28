"""
services/risk/confidence.py

Deterministic confidence calculation.

Risk and Confidence are separate (§21):
    risk      = HOW BAD (weighted evidence score)
    confidence = HOW SURE (evidence completeness + reliability + conflicts)

Example:
    risk = 85, confidence = 0.91  → High risk, strong evidence → MALICIOUS
    risk = 70, confidence = 0.35  → Potentially high risk, insufficient evidence
                                    → INCONCLUSIVE (not MALICIOUS)

The confidence formula is transparent and deterministic:

    confidence = completeness × avg_reliability × conflict_factor × failure_factor

Clamped to [0.0, 1.0].

DESIGN RULES:
    - No LLM. No ML. No external calls.
    - Every penalty is documented and auditable.
    - Tool failure reduces confidence — never increases it.
    - Unresolved HIGH conflicts reduce confidence more than MEDIUM.
    - Missing expected evidence reduces completeness.
"""

from __future__ import annotations

from app.contracts.evidence import EvidenceItem
from app.contracts.risk import ConfidenceAssessment

# ---------------------------------------------------------------------------
# Confidence parameters — single source of truth
# ---------------------------------------------------------------------------

# How many evidence items represent "good coverage" for a typical L0 pass.
# When fewer items are present, completeness is proportionally reduced.
# Stage 3+ will increase this as more evidence types become available.
_EXPECTED_L0_EVIDENCE_COUNT = 5

# Penalty per unresolved HIGH-severity conflict
_HIGH_CONFLICT_PENALTY = 0.15

# Penalty per unresolved MEDIUM-severity conflict
_MEDIUM_CONFLICT_PENALTY = 0.07

# Penalty per blocked/failed tool (applied in Stage 3+; currently always 0)
_TOOL_FAILURE_PENALTY_PER_TOOL = 0.10

# Minimum confidence floor (prevents division-by-zero and extreme results)
_CONFIDENCE_FLOOR = 0.0


def calculate_confidence(
    evidence_items: list[EvidenceItem],
    pending_conflicts: list[str],
    tools_failed_count: int = 0,
    expected_evidence_count: int = _EXPECTED_L0_EVIDENCE_COUNT,
    case_id: str = "",
) -> ConfidenceAssessment:
    """
    Compute a ConfidenceAssessment from all available evidence signals.

    Parameters
    ----------
    evidence_items : list[EvidenceItem]
        All evidence items collected for this investigation so far.
    pending_conflicts : list[str]
        Unresolved EvidenceConflict IDs from InvestigationState.
    tools_failed_count : int
        Number of tools that timed out / failed (Stage 3+; pass 0 for Stage 2).
    expected_evidence_count : int
        How many evidence items represent "full coverage" for this level.
    case_id : str
        Case identifier for the ConfidenceAssessment contract.

    Returns
    -------
    ConfidenceAssessment
        Fully populated with all sub-factors for auditability.
    """
    n_items = len(evidence_items)

    # ---- 1. Completeness: how much of expected evidence do we have? ----
    completeness = min(1.0, n_items / max(expected_evidence_count, 1))

    # ---- 2. Reliability: average confidence of evidence items ----
    if evidence_items:
        avg_reliability = sum(item.confidence for item in evidence_items) / n_items
    else:
        avg_reliability = 0.0

    # ---- 3. Conflict penalty: unresolved conflicts reduce confidence ----
    # For Stage 2, all pending_conflicts are treated as MEDIUM severity
    # (we don't have severity details without the full EvidenceConflict objects).
    # Stage 3+ will pass severity-aware conflict objects.
    conflict_penalty = min(
        0.80,  # Never reduce confidence by more than 80% from conflicts alone
        len(pending_conflicts) * _MEDIUM_CONFLICT_PENALTY,
    )
    conflict_factor = max(0.0, 1.0 - conflict_penalty)

    # ---- 4. Tool failure penalty ----
    failure_penalty = min(
        0.50,  # Never reduce confidence by more than 50% from failures alone
        tools_failed_count * _TOOL_FAILURE_PENALTY_PER_TOOL,
    )
    failure_factor = max(0.0, 1.0 - failure_penalty)

    # ---- 5. Final confidence ----
    raw_confidence = completeness * avg_reliability * conflict_factor * failure_factor
    final_confidence = max(_CONFIDENCE_FLOOR, min(1.0, raw_confidence))

    return ConfidenceAssessment(
        case_id=case_id,
        confidence_score=round(final_confidence, 4),
        evidence_completeness=round(completeness, 4),
        calibration_quality=round(avg_reliability, 4),
        evidence_reliability=round(avg_reliability, 4),
        unresolved_conflicts_penalty=round(conflict_penalty, 4),
        tool_failure_penalty=round(failure_penalty, 4),
        contributing_evidence_ids=[item.evidence_id for item in evidence_items],
    )
