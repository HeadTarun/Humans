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
    active_conflicts: list[dict] = None,
    pending_conflicts: list[str] = None,
    tools_failed_count: int = 0,
    expected_evidence_count: int = _EXPECTED_L0_EVIDENCE_COUNT,
    case_id: str = "",
) -> ConfidenceAssessment:
    if active_conflicts is None:
        active_conflicts = []
    if pending_conflicts is None:
        pending_conflicts = []

    n_items = len(evidence_items)
    completeness = min(1.0, n_items / max(expected_evidence_count, 1))

    if evidence_items:
        avg_reliability = sum(item.confidence for item in evidence_items) / n_items
    else:
        avg_reliability = 0.0

    # ---- 3. Conflict penalty: unresolved conflicts reduce confidence ----
    conflict_penalty = 0.0
    for conflict_dict in active_conflicts:
        sev = conflict_dict.get("severity", "MEDIUM")
        status = conflict_dict.get("status", "OPEN")
        if status == "OPEN":
            if sev == "HIGH":
                conflict_penalty += _HIGH_CONFLICT_PENALTY
            elif sev == "MEDIUM":
                conflict_penalty += _MEDIUM_CONFLICT_PENALTY
            elif sev == "LOW":
                conflict_penalty += 0.03
                
    # Fallback to len(pending_conflicts) if no active_conflicts passed
    if not active_conflicts and pending_conflicts:
        conflict_penalty += len(pending_conflicts) * _MEDIUM_CONFLICT_PENALTY

    conflict_penalty = min(0.80, conflict_penalty)
    conflict_factor = max(0.0, 1.0 - conflict_penalty)


    # ---- 4. Tool failure penalty ----
    failure_penalty = min(
        0.50,  # Never reduce confidence by more than 50% from failures alone
        tools_failed_count * _TOOL_FAILURE_PENALTY_PER_TOOL,
    )
    failure_factor = max(0.0, 1.0 - failure_penalty)

    # ---- 5. Historical Cap (Part 14) ----
    has_historical = any(e.key == "historical_exact_match" for e in evidence_items)
    has_strong_current = any(e.key != "historical_exact_match" and e.confidence >= 0.8 for e in evidence_items)
    
    historical_cap = 1.0
    if has_historical and not has_strong_current:
        # If the only strong evidence is historical, cap confidence to 0.70
        historical_cap = 0.70

    # ---- 6. Final confidence ----
    raw_confidence = completeness * avg_reliability * conflict_factor * failure_factor
    final_confidence = max(_CONFIDENCE_FLOOR, min(historical_cap, raw_confidence))

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
