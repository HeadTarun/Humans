"""
services/investigation/result_factory.py

Converts Stage1Result (internal dataclass) → InvestigationResult (API contract).

This module is the ONLY place where:
    - InvestigationStatus is assigned
    - InvestigationResult is constructed

SECURITY INVARIANTS enforced here (and also in InvestigationResult validators):

    1. Resource-stop investigations must have status=INCONCLUSIVE.
    2. Resource-stop investigations must NOT have verdict=BENIGN.
    3. Stop reason is required for all non-COMPLETED results.
    4. All evidence collected before stopping is preserved.

DESIGN:
    The factory is a pure function — same inputs always produce same output.
    It has no side effects, no external calls, no LLM.

    It calls the Risk Engine once (deterministically) to produce the final
    risk assessment before packaging the result.
"""

from __future__ import annotations

from app.contracts.common import utcnow
from app.contracts.investigation import (
    InvestigationLevel,
    InvestigationStatus,
    StopReason,
    StateMachineStatus,
)
from app.contracts.result import RESOURCE_STOP_REASONS, InvestigationResult
from app.contracts.risk import Verdict
from app.services.investigation.decision_engine import Stage1Result
from app.services.investigation.state_machine import complete_investigation
from app.services.risk.engine import RiskEngine

# Reusable engine instance — stateless, safe to share
_risk_engine = RiskEngine()


def _determine_investigation_status(
    stop_reason: StopReason | None,
    verdict: Verdict,
    sm_status: StateMachineStatus,
) -> InvestigationStatus:
    """
    Map stop_reason + verdict → InvestigationStatus.

    Rules:
        - No stop_reason and sm_status=COMPLETED → COMPLETED
        - Resource stop → INCONCLUSIVE
        - Semantic stop (confidence target reached, etc.) with definitive
          verdict → COMPLETED
        - Semantic stop with INCONCLUSIVE verdict → INCONCLUSIVE
    """
    if stop_reason is None:
        # Normal completion (no stop fired)
        if verdict == Verdict.INCONCLUSIVE:
            return InvestigationStatus.INCONCLUSIVE
        return InvestigationStatus.COMPLETED

    if stop_reason in RESOURCE_STOP_REASONS:
        # Resource exhaustion — never COMPLETED
        return InvestigationStatus.INCONCLUSIVE

    # Semantic stop (evidence-based)
    if verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS, Verdict.BENIGN):
        return InvestigationStatus.COMPLETED

    return InvestigationStatus.INCONCLUSIVE


def to_investigation_result(stage1: Stage1Result) -> InvestigationResult:
    """
    Convert a Stage1Result into a fully-formed InvestigationResult.

    This is the sole bridge between the internal investigation machinery
    and the public-facing API contract.

    Parameters
    ----------
    stage1 : Stage1Result
        Output of InvestigationDecisionEngine.run_stage1().

    Returns
    -------
    InvestigationResult
        Fully-formed, serializable Pydantic BaseContract ready for the API.
    """
    state = stage1.state
    stop_reason = stage1.stop_decision.stop_reason if stage1.stop_decision else None

    # ----------------------------------------------------------------
    # 1. Run Risk Engine on all collected evidence
    # ----------------------------------------------------------------
    engine_result = _risk_engine.assess(
        state=state,
        evidence_items=stage1.l0_facts,  # Stage 2: L0 facts only
        stop_reason=stop_reason,
        tools_failed_count=0,  # Stage 3+: will pass actual count
    )

    risk_score = engine_result.risk_assessment.risk_score
    confidence = engine_result.confidence_assessment.confidence_score
    verdict = engine_result.verdict

    # ----------------------------------------------------------------
    # 2. Determine investigation status
    # ----------------------------------------------------------------
    status = _determine_investigation_status(
        stop_reason=stop_reason,
        verdict=verdict,
        sm_status=state.sm_status,
    )

    # ----------------------------------------------------------------
    # 2b. Resolve stop_reason for contract validation.
    #
    # The contract requires stop_reason when status != COMPLETED.
    # If the investigation FSM completed normally (no stop fired) but
    # the Risk Engine produced INCONCLUSIVE verdict (due to low confidence),
    # we assign NO_MANDATORY_EVIDENCE_MISSING — this accurately describes
    # the situation: we ran out of sufficient evidence to be confident.
    #
    # This is NOT a resource exhaustion stop — it is a semantic observation
    # that the available evidence was insufficient for a definitive verdict.
    # ----------------------------------------------------------------
    if status == InvestigationStatus.INCONCLUSIVE and stop_reason is None:
        from app.contracts.investigation import StopReason as _SR
        stop_reason = _SR.NO_MANDATORY_EVIDENCE_MISSING

    # If status is COMPLETED, stop_reason may be omitted (it's optional)
    # For resource-stop INCONCLUSIVE, stop_reason is already set above.

    # ----------------------------------------------------------------
    # 3. Build unresolved questions (from Risk Engine + state)
    # ----------------------------------------------------------------
    unresolved_questions = engine_result.risk_assessment.unresolved_questions

    # ----------------------------------------------------------------
    # 4. Audit trail — last hash from the audit logger
    # ----------------------------------------------------------------
    audit_last_hash = stage1.audit_logger.last_hash

    # ----------------------------------------------------------------
    # 5. Construct InvestigationResult
    #    (model_validators enforce security invariants)
    # ----------------------------------------------------------------
    return InvestigationResult(
        investigation_id=state.case_id,
        created_at=state.created_at,
        completed_at=utcnow(),

        # Outcome
        status=status,
        stop_reason=stop_reason,
        investigation_level_reached=state.investigation_level,

        # Risk
        verdict=verdict,
        risk_score=risk_score,
        confidence=confidence,
        risk_reasons=engine_result.risk_assessment.reasons,
        unresolved_questions=unresolved_questions,

        # Evidence (IDs — preserving everything collected before stop)
        observed_facts=list(state.observed_facts),
        heuristic_findings=list(state.heuristic_findings),
        ml_signals=list(state.ml_signals),
        threat_intelligence=list(state.threat_intelligence),
        historical_matches=list(state.historical_matches),

        # Hypotheses
        attack_hypotheses=list(state.attack_hypotheses),

        # Budget transparency
        budget=state.budget,
        budget_spent=state.tool_cost_spent,
        budget_remaining=state.budget_remaining,

        # Evidence gaps
        missing_evidence=list(state.missing_evidence),
        pending_conflicts=list(state.pending_conflicts),

        # Investigation metadata
        tools_used=list(state.tools_used),
        iteration_count=state.iteration_count,

        # Audit
        audit_chain_last_hash=audit_last_hash,
    )
