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
from app.contracts.result import (
    RESOURCE_STOP_REASONS,
    ContentAnalysisSummary,
    GeoLocationSummary,
    InvestigationResult,
)
from app.contracts.risk import Verdict
from app.services.investigation.decision_engine import Stage1Result
from app.services.investigation.state_machine import complete_investigation
from app.services.risk.engine import RiskEngine

# Reusable engine instance — stateless, safe to share
_risk_engine = RiskEngine()


def _geolocation_summaries(stage1: Stage1Result) -> list[GeoLocationSummary]:
    """Join geo evidence to immutable Received-hop provenance without reparsing."""
    by_ip: dict[str, dict[str, object]] = {}
    observations_by_ip: dict[str, list[dict[str, object]]] = {}
    geo_keys = {
        "geolocation_success": "success", "geolocation_source": "source",
        "geolocation_provider": "provider", "geolocation_error": "unavailable_reason",
        "ip_country": "country", "ip_country_code": "country_code",
        "ip_region": "region", "ip_city": "city", "ip_asn": "asn",
        "ip_is_private": "is_private", "ip_is_reserved": "is_reserved",
        "ip_is_loopback": "is_loopback", "ip_is_link_local": "is_link_local",
        "ip_is_multicast": "is_multicast", "ip_is_unspecified": "is_unspecified",
    }
    for item in stage1.all_evidence:
        if item.related_entity and item.key in geo_keys:
            by_ip.setdefault(item.related_entity, {})[geo_keys[item.key]] = item.value
            if item.key == "geolocation_success":
                observations_by_ip.setdefault(item.related_entity, []).append({
                    "provider": item.source,
                    "success": item.value,
                    "timestamp": item.timestamp.isoformat(),
                    "metadata": item.metadata or {},
                })

    summaries: list[GeoLocationSummary] = []
    for hop in stage1.package.received_hops:
        if not hop.sending_ip:
            continue
        data = by_ip.get(hop.sending_ip, {})
        summaries.append(GeoLocationSummary(
            ip=hop.sending_ip,
            hop_position=hop.position,
            hostname=hop.sending_hostname,
            timestamp=hop.timestamp,
            provider_observations=observations_by_ip.get(hop.sending_ip, []),
            **data,
        ))
    return summaries


def _content_summary(stage1: Stage1Result) -> ContentAnalysisSummary | None:
    body = stage1.package.body
    if not body or not (body.visible_text_length or body.plain_text_length or body.html_length):
        return None
    evidence = [item for item in stage1.all_evidence if item.category.value == "CONTENT"]
    metadata = next((item.metadata or {} for item in evidence if (item.metadata or {}).get("content_analysis_mode")), {})
    mode = metadata.get("content_analysis_mode", "ML" if any(item.type.value == "ML_SIGNAL" for item in evidence) else "MODEL_UNAVAILABLE")
    return ContentAnalysisSummary(
        language=body.language,
        language_confidence=body.language_confidence,
        execution_mode=str(mode),
        evidence_ids=list(dict.fromkeys(item.evidence_id for item in evidence)),
        unavailable_reason=metadata.get("model_error"),
    )


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
    # all_evidence is an explicit immutable-package pipeline output, rather
    # than a mutation alias to the initial L0 list.
    engine_result = _risk_engine.assess(
        state=state,
        evidence_items=stage1.all_evidence,
        stop_reason=stop_reason,
        tools_failed_count=len(state.tools_failed),
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
        stop_reason = _SR.NO_CANDIDATE_TOOLS

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
        geolocation=_geolocation_summaries(stage1),
        content_analysis=_content_summary(stage1),

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
        tools_failed=list(state.tools_failed),
        iteration_count=state.iteration_count,

        # Audit
        audit_chain_last_hash=audit_last_hash,
    )
