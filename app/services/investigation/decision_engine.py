"""
services/investigation/decision_engine.py

InvestigationDecisionEngine — Stage 1 implementation.

Orchestrates the Stage 1 deterministic investigation lifecycle:

    1. Initialize state from EmailEvidencePackage (via case_manager)
    2. Log investigation start (audit trail)
    3. Transition to LEVEL_0 (via state_machine)
    4. Generate initial hypotheses (via case_manager, using hypothesis_rules)
    5. Select active investigation profiles (via policy, using RELEVANCE_FLOOR)
    6. Populate tools_available from selected profiles
    7. Evaluate stop conditions (via stop_conditions)
    8. Return the final Stage 1 state

HARD RULES:
    - No LLM is called.
    - No external API calls.
    - No tool execution (Stage 1 only establishes the foundation).
    - No arbitrary tool names from email content.
    - All state transitions go through state_machine.transition().
    - All audit records go through AuditLogger.
    - The engine cannot modify evidence — it only references evidence IDs.

Stage 2 will extend this engine with actual tool execution (Level 0 tools).
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

from app.contracts.evidence import EvidenceItem
from app.contracts.investigation import (
    AttackHypothesis,
    InvestigationState,
    StateMachineStatus,
    StopReason,
)
from app.contracts.policy import InvestigationProfile
from app.services.evidence import EmailEvidencePackage
from app.services.investigation.audit_logger import AuditLogger
from app.services.investigation.case_manager import (
    generate_initial_hypotheses,
    init_state,
)
from app.services.investigation.policy import (
    RELEVANCE_FLOOR,
    get_candidate_tools,
    select_profiles,
)
from app.services.investigation.state_machine import (
    initialize_to_level0,
    stop_investigation,
)
from app.services.investigation.stop_conditions import StopDecision, should_stop

# Stage 4 imports
import asyncio
from app.services.tools.executor import ToolExecutor
from app.services.tools.normaliser import EvidenceToolNormaliser
from app.services.investigation.budget import calculate_budget_remaining, record_tool_cost
from app.services.investigation.tool_priority import rank_tools
from app.services.risk.engine import RiskEngine
from app.contracts.tool import ToolExecutionRequest, ToolExecutionStatus
from app.contracts.investigation import InvestigationLevel
from app.services.investigation.tool_registry import get_tool

@dataclass
class Stage1Result:
    """
    Output of the Stage 1 investigation pass.

    Attributes:
        state          : Final InvestigationState after Stage 1.
        l0_facts       : EvidenceItems extracted from the evidence package.
        hypotheses     : Initial hypotheses produced by Level 0 rules.
        active_profiles: Investigation profiles selected by the relevance gate.
        stop_decision  : Stop condition that terminated Stage 1, or None if
                         Stage 1 completed normally and is ready for Stage 2.
        audit_logger   : The audit trail for this investigation (append to it in Stage 2).
    """

    state: InvestigationState
    package: EmailEvidencePackage
    l0_facts: list[EvidenceItem]
    all_evidence: list[EvidenceItem]
    hypotheses: list[AttackHypothesis]
    active_profiles: list[InvestigationProfile]
    stop_decision: Optional[StopDecision]
    audit_logger: AuditLogger


class InvestigationDecisionEngine:
    """
    Stage 1 Investigation Decision Engine.

    Responsibilities (Stage 1):
        - Consume EmailEvidencePackage
        - Initialize InvestigationState
        - Generate deterministic Level-0 hypotheses
        - Select active investigation profiles
        - Transition FSM to LEVEL_0
        - Evaluate structural stop conditions
        - Produce a Stage1Result

    NOT responsible for (Stage 2+):
        - Executing tools
        - Calling external APIs
        - Groq reasoning
        - ML model inference
        - Updating risk/confidence scores
    """

    async def run_stage1(
        self,
        package: EmailEvidencePackage,
        original_case_id: str | None = None,
        started_at: float | None = None,
    ) -> Stage1Result:
        """
        Execute the complete Stage 1 investigation pass.

        This is the top-level entry point for Stage 1.
        It is deterministic: the same input always produces the same output.

        Parameters:
            package: Validated EmailEvidencePackage from the evidence normalizer.
            original_case_id: Used during re-investigations to trace back to original case.

        Returns:
            Stage1Result containing the final state, facts, hypotheses,
            profiles, stop decision, and audit logger.
        """
        # ------------------------------------------------------------------
        # 1. Initialize state
        # ------------------------------------------------------------------
        state, l0_facts = init_state(package, original_case_id=original_case_id)
        # Charge parse/normalization time supplied by the API entry point.
        # It is pipeline latency, not a tool execution, so do not increment
        # the tool-call budget.
        if started_at is not None:
            elapsed_ms = int((time.perf_counter() - started_at) * 1000)
            state = state.model_copy(update={
                "tool_cost_spent": state.tool_cost_spent.model_copy(update={"latency_ms": elapsed_ms}),
            })
            state = state.model_copy(update={"budget_remaining": calculate_budget_remaining(state)})
        audit = AuditLogger(case_id=state.case_id)
        fact_ids = [f.evidence_id for f in l0_facts]

        audit.log_investigation_started(
            evidence_ids=fact_ids,
            initial_risk=state.current_risk,
            initial_confidence=state.current_confidence,
        )

        # ------------------------------------------------------------------
        # 1b. Fast Historical Lookup — runs BEFORE hypothesis generation
        #     so historical signals can influence hypothesis scores.
        #     Gracefully no-ops if DB is unavailable.
        # ------------------------------------------------------------------
        try:
            from app.repositories.db import SessionLocal
            from app.repositories.historical_repository import HistoricalRepository
            from app.services.investigation.historical_lookup import FastHistoricalLookup
            # DB is initialized at startup via lifespan() — no per-request init needed.
            with SessionLocal() as _session:
                _hist_repo = HistoricalRepository(_session)
                _hist_facts = FastHistoricalLookup(_hist_repo).perform_lookup(package)
                l0_facts.extend(_hist_facts)
                fact_ids = [f.evidence_id for f in l0_facts]
        except Exception as _hist_exc:  # noqa: BLE001
            # Historical lookup is best-effort: DB unavailable ≠ no historical matches.
            # Log at WARNING (not ERROR) so operators can detect persistent failures
            # without alarming on transient connectivity issues.
            # IMPORTANT: log the exception TYPE only — never exc_info=True here
            # because the exception message may contain DB connection strings.
            logger.warning(
                "Historical lookup non-fatal failure (investigation continues): %s",
                type(_hist_exc).__name__,
            )

        # ------------------------------------------------------------------
        # 2. Transition INITIALIZED → LEVEL_0
        # ------------------------------------------------------------------
        state = initialize_to_level0(state)
        audit.log_transition(
            from_status=StateMachineStatus.INITIALIZED.value,
            to_status=StateMachineStatus.LEVEL_0.value,
            reason_code="STAGE1_LEVEL0_ENTRY",
            evidence_ids=fact_ids,
            risk_before=None,
            risk_after=state.current_risk,
        )

        # ------------------------------------------------------------------
        # 3. Generate Level-0 hypotheses
        # ------------------------------------------------------------------
        hypotheses = generate_initial_hypotheses(state, package)

        # Attach hypotheses to state (immutable update)
        state = state.model_copy(update={"attack_hypotheses": hypotheses})

        # ------------------------------------------------------------------
        # 4. Select active profiles via relevance gate (RELEVANCE_FLOOR=0.15)
        # ------------------------------------------------------------------
        active_profiles = select_profiles(hypotheses)

        # ------------------------------------------------------------------
        # 5. Populate tools_available from active profiles
        # ------------------------------------------------------------------
        candidate_tools = get_candidate_tools(
            profiles=active_profiles,
            tools_used=state.tools_used,
            tools_blocked=state.tools_blocked, current_level=state.investigation_level,
        )
        state = state.model_copy(update={"tools_available": candidate_tools})

        # ------------------------------------------------------------------
        # 6. Evaluate stop conditions (structural only in Stage 1)
        # ------------------------------------------------------------------
        stop_decision = should_stop(state)

        if stop_decision.should_stop:
            state = stop_investigation(
                state,
                stop_reason=stop_decision.stop_reason,  # type: ignore[arg-type]
            )
            audit.log_stop(
                stop_reason=stop_decision.stop_reason.value,  # type: ignore[union-attr]
                risk_before=state.current_risk,
                confidence_before=state.current_confidence,
                evidence_ids=fact_ids,
            )
            return Stage1Result(
                state=state,
                package=package,
                l0_facts=l0_facts,
                all_evidence=l0_facts,
                hypotheses=hypotheses,
                active_profiles=active_profiles,
                stop_decision=stop_decision,
                audit_logger=audit,
            )
            
        # ------------------------------------------------------------------
        # STAGE 4 IMPLEMENTATION - Adaptive Tool Execution Loop
        # ------------------------------------------------------------------
        from app.services.investigation.adaptive_loop import run_adaptive_loop
        
        state, all_evidence, post_stop_decision = await run_adaptive_loop(
            initial_state=state,
            package=package,
            initial_evidence=l0_facts,
            audit=audit
        )
        
        # ------------------------------------------------------------------
        # 6. Evaluate stop conditions again post-tools
        # ------------------------------------------------------------------
        stop_decision = should_stop(state)

        if stop_decision.should_stop:
            state = stop_investigation(
                state,
                stop_reason=stop_decision.stop_reason,  # type: ignore[arg-type]
            )
            audit.log_stop(
                stop_reason=stop_decision.stop_reason.value,  # type: ignore[union-attr]
                risk_before=state.current_risk,
                confidence_before=state.current_confidence,
                evidence_ids=fact_ids,
            )
        else:
            from app.contracts.investigation import StopReason as _SR
            from app.services.investigation.state_machine import complete_investigation
            state = stop_investigation(
                state,
                stop_reason=_SR.CONFIDENCE_TARGET_REACHED,
            )
            state = complete_investigation(state)
            audit.log_transition(
                from_status=StateMachineStatus.LEVEL_0.value,
                to_status=StateMachineStatus.COMPLETED.value,
                reason_code="STAGE4_COMPLETED_NORMALLY",
                evidence_ids=fact_ids,
                risk_before=state.current_risk,
                risk_after=state.current_risk,
            )

        return Stage1Result(
            state=state,
            package=package,
            l0_facts=l0_facts,
            all_evidence=all_evidence if 'all_evidence' in locals() else l0_facts,
            hypotheses=hypotheses,
            active_profiles=active_profiles,
            stop_decision=stop_decision if stop_decision.should_stop else None,
            audit_logger=audit,
        )
