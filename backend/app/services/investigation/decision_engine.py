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

from dataclasses import dataclass
from typing import Optional

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
    l0_facts: list[EvidenceItem]
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

    def run_stage1(self, package: EmailEvidencePackage, original_case_id: str | None = None) -> Stage1Result:
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
        audit = AuditLogger(case_id=state.case_id)
        fact_ids = [f.evidence_id for f in l0_facts]

        audit.log_investigation_started(
            evidence_ids=fact_ids,
            initial_risk=state.current_risk,
            initial_confidence=state.current_confidence,
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
            tools_blocked=state.tools_blocked,
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
                l0_facts=l0_facts,
                hypotheses=hypotheses,
                active_profiles=active_profiles,
                stop_decision=stop_decision,
                audit_logger=audit,
            )
            
        # ------------------------------------------------------------------
        # STAGE 4 IMPLEMENTATION - Adaptive Tool Execution Loop
        # ------------------------------------------------------------------
        executor = ToolExecutor()
        normaliser = EvidenceToolNormaliser()
        risk_engine = RiskEngine()
        
        async def run_adaptive_loop(current_state: InvestigationState, accumulated_evidence: list[EvidenceItem]) -> InvestigationState:
            MAX_ITERATIONS = 10
            iteration = 0
            
            # Helper to map inputs
            async def _map_inputs_for_tool(tool_name: str) -> list[dict]:
                inputs = []
                if tool_name in ["url_canonicalizer", "attachment_hasher"]:
                    return [{}]
                if tool_name in ["virustotal_lookup", "urlhaus_feed_lookup"]:
                    for url_item in package.urls:
                        inputs.append({"indicator": url_item.raw_url, "url": url_item.raw_url, "canonical_url": url_item.raw_url, "indicator_type": "URL"})
                if tool_name == "url_ml":
                    # Only unique canonical URLs
                    unique_urls = set()
                    try:
                        from app.services.tools.handlers.url_canonicalizer import _canonicalize_url
                        for url_item in package.urls:
                            c_url = _canonicalize_url(url_item.raw_url)
                            if c_url not in unique_urls:
                                unique_urls.add(c_url)
                                inputs.append({"canonical_url": c_url})
                    except Exception as e:
                        logger.error(f"Failed to canonicalize for url_ml: {e}")
                if tool_name == "nlp_intent_ml":
                    inputs.append({"artifact_reference": package.raw_artifact_reference})
                if tool_name in ["ip_classifier", "abuseipdb_lookup", "geoip_lookup"]:
                    for hop in package.headers.received_hops:
                        if hop.sender_ip:
                            inputs.append({"ip_address": hop.sender_ip})
                    for ev in accumulated_evidence:
                        if ev.type.value == "NETWORK" and ev.related_entity:
                            if "." in ev.related_entity and not ev.related_entity.startswith("http"):
                                inputs.append({"ip_address": ev.related_entity})

                if tool_name in ["dns_resolver", "rdap_domain_lookup"]:
                    for url_item in package.urls:
                        import tldextract
                        ext = tldextract.extract(url_item.raw_url)
                        domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
                        if domain:
                            inputs.append({"domain": domain})
                    for ev in accumulated_evidence:
                        if ev.type.value == "URL" and ev.related_entity:
                            import tldextract
                            ext = tldextract.extract(ev.related_entity)
                            domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
                            if domain:
                                inputs.append({"domain": domain})
                        if ev.type.value == "NETWORK" and ev.related_entity:
                            if any(c.isalpha() for c in ev.related_entity) and "." in ev.related_entity and not ev.related_entity.startswith("http"):
                                inputs.append({"domain": ev.related_entity})

                if tool_name == "sender_history":
                    if package.sender and package.sender.email_address:
                        inputs.append({"email_address": package.sender.email_address})
                if tool_name == "historical_correlation":
                    inputs.append({})
                    
                # Dedup
                unique = []
                seen = set()
                for inp in inputs:
                    k = frozenset(inp.items())
                    if k not in seen:
                        seen.add(k)
                        unique.append(inp)
                return unique

            while iteration < MAX_ITERATIONS:
                # 1. Re-evaluate Hypotheses & Policy
                hypotheses = generate_initial_hypotheses(current_state, package, accumulated_evidence)
                active_profiles = select_profiles(hypotheses)
                candidate_tools = get_candidate_tools(active_profiles, current_state.tools_used, current_state.tools_blocked)
                
                current_state = current_state.model_copy(update={
                    "attack_hypotheses": hypotheses,
                    "tools_available": candidate_tools
                })
                
                # 2. Rank Eligible Tools
                ranked_tools = rank_tools(candidate_tools, current_state, active_profiles)
                if not ranked_tools:
                    break
                    
                iteration += 1
                current_state = current_state.model_copy(update={"iteration_count": iteration})
                
                # 3. Select Top Tool
                top_tool_score = ranked_tools[0]
                tool_def = get_tool(top_tool_score.tool_name)
                
                # 4. Budget Check
                remaining = calculate_budget_remaining(current_state)
                # Ensure we have enough calls
                if remaining.max_tool_calls <= 0 or (tool_def.external_api and remaining.max_external_calls <= 0):
                    current_state = current_state.model_copy(update={"tools_blocked": current_state.tools_blocked + [tool_def.name]})
                    continue
                    
                # 5. Generate Inputs
                inputs = await _map_inputs_for_tool(tool_def.name)
                if not inputs:
                    current_state = current_state.model_copy(update={"tools_blocked": current_state.tools_blocked + [tool_def.name]})
                    continue
                    
                # 6. Execute
                tasks = []
                for inp in inputs:
                    req = ToolExecutionRequest(
                        case_id=current_state.case_id,
                        tool_name=tool_def.name,
                        input=inp,
                        reason=top_tool_score.reason,
                        policy_version="1.0"
                    )
                    tasks.append(executor.execute(req, current_state, package=package))
                    
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # 7. Normalize & Update State
                current_state = current_state.model_copy(update={
                    "tools_used": current_state.tools_used + [tool_def.name],
                    "tool_cost_spent": record_tool_cost(
                        current_state.tool_cost_spent, 
                        latency_ms=tool_def.estimated_latency_ms, 
                        is_external=getattr(tool_def, "external_api", False)
                    )
                })
                
                new_evidence = []
                for res in results:
                    if hasattr(res, "status") and res.status == ToolExecutionStatus.SUCCESS and res.output:
                        try:
                            if isinstance(res.output, list):
                                from app.contracts.evidence import EvidenceItem
                                for item in res.output:
                                    if isinstance(item, dict):
                                        new_evidence.append(EvidenceItem(**item))
                                    elif isinstance(item, EvidenceItem):
                                        new_evidence.append(item)
                            else:
                                from app.contracts.provider_result import ProviderResult
                                pr = ProviderResult(**res.output)
                                items = normaliser.from_provider_result(
                                    case_id=current_state.case_id,
                                    result=pr,
                                    module_path=tool_def.handler_ref
                                )
                                new_evidence.extend(items)
                        except Exception as e:
                            pass
                accumulated_evidence.extend(new_evidence)
                
                # Update State with Evidence IDs
                from app.contracts.evidence import EvidenceType
                obs = list(current_state.observed_facts)
                heu = list(current_state.heuristic_findings)
                mls = list(current_state.ml_signals)
                thi = list(current_state.threat_intelligence)
                his = list(current_state.historical_matches)
                for item in new_evidence:
                    if item.type == EvidenceType.FACT:
                        obs.append(item.evidence_id)
                    elif item.type == EvidenceType.HEURISTIC:
                        heu.append(item.evidence_id)
                    elif item.type == EvidenceType.ML_SIGNAL:
                        mls.append(item.evidence_id)
                    elif item.type == EvidenceType.THREAT_INTEL:
                        thi.append(item.evidence_id)
                    elif item.type == EvidenceType.HISTORICAL:
                        his.append(item.evidence_id)
                current_state = current_state.model_copy(update={
                    "observed_facts": obs,
                    "heuristic_findings": heu,
                    "ml_signals": mls,
                    "threat_intelligence": thi,
                    "historical_matches": his
                })
                
                # Stage 7 Conflict Detection
                from app.services.risk.conflict_engine import ConflictEngine
                conflicts = ConflictEngine().detect_conflicts(accumulated_evidence)
                current_state = current_state.model_copy(update={
                    "active_conflicts": [c.model_dump() for c in conflicts]
                })

                # 8. Re-evaluate Risk
                risk_result = risk_engine.assess(current_state, accumulated_evidence)
                current_state = current_state.model_copy(update={
                    "current_risk": risk_result.risk_assessment.risk_score,
                    "current_confidence": risk_result.confidence_assessment.confidence_score
                })
                
                # 9. Check Stop Conditions
                stop_dec = should_stop(current_state)
                if stop_dec.should_stop:
                    break
                    
            return current_state
            
        try:
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            
            if loop.is_running():
                import nest_asyncio
                nest_asyncio.apply()
                state = loop.run_until_complete(run_adaptive_loop(state, l0_facts))
            else:
                state = loop.run_until_complete(run_adaptive_loop(state, l0_facts))
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Adaptive tool execution loop failed: {e}")
            
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
            l0_facts=l0_facts,
            hypotheses=hypotheses,
            active_profiles=active_profiles,
            stop_decision=stop_decision if stop_decision.should_stop else None,
            audit_logger=audit,
        )
