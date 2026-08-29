"""
services/reporting/report_generator.py

Generates the final InvestigationReport (ForensicReport).
Uses GroqAdapter to generate the narrative from evidence.
Enforces the requirement that every claim is backed by evidence IDs.
"""

import json
from typing import Optional

from app.contracts.investigation import InvestigationState
from app.contracts.report import InvestigationReport
from app.contracts.risk import RiskAssessment, ConfidenceAssessment
from app.contracts.evidence import EvidenceItem, EvidenceType
from app.contracts.groq import ReasoningInput, ReasoningOutput, EvidenceSnapshot
from app.services.ml.groq_adapter import GroqAdapter
from app.contracts.common import Recommendation
from pydantic import ValidationError

def should_use_reasoning(state: InvestigationState, ra: RiskAssessment, analyst_question: Optional[str] = None) -> bool:
    if state.budget_remaining.max_llm_tokens <= 0:
        return False
        
    if analyst_question:
        return True
    if state.active_conflicts:
        return True
    if len(state.attack_hypotheses) > 1:
        return True
    if state.historical_matches:
        return True
    
    # If INCONCLUSIVE but we have ML signals, maybe groq can summarize why.
    if ra.verdict == "INCONCLUSIVE" and state.ml_signals:
        return True

    # Otherwise, don't use Groq.
    return False

def _generate_fallback_explanation(state: InvestigationState, ra: RiskAssessment) -> str:
    parts = []
    if ra.verdict == "BENIGN":
        parts.append("Low risk because no suspicious indicators were found.")
    elif ra.verdict == "INCONCLUSIVE":
        stop = state.stop_reason.value if state.stop_reason else "UNKNOWN"
        parts.append(f"The available evidence indicates elevated risk, but the investigation did not obtain sufficient evidence to reach a high-confidence conclusion before the configured investigation budget was exhausted. Stop reason: {stop}.")
    else:
        parts.append(f"High risk because of several suspicious indicators.")
        if state.ml_signals:
            parts.append("ML classification flagged components as suspicious.")
        if state.threat_intelligence:
            parts.append("Threat intelligence identified malicious external infrastructure.")
        if state.active_conflicts:
            parts.append("There was conflicting evidence during investigation.")
            
    return " ".join(parts)

class ReportGenerator:
    def __init__(self, groq_adapter: Optional[GroqAdapter] = None):
        self.groq = groq_adapter or GroqAdapter()
        
    async def generate_report(
        self,
        state: InvestigationState,
        evidence_store: dict[str, EvidenceItem],
        risk_result: dict, # from risk_engine
        analyst_question: Optional[str] = None
    ) -> tuple[InvestigationReport, InvestigationState]:
        
        # Extract risk assessment
        if isinstance(risk_result, dict) and "risk_assessment" in risk_result:
            ra = risk_result["risk_assessment"]
        elif hasattr(risk_result, 'risk_assessment'):
            ra = risk_result.risk_assessment
        else:
            ra = RiskAssessment(
                case_id=state.case_id,
                risk_score=state.current_risk,
                verdict="INCONCLUSIVE",
                confidence=state.current_confidence,
                contributions=[],
                recommended_action=Recommendation.MONITOR,
                engine_version="1.0"
            )

        # Gather evidence IDs
        all_evidence_ids = (
            state.observed_facts + 
            state.heuristic_findings + 
            state.ml_signals + 
            state.threat_intelligence + 
            state.historical_matches
        )
        
        narrative = ""
        points = []

        if should_use_reasoning(state, ra, analyst_question):
            # Populate EvidenceSnapshot correctly
            facts_list = []
            heuristics_list = []
            ml_signals_list = []
            threat_intel_list = []
            historical_list = []
            inferences_list = []

            for eid in all_evidence_ids:
                if eid not in evidence_store:
                    continue
                item = evidence_store[eid]
                item_dict = item.model_dump(mode="json")
                if item.type == EvidenceType.FACT:
                    facts_list.append(item_dict)
                elif item.type == EvidenceType.HEURISTIC:
                    heuristics_list.append(item_dict)
                elif item.type == EvidenceType.ML_SIGNAL:
                    ml_signals_list.append(item_dict)
                elif item.type == EvidenceType.THREAT_INTEL:
                    threat_intel_list.append(item_dict)
                elif item.type == EvidenceType.HISTORICAL:
                    historical_list.append(item_dict)
                elif item.type == EvidenceType.INFERENCE:
                    inferences_list.append(item_dict)
                    
            snapshot_obj = EvidenceSnapshot(
                facts=facts_list,
                heuristics=heuristics_list,
                ml_signals=ml_signals_list,
                threat_intelligence=threat_intel_list,
                historical_evidence=historical_list,
                inferences=inferences_list,
                informational_risk_score=ra.risk_score,
                informational_confidence=ra.confidence,
                informational_verdict=ra.verdict,
                stop_reason=state.stop_reason.value if state.stop_reason else None
            )

            hypotheses = [h.model_dump(mode="json") for h in state.attack_hypotheses]
            
            snapshot_hash = snapshot_obj.compute_hash()

            # Ask Groq to synthesize the narrative
            req = ReasoningInput(
                case_id=state.case_id,
                task="generate_report_narrative" if not analyst_question else "answer_analyst_question",
                evidence_snapshot=snapshot_obj,
                hypotheses=hypotheses,
                unresolved_conflicts=state.active_conflicts,
                investigation_path=state.tools_used,
                analyst_question=analyst_question,
                policy_version="1.0",
                evidence_snapshot_hash=snapshot_hash
            )
            
            reasoning = await self.groq.analyze(req)
            
            # Extract tokens if present in response
            used_tokens = getattr(reasoning, "total_tokens", 0)
            if used_tokens > 0:
                new_cost = state.tool_cost_spent.model_copy(update={
                    "llm_tokens": state.tool_cost_spent.llm_tokens + used_tokens
                })
                new_rem = state.budget_remaining.model_copy(update={
                    "max_llm_tokens": max(0, state.budget_remaining.max_llm_tokens - used_tokens)
                })
                state = state.model_copy(update={"tool_cost_spent": new_cost, "budget_remaining": new_rem})
                
            # Enforce §25: validate referenced evidence
            from app.contracts.groq import validate_referenced_evidence
            try:
                validate_referenced_evidence(reasoning, all_evidence_ids)
                narrative = reasoning.summary + "\n\nKey Points:\n"
                for point in reasoning.reasoning_points:
                    narrative += f"- {point}\n"
                if analyst_question and reasoning.recommendation:
                    narrative += f"\nAnswer: {reasoning.recommendation}"
            except ValueError:
                narrative = "WARNING: LLM generated invalid evidence references. Narrative disabled.\nFallback: " + _generate_fallback_explanation(state, ra)
        else:
            narrative = "Deterministic Fallback: " + _generate_fallback_explanation(state, ra)
            
        report = InvestigationReport(
            case_id=state.case_id,
            risk_assessment=ra,
            attack_hypotheses=state.attack_hypotheses,
            evidence_ids=all_evidence_ids,
            investigation_path=state.tools_used,
            historical_matches=[], 
            correlation_links=[],
            intelligence_results=[],
            relay_path_reference=None,
            recommended_action=Recommendation.ESCALATE_TO_ANALYST if state.current_risk > 50 else Recommendation.MONITOR,
            narrative=narrative,
            audit_reference=f"audit_{state.case_id}"
        )
        return report, state
