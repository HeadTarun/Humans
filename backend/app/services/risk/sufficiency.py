from enum import Enum
from app.contracts.investigation import InvestigationState

class SufficiencyResult(str, Enum):
    SUFFICIENT = "SUFFICIENT"
    INSUFFICIENT = "INSUFFICIENT"
    INCONCLUSIVE = "INCONCLUSIVE"
    CONFLICTED = "CONFLICTED"

class EvidenceSufficiencyEvaluator:
    def evaluate(self, state: InvestigationState, has_useful_tools: bool, budget_exhausted: bool) -> SufficiencyResult:
        # Check conflicts
        has_high_conflict = any(c.get("severity") == "HIGH" and c.get("status") == "OPEN" for c in getattr(state, "active_conflicts", []))
        
        if has_high_conflict:
            return SufficiencyResult.CONFLICTED
            
        # Is confidence sufficient?
        confidence = state.current_confidence
        risk = state.current_risk
        
        # If very low risk and decent confidence -> sufficient benign
        if risk < 20 and confidence >= 0.6:
            return SufficiencyResult.SUFFICIENT
            
        # If very high risk and decent confidence -> sufficient malicious
        if risk >= 80 and confidence >= 0.7:
            return SufficiencyResult.SUFFICIENT
            
        if confidence >= 0.75:
            return SufficiencyResult.SUFFICIENT
            
        # Budget exhausted + insufficient -> Inconclusive
        if budget_exhausted:
            return SufficiencyResult.INCONCLUSIVE
            
        # No more useful tools -> Inconclusive
        if not has_useful_tools:
            return SufficiencyResult.INCONCLUSIVE
            
        return SufficiencyResult.INSUFFICIENT
