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

        # A tool that was attempted and failed represents a real evidence
        # gap (§15: "Tool failure does not mean CLEAN", §17: "a final
        # benign/malicious decision must be supported by sufficient
        # evidence"). Previously this evaluator only looked at the
        # risk/confidence *numbers* and never consulted
        # state.tools_failed/missing_evidence, so a failed tool (e.g. url_ml
        # failing on every URL in the email) could still be waved through as
        # SUFFICIENT purely because unrelated evidence happened to produce a
        # low-risk, high-confidence score. Concretely: an email with 19
        # unanalyzed URLs where url_ml failed on all of them was reaching a
        # confident BENIGN verdict via this shortcut. When there is an
        # unresolved tool failure, skip the risk/confidence shortcuts below
        # and fall through to the budget/tools-remaining logic instead --
        # that already correctly resolves to INCONCLUSIVE (no more useful
        # tools) or INSUFFICIENT (keep investigating), never to a shortcut
        # SUFFICIENT that a failure alone shouldn't be able to produce.
        has_unresolved_tool_failure = bool(getattr(state, "tools_failed", None))

        # Level-0 IOC enrichment is mandatory before a confidence shortcut is
        # allowed.  The adaptive loop marks a tool blocked when the email has
        # no matching IOC, so this only waits for lookups that can actually
        # contribute evidence.  In particular, URL/IP reputation must be
        # considered before calling an otherwise clean-looking message safe.
        level0_intelligence_tools = {
            "domain_intelligence",
            "rdap_domain_lookup",
            "url_reputation",
            "geoip_lookup",
            "ip_intelligence",
        }
        attempted = set(state.tools_used) | set(state.tools_failed) | set(state.tools_blocked)
        pending_intelligence = (
            level0_intelligence_tools.intersection(state.tools_available) - attempted
        )
        if pending_intelligence:
            return SufficiencyResult.INSUFFICIENT

        # 17: Hypothesis awareness
        from app.contracts.investigation import HypothesisStatus
        has_unsupported_hypothesis = False
        for hyp in state.attack_hypotheses:
            if (hyp.status == HypothesisStatus.SUPPORTED or hyp.investigation_triggered) and not hyp.supporting_evidence_ids:
                has_unsupported_hypothesis = True
                break
        
        if has_unsupported_hypothesis:
            has_unresolved_tool_failure = True

        if not has_unresolved_tool_failure:
            # A middling risk or sub-75% confidence is ambiguous. Continue
            # spending the usable investigation budget instead of stopping
            # after a partial result, so downstream threat intelligence can
            # materially affect the verdict.
            ambiguous = 20 <= risk < 80 or confidence < 0.75
            if ambiguous and has_useful_tools and not budget_exhausted:
                return SufficiencyResult.INSUFFICIENT

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
