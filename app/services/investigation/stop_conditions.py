"""
services/investigation/stop_conditions.py

Deterministic structural stop conditions for Stage 1.

DESIGN RULES:
    - Every stop condition is independently testable.
    - Every stop produces a specific StopReason — no silent stops.
    - The order of evaluation is deterministic and documented.
    - No LLM, no external calls, no random numbers.
    - Risk-based stop conditions belong to Stage 2 (Risk Engine).
      Stage 1 only implements structural/budget stops.

IMPORTANT SEMANTIC RULE:
    "budget exhausted with insufficient confidence" ≠ "benign"
    The investigation ends INCONCLUSIVE, not clean. The verdict
    remains for the Risk Engine (Stage 2+) to assign.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from app.contracts.investigation import (
    InvestigationState,
    StateMachineStatus,
    StopReason,
)
from app.services.investigation.budget import (
    calculate_budget_remaining,
    is_external_call_exhausted,
    is_latency_exhausted,
    is_tool_call_exhausted,
)


@dataclass(frozen=True)
class StopDecision:
    """
    Result of a stop-condition evaluation.

    Attributes:
        should_stop    : True if the investigation must halt.
        stop_reason    : Populated when should_stop=True. Identifies the exact reason.
        explanation    : Human-readable detail (deterministic, not LLM-generated).
    """

    should_stop: bool
    stop_reason: Optional[StopReason] = None
    explanation: str = ""

    def __post_init__(self) -> None:
        if self.should_stop and self.stop_reason is None:
            raise ValueError("StopDecision.should_stop=True requires stop_reason to be set")


# ---------------------------------------------------------------------------
# Individual stop-condition evaluators
# (each returns a StopDecision; compose them in should_stop())
# ---------------------------------------------------------------------------


def _check_max_iterations(state: InvestigationState) -> Optional[StopDecision]:
    if state.iteration_count >= state.max_iterations:
        return StopDecision(
            should_stop=True,
            stop_reason=StopReason.MAX_ITERATIONS_REACHED,
            explanation=(
                f"iteration_count ({state.iteration_count}) reached "
                f"max_iterations ({state.max_iterations})"
            ),
        )
    return None


def _check_tool_call_budget(state: InvestigationState) -> Optional[StopDecision]:
    if is_tool_call_exhausted(state):
        remaining = calculate_budget_remaining(state)
        return StopDecision(
            should_stop=True,
            stop_reason=StopReason.BUDGET_EXHAUSTED,
            explanation=(
                f"tool_calls budget exhausted: "
                f"spent={state.tool_cost_spent.tool_calls} / "
                f"max={state.budget.max_tool_calls} "
                f"(remaining={remaining.max_tool_calls})"
            ),
        )
    return None


def _check_latency_budget(state: InvestigationState) -> Optional[StopDecision]:
    if is_latency_exhausted(state):
        remaining = calculate_budget_remaining(state)
        return StopDecision(
            should_stop=True,
            stop_reason=StopReason.LATENCY_BUDGET_EXHAUSTED,
            explanation=(
                f"latency budget exhausted: "
                f"spent={state.tool_cost_spent.latency_ms}ms / "
                f"max={state.budget.max_latency_ms}ms "
                f"(remaining={remaining.max_latency_ms}ms)"
            ),
        )
    return None


def _check_external_call_budget(state: InvestigationState) -> Optional[StopDecision]:
    if is_external_call_exhausted(state):
        remaining = calculate_budget_remaining(state)
        return StopDecision(
            should_stop=True,
            stop_reason=StopReason.EXTERNAL_CALL_BUDGET_EXHAUSTED,
            explanation=(
                f"external_calls budget exhausted: "
                f"spent={state.tool_cost_spent.external_calls} / "
                f"max={state.budget.max_external_calls} "
                f"(remaining={remaining.max_external_calls})"
            ),
        )
    return None


def _check_no_candidate_tools(state: InvestigationState) -> Optional[StopDecision]:
    """
    Stop if there are no available tools left and none have been scheduled.

    An empty list at evaluation time means either all tools were consumed or
    none were applicable given the current investigation profiles.
    """
    # Only trigger this check after at least one iteration has occurred,
    # otherwise initialization hasn't finished populating tools_available yet.
    if state.iteration_count > 0 and not state.tools_available:
        return StopDecision(
            should_stop=True,
            stop_reason=StopReason.NO_CANDIDATE_TOOLS,
            explanation=(
                f"no candidate tools remain after {state.iteration_count} iteration(s); "
                f"tools_used={state.tools_used}, tools_blocked={state.tools_blocked}"
            ),
        )
    return None


def _check_confidence_target(state: InvestigationState) -> Optional[StopDecision]:
    from app.services.risk.sufficiency import EvidenceSufficiencyEvaluator, SufficiencyResult
    
    has_useful_tools = bool(state.tools_available)
    # Check if budget is exhausted based on tool limits
    from app.services.investigation.budget import calculate_budget_remaining
    rem = calculate_budget_remaining(state)
    budget_exhausted = (rem.max_tool_calls <= 0) or (rem.max_latency_ms <= 0)
    
    evaluator = EvidenceSufficiencyEvaluator()
    res = evaluator.evaluate(state, has_useful_tools, budget_exhausted)
    
    if res == SufficiencyResult.SUFFICIENT:
        return StopDecision(
            should_stop=True,
            stop_reason=StopReason.CONFIDENCE_TARGET_REACHED,
            explanation=f"Sufficiency Evaluator determined SUFFICIENT evidence (conf={state.current_confidence:.2f})"
        )
    return None

# ---------------------------------------------------------------------------
# Evaluation order — document explicitly for auditability
# ---------------------------------------------------------------------------

_STOP_EVALUATORS = [
    # 1. Risk-based stop (If we have enough evidence, stop normally even if out of budget)
    _check_confidence_target,
    # 2. Hard resource limits
    _check_max_iterations,
    _check_tool_call_budget,
    _check_latency_budget,
    _check_external_call_budget,
    # 3. Logical stops (require at least one iteration to be meaningful)
    _check_no_candidate_tools,
]

def should_stop(state: InvestigationState) -> StopDecision:
    """
    Evaluate all structural stop conditions in deterministic order.

    Returns the FIRST triggered StopDecision, or StopDecision(should_stop=False)
    if no condition fires.

    Stage 1 only implements structural/budget stops.
    Risk-based stops (confidence target, evidence completeness) are Stage 2.

    IMPORTANT: A stop here does NOT mean the investigation is BENIGN.
    It means the current iteration budget is exhausted or structurally
    impossible to continue. The verdict remains INCONCLUSIVE until the
    Risk Engine (Stage 2+) makes a determination.
    """
    # Already stopped — do not re-evaluate; return a consistent result
    if state.sm_status == StateMachineStatus.STOPPED:
        return StopDecision(
            should_stop=True,
            stop_reason=state.stop_reason,
            explanation="Investigation is already in STOPPED state",
        )

    for evaluator in _STOP_EVALUATORS:
        result = evaluator(state)
        if result is not None:
            return result

    return StopDecision(should_stop=False, explanation="No stop condition triggered")
