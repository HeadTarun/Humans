"""
services/investigation/state_machine.py

Explicit deterministic state machine for investigation lifecycle transitions.

VALID TRANSITIONS (Stage 1 implements INITIALIZED → LEVEL_0 and all → STOPPED):

    INITIALIZED  → LEVEL_0    (always valid at init; Stage 1)
    LEVEL_0      → LEVEL_1    (Stage 2+; guarded here but not auto-executed)
    LEVEL_1      → LEVEL_2    (Stage 2+)
    LEVEL_2      → LEVEL_3    (Stage 5+; L3_GROQ disabled)
    LEVEL_*      → STOPPED    (any level can stop)
    STOPPED      → COMPLETED  (after stop, can transition to completed)

FORBIDDEN:
    Any jump that skips levels (e.g., INITIALIZED → LEVEL_2).
    Any transition from COMPLETED (terminal state).
    Any transition that omits stop_reason when targeting STOPPED.

IMMUTABILITY:
    State is frozen (BaseContract). All transitions return a new InvestigationState
    via model_copy(update={...}). The original state is never mutated.
"""

from __future__ import annotations

from app.contracts.investigation import (
    EscalationStatus,
    InvestigationLevel,
    InvestigationState,
    StateMachineStatus,
    StopReason,
)
from app.services.investigation.budget import calculate_budget_remaining

# ---------------------------------------------------------------------------
# Legal transition map (from → set of legal to states)
# ---------------------------------------------------------------------------

_LEGAL_TRANSITIONS: dict[StateMachineStatus, set[StateMachineStatus]] = {
    StateMachineStatus.INITIALIZED: {StateMachineStatus.LEVEL_0},
    StateMachineStatus.LEVEL_0: {StateMachineStatus.LEVEL_1, StateMachineStatus.STOPPED},
    StateMachineStatus.LEVEL_1: {StateMachineStatus.LEVEL_2, StateMachineStatus.STOPPED},
    StateMachineStatus.LEVEL_2: {StateMachineStatus.LEVEL_3, StateMachineStatus.STOPPED},
    StateMachineStatus.LEVEL_3: {StateMachineStatus.STOPPED},
    StateMachineStatus.STOPPED: {StateMachineStatus.COMPLETED},
    StateMachineStatus.COMPLETED: set(),  # terminal — no transitions allowed
}

# Map FSM status → InvestigationLevel
_STATUS_TO_LEVEL: dict[StateMachineStatus, InvestigationLevel] = {
    StateMachineStatus.LEVEL_0: InvestigationLevel.L0_TRIAGE,
    StateMachineStatus.LEVEL_1: InvestigationLevel.L1_TARGETED,
    StateMachineStatus.LEVEL_2: InvestigationLevel.L2_DEEP,
    StateMachineStatus.LEVEL_3: InvestigationLevel.L3_GROQ,
}


class InvalidTransitionError(Exception):
    """Raised when a state machine transition is illegal."""


def transition(
    state: InvestigationState,
    target_status: StateMachineStatus,
    *,
    stop_reason: StopReason | None = None,
    escalation_reason: str | None = None,
) -> InvestigationState:
    """
    Perform a validated state-machine transition.

    Parameters:
        state           : Current (immutable) InvestigationState.
        target_status   : The desired next StateMachineStatus.
        stop_reason     : Required when target_status == STOPPED.
        escalation_reason: Optional string when escalation is being recorded.

    Returns:
        A new InvestigationState with the updated sm_status, investigation_level,
        and budget_remaining recomputed from current spent values.

    Raises:
        InvalidTransitionError: If the transition is not in _LEGAL_TRANSITIONS.
        ValueError: If STOPPED is requested without a stop_reason.
    """
    current = state.sm_status
    allowed = _LEGAL_TRANSITIONS.get(current, set())

    if target_status not in allowed:
        raise InvalidTransitionError(
            f"Illegal FSM transition: {current} → {target_status}. "
            f"Allowed transitions from {current}: {sorted(s.value for s in allowed) or 'none (terminal)'}"
        )

    if target_status == StateMachineStatus.STOPPED and stop_reason is None:
        raise ValueError(
            "Transition to STOPPED requires stop_reason to be specified"
        )

    # Determine the new investigation level
    new_level = _STATUS_TO_LEVEL.get(target_status, state.investigation_level)

    # Recompute budget_remaining from current spend
    new_budget_remaining = calculate_budget_remaining(state)

    updates: dict = {
        "sm_status": target_status,
        "investigation_level": new_level,
        "budget_remaining": new_budget_remaining,
    }

    if stop_reason is not None:
        updates["stop_reason"] = stop_reason

    if escalation_reason is not None:
        updates["escalation_reason"] = escalation_reason
        updates["escalation_status"] = EscalationStatus.REQUESTED

    return state.model_copy(update=updates)


def initialize_to_level0(state: InvestigationState) -> InvestigationState:
    """
    Transition from INITIALIZED → LEVEL_0.

    This is the only Stage 1 auto-transition. It is called by the
    InvestigationDecisionEngine immediately after state initialization.
    """
    return transition(state, StateMachineStatus.LEVEL_0)


def stop_investigation(
    state: InvestigationState,
    stop_reason: StopReason,
    *,
    escalation_reason: str | None = None,
) -> InvestigationState:
    """
    Transition to STOPPED with the given reason.

    Can be called from any non-terminal, non-stopped state.
    """
    return transition(
        state,
        StateMachineStatus.STOPPED,
        stop_reason=stop_reason,
        escalation_reason=escalation_reason,
    )


def complete_investigation(state: InvestigationState) -> InvestigationState:
    """Transition STOPPED → COMPLETED."""
    return transition(state, StateMachineStatus.COMPLETED)
