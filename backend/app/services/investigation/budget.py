"""
services/investigation/budget.py

Budget tracking and remaining-budget calculation.

DESIGN RULES:
    - All calculations are deterministic.
    - Remaining budget must NEVER be negative (enforced by clamp).
    - The default budget is a configuration constant with a single source of truth.
    - Budget checks are used by stop_conditions.py.
    - No external calls, no LLM.
"""

from __future__ import annotations

from app.contracts.investigation import (
    InvestigationBudget,
    InvestigationState,
    ToolCostSpent,
)
from app.core.config import settings

# ---------------------------------------------------------------------------
# Default budget — single source of truth
# ---------------------------------------------------------------------------

DEFAULT_BUDGET = InvestigationBudget(
    max_latency_ms=4000,
    max_tool_calls=8,
    max_external_calls=4,
    max_llm_tokens=settings.MAX_LLM_TOKENS,
)


def make_full_budget_remaining(budget: InvestigationBudget) -> InvestigationBudget:
    """Return a budget_remaining equal to the full budget (nothing spent yet)."""
    return InvestigationBudget(
        max_latency_ms=budget.max_latency_ms,
        max_tool_calls=budget.max_tool_calls,
        max_external_calls=budget.max_external_calls,
        max_llm_tokens=budget.max_llm_tokens,
    )


def calculate_budget_remaining(state: InvestigationState) -> InvestigationBudget:
    """
    Derive remaining budget from the state's budget and cost_spent.

    remaining = max(0, max - spent)   for every dimension

    Never allows negative remaining. The result is a new InvestigationBudget
    instance (immutable); it does NOT mutate the state.
    """
    spent = state.tool_cost_spent
    budget = state.budget

    return InvestigationBudget(
        max_latency_ms=max(0, budget.max_latency_ms - spent.latency_ms),
        max_tool_calls=max(0, budget.max_tool_calls - spent.tool_calls),
        max_external_calls=max(0, budget.max_external_calls - spent.external_calls),
        max_llm_tokens=max(0, budget.max_llm_tokens - spent.llm_tokens),
    )


def record_tool_cost(
    current_spent: ToolCostSpent,
    *,
    latency_ms: int = 0,
    is_external: bool = False,
    llm_tokens: int = 0,
) -> ToolCostSpent:
    """
    Return a new ToolCostSpent with one tool's cost added.

    The caller must replace state.tool_cost_spent with the returned value
    via state.model_copy(update={"tool_cost_spent": new_spent}).
    """
    return ToolCostSpent(
        latency_ms=current_spent.latency_ms + latency_ms,
        tool_calls=current_spent.tool_calls + 1,
        external_calls=current_spent.external_calls + (1 if is_external else 0),
        llm_tokens=current_spent.llm_tokens + llm_tokens,
    )


def is_latency_exhausted(state: InvestigationState) -> bool:
    remaining = calculate_budget_remaining(state)
    return remaining.max_latency_ms <= 0


def is_tool_call_exhausted(state: InvestigationState) -> bool:
    remaining = calculate_budget_remaining(state)
    return remaining.max_tool_calls <= 0


def is_external_call_exhausted(state: InvestigationState) -> bool:
    remaining = calculate_budget_remaining(state)
    return remaining.max_external_calls <= 0
