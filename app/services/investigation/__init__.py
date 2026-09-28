"""
services/investigation/__init__.py

Public surface of the Investigation Decision Engine — Stage 1.

Consumers should import from this package rather than from sub-modules
directly. This enforces a stable API boundary.
"""

from __future__ import annotations

from .audit_logger import AuditLogger, AuditChainIntegrityError
from .budget import (
    DEFAULT_BUDGET,
    calculate_budget_remaining,
    is_external_call_exhausted,
    is_latency_exhausted,
    is_tool_call_exhausted,
    make_full_budget_remaining,
    record_tool_cost,
)
from .case_manager import (
    generate_initial_hypotheses,
    init_state,
)
from .decision_engine import InvestigationDecisionEngine, Stage1Result
from .policy import (
    RELEVANCE_FLOOR,
    get_candidate_tools,
    select_profiles,
)
from .profile_registry import INVESTIGATION_PROFILES
from .state_machine import (
    InvalidTransitionError,
    complete_investigation,
    initialize_to_level0,
    stop_investigation,
    transition,
)
from .stop_conditions import StopDecision, should_stop
from .result_factory import to_investigation_result
from .tool_registry import (
    TOOL_REGISTRY,
    TOOL_REGISTRY_VERSION,
    get_enabled_tools,
    get_tool,
)

__all__ = [
    # Audit
    "AuditLogger",
    "AuditChainIntegrityError",
    # Budget
    "DEFAULT_BUDGET",
    "calculate_budget_remaining",
    "is_external_call_exhausted",
    "is_latency_exhausted",
    "is_tool_call_exhausted",
    "make_full_budget_remaining",
    "record_tool_cost",
    # Case manager
    "generate_initial_hypotheses",
    "init_state",
    # Decision engine
    "InvestigationDecisionEngine",
    "Stage1Result",
    # Policy
    "RELEVANCE_FLOOR",
    "get_candidate_tools",
    "select_profiles",
    # Profile registry
    "INVESTIGATION_PROFILES",
    # State machine
    "InvalidTransitionError",
    "complete_investigation",
    "initialize_to_level0",
    "stop_investigation",
    "transition",
    # Stop conditions
    "StopDecision",
    "should_stop",
    # Result factory
    "to_investigation_result",
    # Tool registry
    "TOOL_REGISTRY",
    "TOOL_REGISTRY_VERSION",
    "get_enabled_tools",
    "get_tool",
]
