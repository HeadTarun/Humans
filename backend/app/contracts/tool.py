"""
contracts/tool.py

Every investigation tool implements ToolDefinition (§15). `handler_ref`
is a string reference (dotted path or registry key) rather than a
callable, so ToolDefinition stays a pure, serializable contract — the
tool registry resolves handler_ref to an actual callable at runtime.

ToolPriorityScore captures the full ranking breakdown from §18 so every
selection decision is auditable: why selected, EIG, reliability, cost.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import Field

from .common import BaseContract, CaseId, EvidenceId, ExecutionId
from .investigation import InvestigationLevel
from .policy import ToolEligibility


class ToolDefinition(BaseContract):
    name: str
    description: str
    profiles: list[str] = Field(default_factory=list, description="InvestigationProfile.profile_id values that use this tool")
    min_level: InvestigationLevel = InvestigationLevel.L1_TRIAGE
    input_contract: str = Field(..., description="Dotted path of the pydantic model this tool accepts")
    output_contract: str = Field(..., description="Dotted path of the pydantic model this tool returns")
    reliability: float = Field(..., ge=0.0, le=1.0)
    cost: float = Field(..., ge=0.0, description="Composite normalized cost, see ToolPriorityScore.cost breakdown")
    handler_ref: str = Field(..., description="Registry key resolved to a callable by the tool registry, not a callable itself")


class ToolExecutionRequest(BaseContract):
    case_id: CaseId
    tool_name: str
    input: dict[str, Any] = Field(default_factory=dict, description="Must validate against the tool's input_contract")
    reason: str = Field(..., description="Why the policy selected this tool")
    policy_version: str


class ToolExecutionStatus(str, Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    REJECTED = "REJECTED"
    SKIPPED = "SKIPPED"


class ToolExecutionResult(BaseContract):
    execution_id: ExecutionId
    tool_name: str
    status: ToolExecutionStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    latency_ms: Optional[float] = Field(default=None, ge=0.0)
    output: Optional[dict[str, Any]] = Field(default=None, description="Must validate against the tool's output_contract")
    evidence_ids: list[EvidenceId] = Field(default_factory=list)
    error: Optional[str] = None


class ToolPriorityScore(BaseContract):
    """
    Auditable breakdown for one ranked candidate tool (§18):
        ToolPriority(t) = EIG(t) * Reliability(t) / Cost(t)   if relevance >= threshold
                        = 0                                    otherwise

    Cost = w_latency*normalized_latency + w_api*normalized_api_cost + w_resource*normalized_resource_cost

    EIG uses the approved uncertainty proxy, NOT true Shannon entropy (§18).
    """

    tool_name: str
    relevance: float = Field(..., ge=0.0, le=1.0)
    eligibility: ToolEligibility
    eig: float = Field(..., ge=0.0, description="Expected information gain proxy")
    reliability: float = Field(..., ge=0.0, le=1.0)
    cost: float = Field(..., ge=0.0)
    cost_breakdown: dict[str, float] = Field(
        default_factory=dict, description="e.g. {'latency': 0.2, 'api_cost': 0.1, 'resource': 0.05}"
    )
    priority: float = Field(..., ge=0.0, description="Final computed priority score; 0 if relevance < threshold")
    reason: str
