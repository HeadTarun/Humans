"""
contracts/tool.py

Every investigation tool implements ToolDefinition (§15). `handler_ref`
is a string reference (dotted path or registry key) rather than a
callable, so ToolDefinition stays a pure, serializable contract — the
tool registry resolves handler_ref to an actual callable at runtime.

ToolPriorityScore captures the full ranking breakdown from §18 so every
selection decision is auditable: why selected, EIG, reliability, cost.

Stage 1 additions:
    ToolDefinition.tier               — mandatory/optional/expensive
    ToolDefinition.estimated_latency_ms
    ToolDefinition.external_api
    ToolDefinition.estimated_api_cost
    ToolDefinition.enabled

Stage 3 additions:
    ToolDefinition.p50_latency_ms     — measured p50 (0 = not yet benchmarked)
    ToolDefinition.p95_latency_ms     — measured p95 (0 = not yet benchmarked)
    ToolDefinition.cache_ttl_seconds  — cache TTL (0 = not cached)
    ToolDefinition.availability_score — provider uptime probability
                                        DISTINCT from reliability (evidence quality)
    ToolExecutionStatus.RATE_LIMITED  — quota exceeded; may succeed on retry
    ToolExecutionResult.provider      — adapter that produced the result
    ToolExecutionResult.cache_hit     — True if result came from cache
    ToolExecutionResult.retry_count   — retries before this result
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
    """
    Static, serializable descriptor for one investigation tool.

    handler_ref is a registry key, never a callable — the tool registry
    resolves it at execution time. This keeps the contract portable and
    auditable.
    """

    name: str = Field(..., description="Stable machine-readable identifier for this tool")
    description: str
    profiles: list[str] = Field(
        default_factory=list,
        description="InvestigationProfile.profile_id values that use this tool",
    )
    min_level: InvestigationLevel = InvestigationLevel.L0_TRIAGE
    tier: ToolEligibility = ToolEligibility.OPTIONAL
    input_contract: str = Field(..., description="Dotted path of the pydantic model this tool accepts")
    output_contract: str = Field(..., description="Dotted path of the pydantic model this tool returns")
    reliability: float = Field(..., ge=0.0, le=1.0)
    cost: float = Field(..., ge=0.0, description="Composite normalized cost, see ToolPriorityScore.cost breakdown")
    handler_ref: str = Field(
        ...,
        description="Registry key resolved to a callable by the tool registry, not a callable itself",
    )

    # Stage 1 metadata additions
    estimated_latency_ms: int = Field(
        default=100,
        ge=0,
        description="Expected wall-clock execution time in ms (used for budget planning)",
    )
    external_api: bool = Field(
        default=False,
        description="True if this tool makes external network calls (counts against external_calls budget)",
    )
    estimated_api_cost: float = Field(
        default=0.0,
        ge=0.0,
        description="Estimated monetary API cost per call (informational; used for future cost-aware selection)",
    )
    enabled: bool = Field(
        default=True,
        description="False disables the tool globally without removing it from the registry",
    )

    # Stage 3 metadata additions
    p50_latency_ms: int = Field(
        default=0,
        ge=0,
        description="Measured p50 wall-clock latency in ms (0 = not yet benchmarked)",
    )
    p95_latency_ms: int = Field(
        default=0,
        ge=0,
        description="Measured p95 wall-clock latency in ms (0 = not yet benchmarked)",
    )
    cache_ttl_seconds: int = Field(
        default=0,
        ge=0,
        description="Cache TTL in seconds for this tool's results (0 = not cached)",
    )
    availability_score: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description=(
            "Provider availability probability [0,1]. "
            "DISTINCT from reliability (evidence quality) — "
            "reliability measures how trustworthy the evidence is; "
            "availability_score measures whether the provider is reachable."
        ),
    )



class ToolExecutionRequest(BaseContract):
    case_id: CaseId
    tool_name: str
    input: dict[str, Any] = Field(
        default_factory=dict,
        description="Must validate against the tool's input_contract",
    )
    reason: str = Field(..., description="Why the policy selected this tool")
    policy_version: str


class ToolExecutionStatus(str, Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    REJECTED = "REJECTED"
    SKIPPED = "SKIPPED"
    # Stage 3: provider rate limit hit — distinct from FAILED (may succeed on retry)
    RATE_LIMITED = "RATE_LIMITED"


class ToolExecutionResult(BaseContract):
    execution_id: ExecutionId
    tool_name: str
    status: ToolExecutionStatus
    # Stage 3 additions
    provider: Optional[str] = Field(
        default=None,
        description="Name of the provider/adapter that produced this result",
    )
    cache_hit: bool = Field(
        default=False,
        description="True if this result was served from cache without executing the tool",
    )
    retry_count: int = Field(
        default=0,
        ge=0,
        description="Number of retries attempted before producing this result",
    )
    started_at: datetime
    completed_at: Optional[datetime] = None
    latency_ms: Optional[float] = Field(default=None, ge=0.0)
    output: Optional[dict[str, Any] | list[Any]] = Field(
        default=None,
        description="Must validate against the tool's output_contract",
    )
    evidence_ids: list[EvidenceId] = Field(default_factory=list)
    error: Optional[str] = None


class ToolPriorityScore(BaseContract):
    """
    Auditable breakdown for one ranked candidate tool (§18):
        ToolPriority(t) = EIG(t) * Reliability(t) / Cost(t)   if relevance >= threshold
                        = 0                                    otherwise

    Cost = w_latency*normalized_latency + w_api*normalized_api_cost + w_resource*normalized_resource_cost

    EIG uses the approved uncertainty proxy, NOT true Shannon entropy (§18).

    NOTE: Stage 1 does not compute EIG or dynamic priority. This contract
    exists as the authoritative shape for Stage 2+ use.
    """

    tool_name: str
    relevance: float = Field(..., ge=0.0, le=1.0)
    eligibility: ToolEligibility
    eig: float = Field(..., ge=0.0, description="Expected information gain proxy")
    reliability: float = Field(..., ge=0.0, le=1.0)
    cost: float = Field(..., ge=0.0)
    cost_breakdown: dict[str, float] = Field(
        default_factory=dict,
        description="e.g. {'latency': 0.2, 'api_cost': 0.1, 'resource': 0.05}",
    )
    priority: float = Field(..., ge=0.0, description="Final computed priority score; 0 if relevance < threshold")
    reason: str
