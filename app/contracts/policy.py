"""
contracts/policy.py

InvestigationPolicy is deterministic (§17). It MUST NOT call Groq and
MUST NOT generate natural-language reasoning — it returns a structured
PolicyDecision only. Profiles (§16) define eligibility; they do not
execute tools themselves.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import Field

from .common import BaseContract, CaseId
from .investigation import AttackHypothesisType, InvestigationLevel


class ToolEligibility(str, Enum):
    MANDATORY = "MANDATORY"
    OPTIONAL = "OPTIONAL"
    EXPENSIVE = "EXPENSIVE"


class InvestigationProfile(BaseContract):
    profile_id: str
    hypothesis_type: AttackHypothesisType
    mandatory_tools: list[str] = Field(default_factory=list)
    optional_tools: list[str] = Field(default_factory=list)
    expensive_tools: list[str] = Field(default_factory=list)
    min_level: InvestigationLevel = InvestigationLevel.L0_TRIAGE


class PolicyAction(str, Enum):
    CONTINUE = "CONTINUE"
    ESCALATE = "ESCALATE"
    STOP = "STOP"


class RankedTool(BaseContract):
    tool_name: str
    priority: float = Field(..., description="See contracts/tool.py ToolPriorityScore for the full breakdown")


class PolicyDecision(BaseContract):
    case_id: CaseId
    action: PolicyAction
    allowed_tools: list[str] = Field(default_factory=list)
    ranked_tools: list[RankedTool] = Field(default_factory=list)
    reason_code: str
    reason_data: dict[str, Any] = Field(default_factory=dict)
    stop: bool = False
    escalate: bool = False
    policy_version: str
