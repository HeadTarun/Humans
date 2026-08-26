"""
contracts/risk.py

Risk Engine is deterministic (§19-20). Groq cannot directly set risk_score,
confidence, or verdict — those fields only ever originate here.

Risk != Confidence (§21): risk measures how bad, confidence measures how
sure. Both must be traceable to specific evidence contributions.

EvidenceConflict (§22): conflicting findings are never blindly averaged;
they must be represented explicitly and resolved or left open.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import Field, model_validator

from .common import BaseContract, CaseId, ConflictId, EvidenceId, Recommendation


class Verdict(str, Enum):
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    INCONCLUSIVE = "INCONCLUSIVE"


class RiskContribution(BaseContract):
    evidence_id: EvidenceId
    weight: float = Field(..., description="Configurable weight from the weight table for this evidence key")
    contribution: float = Field(..., description="weight-derived point contribution to the 0-100 risk score")
    reason_code: str


class RiskAssessment(BaseContract):
    case_id: CaseId
    risk_score: float = Field(..., ge=0.0, le=100.0)
    confidence: float = Field(..., ge=0.0, le=1.0)
    verdict: Verdict
    contributing_evidence_ids: list[EvidenceId] = Field(default_factory=list)
    contributions: list[RiskContribution] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    unresolved_questions: list[str] = Field(default_factory=list)
    recommended_action: Recommendation
    engine_version: str

    @model_validator(mode="after")
    def _score_matches_contributions(self) -> "RiskAssessment":
        if self.contributions:
            total = sum(c.contribution for c in self.contributions)
            clipped = max(0.0, min(100.0, total))
            if abs(clipped - self.risk_score) > 0.01:
                raise ValueError(
                    f"risk_score ({self.risk_score}) does not match sum of contributions "
                    f"clipped to [0,100] ({clipped}); calculation must not be hidden (§20)"
                )
        return self


class ConfidenceAssessment(BaseContract):
    case_id: CaseId
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    evidence_completeness: float = Field(..., ge=0.0, le=1.0)
    calibration_quality: float = Field(..., ge=0.0, le=1.0)
    evidence_reliability: float = Field(..., ge=0.0, le=1.0)
    unresolved_conflicts_penalty: float = Field(default=0.0, ge=0.0, le=1.0)
    tool_failure_penalty: float = Field(default=0.0, ge=0.0, le=1.0)
    contributing_evidence_ids: list[EvidenceId] = Field(default_factory=list)


class ConflictType(str, Enum):
    ML_VS_REPUTATION = "ML_VS_REPUTATION"
    AUTH_VS_CONTENT_SIGNAL = "AUTH_VS_CONTENT_SIGNAL"
    HISTORICAL_VS_CURRENT = "HISTORICAL_VS_CURRENT"
    CROSS_TOOL_DISAGREEMENT = "CROSS_TOOL_DISAGREEMENT"


class ConflictSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class ConflictStatus(str, Enum):
    OPEN = "OPEN"
    RESOLVED = "RESOLVED"
    DISMISSED = "DISMISSED"


class EvidenceConflict(BaseContract):
    conflict_id: ConflictId
    evidence_a_id: EvidenceId
    evidence_b_id: EvidenceId
    conflict_type: ConflictType
    severity: ConflictSeverity
    status: ConflictStatus = ConflictStatus.OPEN
    resolution_evidence_ids: list[EvidenceId] = Field(default_factory=list)
