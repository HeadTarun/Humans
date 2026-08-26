"""
contracts/investigation.py

InvestigationState (§13) is the working memory of one case. It stores
EVIDENCE IDS, never full evidence copies — the evidence store is the
single source of truth (avoids drift between duplicated snapshots).

AttackHypothesis (§14) is multi-label and explicitly NOT a verdict.
Hypotheses feed the Investigation Policy; only the Risk Engine produces
a verdict (contracts/risk.py).
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import Field, model_validator

from .common import BaseContract, CaseId, EvidenceId, HypothesisId


class AttackHypothesisType(str, Enum):
    CREDENTIAL_PHISHING = "credential_phishing"
    BEC = "bec"
    EXECUTIVE_IMPERSONATION = "executive_impersonation"
    VENDOR_FRAUD = "vendor_fraud"
    PAYMENT_DIVERSION = "payment_diversion"
    INVOICE_FRAUD = "invoice_fraud"
    MALICIOUS_URL = "malicious_url"
    MALWARE_DELIVERY = "malware_delivery"
    MALICIOUS_ATTACHMENT = "malicious_attachment"
    SPOOFING = "spoofing"
    COMPROMISED_ACCOUNT = "compromised_account"
    SOCIAL_ENGINEERING = "social_engineering"
    CAMPAIGN = "campaign"


class HypothesisStatus(str, Enum):
    SUPPORTED = "SUPPORTED"
    UNCERTAIN = "UNCERTAIN"
    WEAK = "WEAK"
    REJECTED = "REJECTED"


class AttackHypothesis(BaseContract):
    hypothesis_id: HypothesisId
    case_id: CaseId
    hypothesis_type: AttackHypothesisType
    score: float = Field(..., ge=0.0, le=1.0)
    confidence: float = Field(..., ge=0.0, le=1.0)
    supporting_evidence_ids: list[EvidenceId] = Field(default_factory=list)
    contradicting_evidence_ids: list[EvidenceId] = Field(default_factory=list)
    status: HypothesisStatus


class InvestigationLevel(str, Enum):
    """Depth tiers gating which tools/profiles are eligible (§16-17)."""

    L1_TRIAGE = "L1_TRIAGE"
    L2_STANDARD = "L2_STANDARD"
    L3_DEEP = "L3_DEEP"


class StopReason(str, Enum):
    CONFIDENCE_TARGET_REACHED = "CONFIDENCE_TARGET_REACHED"
    NO_MANDATORY_EVIDENCE_MISSING = "NO_MANDATORY_EVIDENCE_MISSING"
    NO_MAJOR_UNRESOLVED_CONFLICT = "NO_MAJOR_UNRESOLVED_CONFLICT"
    NO_CANDIDATE_TOOL_UTILITY = "NO_CANDIDATE_TOOL_UTILITY"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    LATENCY_BUDGET_EXHAUSTED = "LATENCY_BUDGET_EXHAUSTED"
    MAX_ITERATIONS_REACHED = "MAX_ITERATIONS_REACHED"
    REPEATED_FAILURES_EXCEEDED = "REPEATED_FAILURES_EXCEEDED"


class EscalationStatus(str, Enum):
    NONE = "NONE"
    REQUESTED = "REQUESTED"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"


class InvestigationState(BaseContract):
    case_id: CaseId
    attack_hypotheses: list[AttackHypothesis] = Field(default_factory=list)

    evidence_ids: list[EvidenceId] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list, description="Named required evidence not yet acquired")

    pending_conflicts: list[str] = Field(default_factory=list, description="EvidenceConflict.conflict_id values")
    resolved_conflicts: list[str] = Field(default_factory=list)

    tools_available: list[str] = Field(default_factory=list)
    tools_used: list[str] = Field(default_factory=list)
    tools_blocked: list[str] = Field(default_factory=list)

    current_risk: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    current_confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    risk_history: list[float] = Field(default_factory=list)

    investigation_level: InvestigationLevel = InvestigationLevel.L1_TRIAGE
    iteration_count: int = Field(default=0, ge=0)

    budget: int = Field(..., description="Total tool-call budget allotted to this case")
    budget_remaining: int = Field(..., ge=0)

    stop_reason: Optional[StopReason] = None
    escalation_reason: Optional[str] = None
    escalation_status: EscalationStatus = EscalationStatus.NONE

    @model_validator(mode="after")
    def _budget_not_exceeded(self) -> "InvestigationState":
        if self.budget_remaining > self.budget:
            raise ValueError("budget_remaining cannot exceed budget")
        return self
