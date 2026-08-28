"""
contracts/investigation.py

InvestigationState (§13) is the working memory of one case. It stores
EVIDENCE IDS, never full evidence copies — the evidence store is the
single source of truth (avoids drift between duplicated snapshots).

AttackHypothesis (§14) is multi-label and explicitly NOT a verdict.
Hypotheses feed the Investigation Policy; only the Risk Engine produces
a verdict (contracts/risk.py).

InvestigationLevel — four tiers that gate tool eligibility:

    L0_TRIAGE  : deterministic heuristics, SPF/DKIM/DMARC, header parse
    L1_TARGETED: targeted ML + cheap deterministic probes
    L2_DEEP    : external enrichment, RDAP, historical correlation
    L3_GROQ    : bounded LLM reasoning (NOT invoked in Stage 1)

StateMachineStatus — explicit FSM node for the investigation lifecycle.

Budget — four-dimensional resource envelope. Remaining budget is
computed deterministically; it must never go negative.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import Field, model_validator

from .common import BaseContract, CaseId, EvidenceId, HypothesisId, utcnow


# ---------------------------------------------------------------------------
# Attack Hypothesis Types
# ---------------------------------------------------------------------------


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
    reasons: list[str] = Field(
        default_factory=list,
        description="Human-readable rule reasons that contributed to this hypothesis score",
    )


# ---------------------------------------------------------------------------
# Investigation Level — four-tier depth gate
# ---------------------------------------------------------------------------


class InvestigationLevel(str, Enum):
    """Depth tiers gating which tools/profiles are eligible.

    L0_TRIAGE  — deterministic only (SPF/DKIM/DMARC, header parse, relay)
    L1_TARGETED— targeted ML + cheap deterministic probes
    L2_DEEP    — external enrichment, domain intelligence, historical
    L3_GROQ    — bounded Groq reasoning (Stage 5, NOT used in Stage 1)
    """

    L0_TRIAGE = "L0_TRIAGE"
    L1_TARGETED = "L1_TARGETED"
    L2_DEEP = "L2_DEEP"
    L3_GROQ = "L3_GROQ"


# ---------------------------------------------------------------------------
# State Machine Status — explicit FSM nodes
# ---------------------------------------------------------------------------


class StateMachineStatus(str, Enum):
    """Explicit lifecycle nodes for the investigation FSM.

    Valid transitions in Stage 1:
        INITIALIZED → LEVEL_0
        LEVEL_0     → LEVEL_1  (Stage 2+)
        LEVEL_1     → LEVEL_2  (Stage 2+)
        LEVEL_2     → LEVEL_3  (Stage 5+)
        LEVEL_*     → STOPPED
        STOPPED     → COMPLETED
    """

    INITIALIZED = "INITIALIZED"
    LEVEL_0 = "LEVEL_0"
    LEVEL_1 = "LEVEL_1"
    LEVEL_2 = "LEVEL_2"
    LEVEL_3 = "LEVEL_3"
    STOPPED = "STOPPED"
    COMPLETED = "COMPLETED"


# ---------------------------------------------------------------------------
# Stop Reasons
# ---------------------------------------------------------------------------


class StopReason(str, Enum):
    # Semantic / evidence-based stops
    CONFIDENCE_TARGET_REACHED = "CONFIDENCE_TARGET_REACHED"
    NO_MANDATORY_EVIDENCE_MISSING = "NO_MANDATORY_EVIDENCE_MISSING"
    NO_MAJOR_UNRESOLVED_CONFLICT = "NO_MAJOR_UNRESOLVED_CONFLICT"

    # Resource / structural stops
    NO_CANDIDATE_TOOL_UTILITY = "NO_CANDIDATE_TOOL_UTILITY"
    NO_CANDIDATE_TOOLS = "NO_CANDIDATE_TOOLS"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    LATENCY_BUDGET_EXHAUSTED = "LATENCY_BUDGET_EXHAUSTED"
    EXTERNAL_CALL_BUDGET_EXHAUSTED = "EXTERNAL_CALL_BUDGET_EXHAUSTED"
    MAX_ITERATIONS_REACHED = "MAX_ITERATIONS_REACHED"
    REPEATED_FAILURES_EXCEEDED = "REPEATED_FAILURES_EXCEEDED"


# ---------------------------------------------------------------------------
# Escalation Status
# ---------------------------------------------------------------------------


class EscalationStatus(str, Enum):
    NONE = "NONE"
    REQUESTED = "REQUESTED"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"


# ---------------------------------------------------------------------------
# Investigation Outcome Status
#
# Distinct from StateMachineStatus (internal FSM node) and Verdict (risk).
#
# InvestigationStatus describes WHETHER the investigation produced a
# sufficiently confident result:
#
#     COMPLETED    — Investigation ran to a natural stop with sufficient
#                    evidence; a confident verdict was produced.
#     INCONCLUSIVE — Investigation stopped (budget/iterations/no-tools)
#                    before sufficient evidence was gathered. The verdict
#                    is INCONCLUSIVE; previous evidence is preserved.
#     ESCALATED    — Referred to a human analyst for review.
#     FAILED       — Internal error; investigation could not complete.
#
# NEVER map budget exhaustion → COMPLETED.
# NEVER map INCONCLUSIVE → BENIGN.
# ---------------------------------------------------------------------------


class InvestigationStatus(str, Enum):
    COMPLETED    = "COMPLETED"     # Sufficient evidence; confident verdict
    INCONCLUSIVE = "INCONCLUSIVE"  # Stopped early; evidence insufficient
    ESCALATED    = "ESCALATED"     # Referred to human analyst
    FAILED       = "FAILED"        # Internal error


# ---------------------------------------------------------------------------
# Budget models
# ---------------------------------------------------------------------------


class InvestigationBudget(BaseContract):
    """Four-dimensional resource envelope.

    All values are non-negative integers/floats.
    budget_remaining fields must never exceed the corresponding max.
    """

    max_latency_ms: int = Field(..., ge=0, description="Wall-clock latency budget in ms")
    max_tool_calls: int = Field(..., ge=0, description="Total tool-call budget for this case")
    max_external_calls: int = Field(..., ge=0, description="External API call budget")
    max_llm_tokens: int = Field(..., ge=0, description="LLM token budget (Stage 5; 0 in Stage 1)")


class ToolCostSpent(BaseContract):
    """Monotonically increasing resource consumption tracker.

    Every field is non-negative. The engine must never decrement these.
    """

    latency_ms: int = Field(default=0, ge=0)
    tool_calls: int = Field(default=0, ge=0)
    external_calls: int = Field(default=0, ge=0)
    llm_tokens: int = Field(default=0, ge=0)


# ---------------------------------------------------------------------------
# Investigation State — working memory of one case
# ---------------------------------------------------------------------------


class InvestigationState(BaseContract):
    """
    Immutable snapshot of the investigation at a point in time.

    Transition pattern (preserves immutability):
        new_state = state.model_copy(update={...})

    Evidence is referenced by ID only; the evidence store is authoritative.
    """

    # ---- Identity ----
    case_id: CaseId
    created_at: datetime = Field(default_factory=utcnow)

    # ---- Hypotheses ----
    attack_hypotheses: list[AttackHypothesis] = Field(default_factory=list)

    # ---- Evidence references (IDs only, grouped by type) ----
    observed_facts: list[EvidenceId] = Field(
        default_factory=list,
        description="EvidenceItem IDs of type=FACT",
    )
    heuristic_findings: list[EvidenceId] = Field(
        default_factory=list,
        description="EvidenceItem IDs of type=HEURISTIC",
    )
    ml_signals: list[EvidenceId] = Field(
        default_factory=list,
        description="EvidenceItem IDs of type=ML_SIGNAL",
    )
    threat_intelligence: list[EvidenceId] = Field(
        default_factory=list,
        description="EvidenceItem IDs of type=THREAT_INTEL",
    )
    historical_matches: list[EvidenceId] = Field(
        default_factory=list,
        description="EvidenceItem IDs of type=HISTORICAL",
    )

    # ---- Risk / confidence ----
    current_risk: float = Field(default=0.0, ge=0.0, le=100.0)
    current_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    risk_history: list[float] = Field(default_factory=list)

    # ---- Evidence gaps & conflicts ----
    missing_evidence: list[str] = Field(
        default_factory=list,
        description="Named required evidence not yet acquired",
    )
    pending_conflicts: list[str] = Field(
        default_factory=list,
        description="EvidenceConflict.conflict_id values",
    )
    resolved_conflicts: list[str] = Field(default_factory=list)

    # ---- Tool tracking ----
    tools_used: list[str] = Field(default_factory=list)
    tools_available: list[str] = Field(default_factory=list)
    tools_blocked: list[str] = Field(default_factory=list)

    # ---- Resource tracking ----
    tool_cost_spent: ToolCostSpent = Field(default_factory=ToolCostSpent)
    budget: InvestigationBudget
    budget_remaining: InvestigationBudget

    # ---- Investigation progress ----
    investigation_level: InvestigationLevel = InvestigationLevel.L0_TRIAGE
    iteration_count: int = Field(default=0, ge=0)
    max_iterations: int = Field(default=12, ge=1)

    # ---- FSM status ----
    sm_status: StateMachineStatus = StateMachineStatus.INITIALIZED

    # ---- Outcome fields ----
    stop_reason: Optional[StopReason] = None
    escalation_reason: Optional[str] = None
    escalation_status: EscalationStatus = EscalationStatus.NONE

    @model_validator(mode="after")
    def _budget_remaining_not_exceeded(self) -> "InvestigationState":
        r = self.budget_remaining
        b = self.budget
        errors = []
        if r.max_latency_ms > b.max_latency_ms:
            errors.append(f"budget_remaining.max_latency_ms ({r.max_latency_ms}) > budget ({b.max_latency_ms})")
        if r.max_tool_calls > b.max_tool_calls:
            errors.append(f"budget_remaining.max_tool_calls ({r.max_tool_calls}) > budget ({b.max_tool_calls})")
        if r.max_external_calls > b.max_external_calls:
            errors.append(f"budget_remaining.max_external_calls ({r.max_external_calls}) > budget ({b.max_external_calls})")
        if r.max_llm_tokens > b.max_llm_tokens:
            errors.append(f"budget_remaining.max_llm_tokens ({r.max_llm_tokens}) > budget ({b.max_llm_tokens})")
        if errors:
            raise ValueError("InvestigationState: " + "; ".join(errors))
        return self

    @model_validator(mode="after")
    def _stop_reason_when_stopped(self) -> "InvestigationState":
        if self.sm_status == StateMachineStatus.STOPPED and self.stop_reason is None:
            raise ValueError("sm_status=STOPPED requires stop_reason to be set")
        return self
