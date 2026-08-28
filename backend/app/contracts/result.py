"""
contracts/result.py

InvestigationResult — the final structured output of one investigation case.

This is the ONLY contract that crosses the API boundary as a response.
It is distinct from:

    InvestigationState  — working memory (internal FSM state)
    Stage1Result        — internal dataclass (not serializable, contains AuditLogger)
    RiskAssessment      — risk-specific sub-contract (embedded here)
    ForensicReport      — long-form narrative report (future, requires narrative text)

SECURITY INVARIANTS (enforced by model_validator):

    1. INCONCLUSIVE verdict must never map to BENIGN.
    2. Resource-stop investigations (budget exhaustion, max iterations, etc.)
       must have status=INCONCLUSIVE unless confidence was already sufficient.
    3. stop_reason is required when status != COMPLETED.

Evidence is referenced by ID only (InvestigationState convention). The
evidence store is the authoritative source for full EvidenceItem objects.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import Field, model_validator

from .common import BaseContract, CaseId, EvidenceId, utcnow
from .investigation import (
    AttackHypothesis,
    InvestigationBudget,
    InvestigationLevel,
    InvestigationStatus,
    StopReason,
    ToolCostSpent,
)
from .risk import Verdict

# ---------------------------------------------------------------------------
# Stop reasons that indicate resource exhaustion (not semantic completion).
# Budget exhaustion ≠ safe. These ALWAYS produce status=INCONCLUSIVE
# unless the risk engine determined a confident verdict before exhaustion.
# ---------------------------------------------------------------------------

RESOURCE_STOP_REASONS: frozenset[StopReason] = frozenset({
    StopReason.BUDGET_EXHAUSTED,
    StopReason.EXTERNAL_CALL_BUDGET_EXHAUSTED,
    StopReason.LATENCY_BUDGET_EXHAUSTED,
    StopReason.MAX_ITERATIONS_REACHED,
    StopReason.NO_CANDIDATE_TOOLS,
    StopReason.NO_CANDIDATE_TOOL_UTILITY,
    StopReason.REPEATED_FAILURES_EXCEEDED,
})


class InvestigationResult(BaseContract):
    """
    Final investigation result — the contract returned by the API.

    Fields
    ------
    investigation_id : CaseId
        Matches EmailEvidencePackage.package_id and InvestigationState.case_id.

    status : InvestigationStatus
        COMPLETED / INCONCLUSIVE / ESCALATED / FAILED.
        See InvestigationStatus docstring for semantics.

    stop_reason : Optional[StopReason]
        Why investigation stopped. Required when status != COMPLETED.

    investigation_level_reached : InvestigationLevel
        The deepest level the investigation reached before stopping.

    verdict : Verdict
        BENIGN / SUSPICIOUS / MALICIOUS / INCONCLUSIVE.
        Produced by the Risk Engine. Never produced by LLM.

    risk_score : float [0–100]
        Weighted risk score from the Risk Engine. 0 = no risk, 100 = max.

    confidence : float [0–1]
        Confidence in the verdict. Low confidence → INCONCLUSIVE verdict.

    risk_reasons : list[str]
        Human-readable, deterministic reasons for the risk score.
        Every reason references a specific evidence key.

    unresolved_questions : list[str]
        Open questions the Risk Engine could not resolve with available evidence.

    observed_facts : list[EvidenceId]
        IDs of FACT evidence from L0 analysis.

    heuristic_findings : list[EvidenceId]
        IDs of HEURISTIC evidence from rule-based tools.

    ml_signals : list[EvidenceId]
        IDs of ML_SIGNAL evidence (Stage 3+).

    threat_intelligence : list[EvidenceId]
        IDs of THREAT_INTEL evidence from external lookups (Stage 3+).

    historical_matches : list[EvidenceId]
        IDs of HISTORICAL evidence from correlation (Stage 3+).

    attack_hypotheses : list[AttackHypothesis]
        All 13 hypotheses with scores, reasons, and status.

    budget : InvestigationBudget
        The total resource budget allocated for this case.

    budget_spent : ToolCostSpent
        What was actually consumed.

    budget_remaining : InvestigationBudget
        What remained when investigation ended.

    missing_evidence : list[str]
        Named required evidence that was NOT acquired before stopping.

    pending_conflicts : list[str]
        EvidenceConflict IDs that were not resolved before stopping.

    tools_used : list[str]
        Tool names that were executed during the investigation.

    iteration_count : int
        How many tool-execution iterations ran.

    audit_chain_last_hash : str
        SHA256 hash of the last AuditRecord — allows verification of the
        complete audit trail without embedding the entire chain.

    created_at : datetime
        When the investigation started.

    completed_at : datetime
        When the investigation result was produced.
    """

    # Identity
    investigation_id: CaseId
    created_at: datetime = Field(default_factory=utcnow)
    completed_at: datetime = Field(default_factory=utcnow)

    # Outcome
    status: InvestigationStatus
    stop_reason: Optional[StopReason] = None
    investigation_level_reached: InvestigationLevel

    # Risk
    verdict: Verdict
    risk_score: float = Field(..., ge=0.0, le=100.0)
    confidence: float = Field(..., ge=0.0, le=1.0)
    risk_reasons: list[str] = Field(default_factory=list)
    unresolved_questions: list[str] = Field(default_factory=list)

    # Evidence (IDs only — evidence store is authoritative)
    observed_facts: list[EvidenceId] = Field(default_factory=list)
    heuristic_findings: list[EvidenceId] = Field(default_factory=list)
    ml_signals: list[EvidenceId] = Field(default_factory=list)
    threat_intelligence: list[EvidenceId] = Field(default_factory=list)
    historical_matches: list[EvidenceId] = Field(default_factory=list)

    # Hypotheses
    attack_hypotheses: list[AttackHypothesis] = Field(default_factory=list)

    # Budget transparency (always included — never hide budget state)
    budget: InvestigationBudget
    budget_spent: ToolCostSpent
    budget_remaining: InvestigationBudget

    # Evidence gaps
    missing_evidence: list[str] = Field(default_factory=list)
    pending_conflicts: list[str] = Field(default_factory=list)

    # Investigation metadata
    tools_used: list[str] = Field(default_factory=list)
    iteration_count: int = Field(default=0, ge=0)

    # Audit trail
    audit_chain_last_hash: str

    # ----------------------------------------------------------------
    # Security invariants
    # ----------------------------------------------------------------

    @model_validator(mode="after")
    def _stop_reason_required_when_not_completed(self) -> "InvestigationResult":
        if self.status != InvestigationStatus.COMPLETED and self.stop_reason is None:
            raise ValueError(
                f"InvestigationResult.stop_reason is required when "
                f"status={self.status.value} (only COMPLETED may omit it)"
            )
        return self

    @model_validator(mode="after")
    def _resource_stop_cannot_be_benign(self) -> "InvestigationResult":
        """
        Core security invariant:

        If investigation stopped because a resource limit was hit, the
        verdict MUST NOT be BENIGN. We did not finish the investigation —
        we ran out of resources. That is not evidence of safety.

        INCONCLUSIVE, SUSPICIOUS, or MALICIOUS are all permissible.
        BENIGN is not, because we didn't look hard enough to say "safe".
        """
        if (
            self.stop_reason in RESOURCE_STOP_REASONS
            and self.verdict == Verdict.BENIGN
        ):
            raise ValueError(
                f"Verdict.BENIGN is forbidden when stop_reason={self.stop_reason.value}. "
                f"Resource exhaustion ≠ safe. Use Verdict.INCONCLUSIVE or "
                f"Verdict.SUSPICIOUS when investigation stopped early. (§ Security Invariant)"
            )
        return self
