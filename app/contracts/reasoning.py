"""
contracts/reasoning.py

Bounded reasoning layer contracts for the ASHIELDER advisory intelligence system.

These contracts define the ONLY data shapes that cross the LLM boundary.
They are deliberately restrictive:

    - ReasoningEvidenceSnapshot is an ALLOWLIST — only explicitly declared
      fields may reach the model. Raw .eml, HTML, headers, attachments,
      credentials are structurally excluded.

    - ReasoningResult deliberately OMITS risk, confidence, verdict, budget,
      tool-execution, and DB-mutation fields. The model is structurally
      incapable of returning authoritative values.

    - ReasoningUnavailable is an explicit failure contract. We never return
      None silently or expose raw provider errors.

    - ValidatedReasoningArtifact wraps a validated result with full
      provenance so it is never confused with deterministic FACT evidence.

Authority boundaries (§24-25, §19-20):
    Risk     → deterministic RiskEngine only
    Verdict  → deterministic RiskEngine only
    State    → InvestigationState only
    Tools    → Adaptive Investigation Engine only
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, field_validator

from .common import BaseContract, CaseId, EvidenceId, utcnow


# ---------------------------------------------------------------------------
# Supporting types for the snapshot (allowlist members)
# ---------------------------------------------------------------------------


class ReasoningFinding(BaseContract):
    """A typed, bounded summary of one evidence item for reasoning.

    Contains only machine-readable key/value pairs and metadata.
    NEVER contains raw email body, raw HTML, raw headers, or attachment bytes.
    """

    evidence_id: EvidenceId
    type: str = Field(..., description="FACT | HEURISTIC | ML_SIGNAL | THREAT_INTEL | HISTORICAL")
    category: str = Field(..., description="AUTHENTICATION | HEADER | CONTENT | URL | etc.")
    key: str = Field(..., description="Machine-readable field name, e.g. 'dmarc' or 'phishing_probability'")
    value: Any = Field(..., description="The observation or score value")
    source: str = Field(..., description="Producing analyzer/tool name")
    confidence: float = Field(..., ge=0.0, le=1.0)


class ReasoningHypothesis(BaseContract):
    """Bounded hypothesis summary for reasoning context."""

    hypothesis_type: str
    score: float = Field(..., ge=0.0, le=1.0)
    status: str
    reasons: list[str] = Field(default_factory=list, max_length=10)
    supporting_evidence_ids: list[EvidenceId] = Field(default_factory=list, max_length=50)
    contradicting_evidence_ids: list[EvidenceId] = Field(default_factory=list, max_length=50)


class UntrustedContentItem(BaseContract):
    """Email-derived free-form text explicitly marked as untrusted.

    The reasoning service wraps these in <untrusted_evidence_text> delimiters
    and instructs the model to treat them as DATA, not instructions.
    """

    evidence_id: EvidenceId
    content_type: str = Field(..., description="e.g. 'subject', 'body_snippet', 'display_name'")
    text: str = Field(..., max_length=2000, description="Bounded untrusted text snippet")


class BudgetStatus(str, Enum):
    """Coarse budget status — never exposes exact remaining counts to the LLM."""

    AVAILABLE = "AVAILABLE"
    LOW = "LOW"
    EXHAUSTED = "EXHAUSTED"


# ---------------------------------------------------------------------------
# ReasoningEvidenceSnapshot — the ALLOWLIST input to the LLM
# ---------------------------------------------------------------------------


class ReasoningEvidenceSnapshot(BaseContract):
    """Sanitized, allowlist-based snapshot sent to the reasoning model.

    SECURITY PRINCIPLE: This is built as
        "Only explicitly permitted typed fields"
    NOT as
        "All investigation data except dangerous fields"

    This prevents future developers from accidentally leaking new
    sensitive fields into the LLM.

    NEVER directly contains:
        - raw .eml bytes
        - raw HTML blocks
        - raw header blocks
        - attachment contents
        - credentials / API keys
        - internal infrastructure secrets
    """

    # ---- Identity ----
    case_id: CaseId
    investigation_id: str = Field(..., description="Same as case_id in current architecture")
    investigation_level: str = Field(..., description="L0_TRIAGE | L1_TARGETED | L2_DEEP | L3_GROQ")

    # ---- Current assessment (READ-ONLY context, not authority) ----
    current_risk: float = Field(..., ge=0.0, le=100.0)
    current_confidence: float = Field(..., ge=0.0, le=1.0)

    # ---- Typed evidence (bounded) ----
    key_findings: list[ReasoningFinding] = Field(
        default_factory=list,
        max_length=100,
        description="Typed evidence summaries — never raw content",
    )

    # ---- Hypotheses (bounded) ----
    current_hypotheses: list[ReasoningHypothesis] = Field(
        default_factory=list,
        max_length=15,
    )

    # ---- Evidence gaps ----
    missing_evidence: list[str] = Field(
        default_factory=list,
        max_length=30,
        description="Named required evidence not yet acquired",
    )

    # ---- Tool tracking ----
    completed_tools: list[str] = Field(default_factory=list, max_length=30)
    failed_tools: list[str] = Field(default_factory=list, max_length=30)

    # ---- Budget status (coarse — no exact numbers) ----
    budget_status: BudgetStatus = BudgetStatus.AVAILABLE

    # ---- Optional context ----
    supporting_evidence: list[EvidenceId] = Field(
        default_factory=list, max_length=50
    )
    contradictory_evidence: list[EvidenceId] = Field(
        default_factory=list, max_length=50
    )
    historical_context: Optional[str] = Field(
        default=None,
        max_length=500,
        description="Bounded summary of historical correlations, e.g. '3 prior cases share this ASN'",
    )

    # ---- Untrusted email-derived content ----
    untrusted_content: list[UntrustedContentItem] = Field(
        default_factory=list,
        max_length=10,
        description="Email-derived text explicitly marked as untrusted data",
    )

    def compute_hash(self) -> str:
        """Deterministic SHA-256 hash for audit/cache keying.

        Strips volatile fields (timestamps) and sorts for repeatability.
        """
        def _sort_key(d: dict) -> str:
            return str(d.get("evidence_id", json.dumps(d, sort_keys=True, default=str)))

        canonical = {
            "case_id": self.case_id,
            "investigation_id": self.investigation_id,
            "investigation_level": self.investigation_level,
            "current_risk": self.current_risk,
            "current_confidence": self.current_confidence,
            "key_findings": sorted(
                [f.model_dump(mode="json") for f in self.key_findings],
                key=_sort_key,
            ),
            "current_hypotheses": [h.model_dump(mode="json") for h in self.current_hypotheses],
            "missing_evidence": sorted(self.missing_evidence),
            "completed_tools": sorted(self.completed_tools),
            "failed_tools": sorted(self.failed_tools),
            "budget_status": self.budget_status.value,
            "historical_context": self.historical_context,
        }
        serialized = json.dumps(canonical, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# ReasoningResult — the structured LLM output
# ---------------------------------------------------------------------------


class ReasoningResult(BaseModel):
    """Structured output from the reasoning model.

    Uses plain BaseModel (NOT BaseContract) because it is used with
    ChatGroq.with_structured_output() which needs a mutable Pydantic model.

    DELIBERATELY OMITS:
        - risk score
        - confidence score
        - verdict
        - budget fields
        - tool execution commands
        - database mutation commands

    The model is structurally incapable of returning authoritative values.
    """

    model_config = {"extra": "forbid"}

    schema_version: Literal["1.0"] = "1.0"
    case_id: str
    investigation_id: str
    summary: str = Field(
        ...,
        description="~120 word summary of findings",
    )
    hypotheses: list[str] = Field(
        ...,
        description="Hypothesis labels supported by evidence",
    )
    supporting_evidence_ids: list[str] = Field(
        ...,
        description="Evidence IDs that support the analysis — must exist in snapshot",
    )
    contradicting_evidence_ids: list[str] = Field(
        ...,
        description="Evidence IDs that contradict primary hypotheses — must exist in snapshot",
    )
    uncertainty: Literal["low", "medium", "high"] = Field(
        ...,
        description="Self-assessed uncertainty level",
    )
    recommended_next_actions: list[str] = Field(
        ...,
        description="Advisory-only suggested next steps — NOT executable",
    )
    explanation: str = Field(
        ...,
        description="Detailed reasoning explanation",
    )
    escalation_required: bool = Field(
        ...,
        description="Whether the model recommends human analyst escalation",
    )


    @field_validator("summary")
    @classmethod
    def _summary_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("summary must not be empty")
        return v

    @field_validator("explanation")
    @classmethod
    def _explanation_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("explanation must not be empty")
        return v


# ---------------------------------------------------------------------------
# ReasoningUnavailable — explicit failure contract
# ---------------------------------------------------------------------------


class ReasoningFailureCategory(str, Enum):
    PROVIDER_TIMEOUT = "PROVIDER_TIMEOUT"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    RATE_LIMITED = "RATE_LIMITED"
    SCHEMA_VALIDATION_FAILED = "SCHEMA_VALIDATION_FAILED"
    VALIDATION_FAILED = "VALIDATION_FAILED"
    REASONING_DISABLED = "REASONING_DISABLED"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class ReasoningUnavailable(BaseContract):
    """Explicit failure contract — never return None silently.

    No raw provider errors are exposed to clients.
    """

    category: ReasoningFailureCategory
    reason: str = Field(..., max_length=500)
    request_correlation_id: str
    timestamp: datetime = Field(default_factory=utcnow)
    safe_diagnostic: dict[str, str] = Field(
        default_factory=dict,
        description="Safe metadata for debugging — never raw provider payloads",
    )


# ---------------------------------------------------------------------------
# ValidatedReasoningArtifact — provenance-wrapped result
# ---------------------------------------------------------------------------


class ValidatedReasoningArtifact(BaseContract):
    """Post-validation reasoning artifact with full provenance.

    This is NOT deterministic FACT evidence. It is explanation/hypothesis
    metadata that must never be scored as ordinary hard evidence.
    """

    source_type: Literal["reasoning_model"] = "reasoning_model"
    model: str
    prompt_version: str
    snapshot_hash: str
    timestamp: datetime = Field(default_factory=utcnow)
    validation_status: Literal["validated"] = "validated"
    result: dict = Field(
        ...,
        description="The validated ReasoningResult as a dict (model_dump output)",
    )
