"""
contracts/groq.py

Groq is an OPTIONAL reasoning/explanation component, never the source of
forensic truth (§24-25). It cannot invent evidence, modify EvidenceItems,
change risk_score, change verdict, or invoke arbitrary tools.

The backend MUST validate every evidence_id Groq references against the
real evidence store before accepting a GroqReasoningResponse. If any
referenced ID does not exist, the response is rejected outright — see
`validate_referenced_evidence` below, intended to be called by the
service layer (not enforced structurally here, since this module has no
access to the evidence store).
"""

from __future__ import annotations

from enum import Enum
from typing import Iterable

from pydantic import Field

from .common import BaseContract, CaseId, EvidenceId


class RequestedAction(str, Enum):
    NO_ACTION = "NO_ACTION"
    REQUEST_ADDITIONAL_TOOL = "REQUEST_ADDITIONAL_TOOL"
    REQUEST_ANALYST_REVIEW = "REQUEST_ANALYST_REVIEW"
    EXPLANATION_ONLY = "EXPLANATION_ONLY"


class GroqInvestigationRequest(BaseContract):
    case_id: CaseId
    task: str = Field(..., description="e.g. 'explain_risk', 'resolve_conflict', 'summarize_investigation'")
    evidence_snapshot: list[dict] = Field(
        ..., description="Serialized EvidenceItem dicts only — never raw email content (§24)"
    )
    hypotheses: list[dict] = Field(default_factory=list, description="Serialized AttackHypothesis dicts")
    unresolved_conflicts: list[dict] = Field(default_factory=list, description="Serialized EvidenceConflict dicts")
    investigation_path: list[str] = Field(default_factory=list, description="Tool names executed so far, in order")
    analyst_question: str | None = None
    policy_version: str
    evidence_snapshot_hash: str = Field(..., description="Hash of evidence_snapshot for audit/integrity linkage")


class GroqReasoningResponse(BaseContract):
    summary: str
    reasoning_points: list[str] = Field(default_factory=list)
    requested_action: RequestedAction
    referenced_evidence_ids: list[EvidenceId] = Field(default_factory=list)
    uncertainty: float = Field(..., ge=0.0, le=1.0)
    recommendation: str
    safety_flags: list[str] = Field(default_factory=list, description="e.g. 'possible_prompt_injection_in_source_email'")


def validate_referenced_evidence(
    response: GroqReasoningResponse, known_evidence_ids: Iterable[EvidenceId]
) -> None:
    """
    Enforce §25: if Groq references evidence that does not exist, REJECT
    the response outright. Call this in the service layer immediately
    after receiving a response, before it touches any report or state.
    """
    known = set(known_evidence_ids)
    unknown = [eid for eid in response.referenced_evidence_ids if eid not in known]
    if unknown:
        raise ValueError(
            f"GroqReasoningResponse references unknown evidence_ids {unknown}; response REJECTED per §25"
        )
