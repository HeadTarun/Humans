"""
contracts/correlation.py

Broader than a single pairwise HistoricalMatch: a CorrelationLink groups
a case with one or more related cases under a single explanation (e.g.
a detected campaign). Still subject to §12 — never auto-determines verdict.
"""

from __future__ import annotations

from enum import Enum

from pydantic import Field

from .common import BaseContract, CaseId, CorrelationId, EvidenceId


class CorrelationType(str, Enum):
    CAMPAIGN = "CAMPAIGN"
    SHARED_INFRASTRUCTURE = "SHARED_INFRASTRUCTURE"
    SHARED_SENDER = "SHARED_SENDER"
    SHARED_CONTENT_TEMPLATE = "SHARED_CONTENT_TEMPLATE"


class CorrelationLink(BaseContract):
    correlation_id: CorrelationId
    case_id: CaseId
    related_case_ids: list[CaseId] = Field(default_factory=list)
    correlation_type: CorrelationType
    strength: float = Field(..., ge=0.0, le=1.0)
    explanation: str
    evidence_ids: list[EvidenceId] = Field(default_factory=list)
