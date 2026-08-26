"""
contracts/historical.py

§12: historical evidence must NEVER automatically determine the verdict.
Consumers (Risk Engine) must treat HistoricalMatch as one input among
many, subject to the same weighted/capped contribution rules as anything
else (see contracts/risk.py RiskContribution).
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import Field

from .common import BaseContract, CaseId


class MatchType(str, Enum):
    EXACT_HASH = "EXACT_HASH"
    EXACT_IP = "EXACT_IP"
    EXACT_DOMAIN = "EXACT_DOMAIN"
    EXACT_URL = "EXACT_URL"
    SENDER_RELATIONSHIP = "SENDER_RELATIONSHIP"
    HEADER_SIMILARITY = "HEADER_SIMILARITY"
    CONTENT_SIMILARITY = "CONTENT_SIMILARITY"
    INFRASTRUCTURE_RELATIONSHIP = "INFRASTRUCTURE_RELATIONSHIP"


class HistoricalMatch(BaseContract):
    current_case_id: CaseId
    previous_case_id: CaseId
    match_type: MatchType
    similarity: float = Field(..., ge=0.0, le=1.0)
    reliability: float = Field(..., ge=0.0, le=1.0, description="How trustworthy this match type/source is")
    recency: Optional[str] = Field(default=None, description="e.g. ISO8601 duration or bucket like 'within_30d'")
    evidence_reference: Optional[str] = None
    explanation: str
