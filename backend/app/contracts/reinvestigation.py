"""
contracts/reinvestigation.py

Defines contracts for requesting and representing re-investigations.
Original cases must remain immutable, and re-investigations create new cases.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import Field

from .common import BaseContract, CaseId, utcnow


class ReinvestigationRequest(BaseContract):
    original_case_id: CaseId
    reason: str = Field(..., description="Analyst reason for requesting re-investigation")
    requested_by: str = Field(..., description="Analyst identifier")
    additional_evidence: list[dict] = Field(default_factory=list, description="New evidence or context provided")


class ReinvestigationResult(BaseContract):
    original_case_id: CaseId
    new_case_id: CaseId
    started_at: datetime = Field(default_factory=utcnow)
    status: str
    message: str
