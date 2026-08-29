"""
contracts/report.py

Every forensic claim in the narrative must reference evidence IDs (§29),
e.g. "DMARC failed [EV-003] and the URL was identified as malicious
[EV-021]." Never generate unreferenced forensic claims — the service
layer producing `narrative` should reject any generated sentence whose
claims aren't backed by an ID present in evidence_ids.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import Field

from .common import BaseContract, CaseId, Recommendation, utcnow
from .correlation import CorrelationLink
from .historical import HistoricalMatch
from .investigation import AttackHypothesis
from .risk import RiskAssessment
from .threat_intel import ThreatIntelResult


class ForensicReport(BaseContract):
    case_id: CaseId
    risk_assessment: RiskAssessment
    attack_hypotheses: list[AttackHypothesis] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    investigation_path: list[str] = Field(default_factory=list, description="Tool names in execution order")
    historical_matches: list[HistoricalMatch] = Field(default_factory=list)
    correlation_links: list[CorrelationLink] = Field(default_factory=list)
    intelligence_results: list[ThreatIntelResult] = Field(default_factory=list)
    relay_path_reference: Optional[str] = Field(default=None, description="Pointer to the stored RelayPath")
    recommended_action: Recommendation
    narrative: str = Field(..., description="Must only make claims traceable to evidence_ids, e.g. '...DMARC failed [EV-003]'")
    audit_reference: str = Field(..., description="Pointer to the AuditRecord chain / final hash_self for this case")
    generated_at: datetime = Field(default_factory=utcnow)


InvestigationReport = ForensicReport
