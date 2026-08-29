import pytest
from app.services.reporting.report_generator import ReportGenerator
from app.contracts.investigation import InvestigationState
from app.contracts.evidence import EvidenceItem, EvidenceType, EvidenceCategory, TrustLevel, SourceType
from app.contracts.common import Provenance, utcnow
from app.contracts.risk import RiskAssessment, ConfidenceAssessment

@pytest.mark.asyncio
async def test_report_generator():
    gen = ReportGenerator()
    
    from app.services.investigation.budget import DEFAULT_BUDGET, make_full_budget_remaining
    state = InvestigationState(
        case_id="case_report",
        budget=DEFAULT_BUDGET,
        budget_remaining=make_full_budget_remaining(DEFAULT_BUDGET),
        observed_facts=["ev1"],
        current_risk=75.0,
        current_confidence=0.9
    )
    
    ev = EvidenceItem(
        evidence_id="ev1",
        case_id="case_report",
        type=EvidenceType.FACT,
        category=EvidenceCategory.URL,
        key="url_http_scheme",
        value="http",
        source="test",
        source_type=SourceType.DETERMINISTIC,
        confidence=1.0,
        trust_level=TrustLevel.VERIFIED,
        timestamp=utcnow(),
        provenance=Provenance(producer_module="test", extraction_method="test")
    )
    
    evidence_store = {"ev1": ev}
    risk_result = {
        "risk_assessment": RiskAssessment(
            case_id="case_report",
            risk_score=75.0,
            verdict="MALICIOUS",
            confidence=0.9,
            contributions=[],
            recommended_action="escalate_to_analyst",
            engine_version="1.0"
        )
    }
    
    report, new_state = await gen.generate_report(state, evidence_store, risk_result)
    
    assert report.case_id == "case_report"
    assert "High risk" in report.narrative
    assert report.risk_assessment.risk_score == 75.0
    assert report.recommended_action == "escalate_to_analyst"
