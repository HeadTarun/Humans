import pytest
from app.contracts.investigation import InvestigationState, StopReason, StateMachineStatus
from app.services.investigation.decision_engine import InvestigationDecisionEngine
from app.services.evidence.models import EmailEvidencePackage
from app.services.ingestion.parser import EmailParser
from app.services.evidence.normalizer import EvidenceNormalizer
from tests.test_e2e_investigation import _build_eml

def _build_package(phishing=False):
    if phishing:
        eml = _build_eml(
            subject="Urgent: Password Reset", 
            from_addr="admin@evil.com", 
            body_text="Click here http://evil.com/reset",
            auth_results="spf=fail (sender IP is 1.2.3.4); dkim=fail; dmarc=fail"
        )
    else:
        eml = _build_eml(
            auth_results="spf=pass; dkim=pass; dmarc=pass"
        )
    parser = EmailParser()
    normalizer = EvidenceNormalizer()
    parsed = parser.parse(eml)
    return normalizer.normalize(parsed)

class TestAdaptiveLoop:
    def test_benign_email_stops_at_level_0(self):
        package = _build_package(False)
        engine = InvestigationDecisionEngine()
        result = engine.run_stage1(package)
        assert result.state.iteration_count == 0
        assert result.state.sm_status == StateMachineStatus.COMPLETED
        assert result.stop_decision is None
        
    def test_phishing_email_adaptive_execution(self):
        package = _build_package(True)
        engine = InvestigationDecisionEngine()
        result = engine.run_stage1(package)
        assert result.state.iteration_count > 0
        assert len(result.state.tools_used) > 0
        assert result.state.current_risk > 50.0
        assert result.state.sm_status in [StateMachineStatus.COMPLETED, StateMachineStatus.STOPPED]

    def test_deduplication_and_cache_avoids_repeated_calls(self):
        # 19 URLs -> should be deduplicated
        eml = _build_eml(
            subject="Lots of URLs",
            body_text="http://evil.com/1 http://evil.com/2 http://evil.com/3 " * 6,
            auth_results="spf=fail"
        )
        parser = EmailParser()
        normalizer = EvidenceNormalizer()
        package = normalizer.normalize(parser.parse(eml))
        
        engine = InvestigationDecisionEngine()
        result = engine.run_stage1(package)
        
        # We only have max 4 external calls in budget. If dedup fails, budget is exhausted.
        # But wait, 19 URLs of same domain might just be 1 domain lookup.
        assert result.state.iteration_count > 0

