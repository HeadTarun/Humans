import pytest
import os
from app.services.investigation.decision_engine import InvestigationDecisionEngine
from app.contracts.investigation import InvestigationStatus
from app.contracts.risk import Verdict
from app.services.investigation.result_factory import to_investigation_result
from app.contracts.evidence import TrustLevel
from app.services.evidence.models import (
    EmailEvidencePackage, HeaderEvidence, BodyEvidence,
    SenderEvidence, RecipientEvidence, AuthenticationEvidence,
    URLIndicator, EvidenceMetadata, ExtractionMethod
)

def make_test_package(urls=None, auth_pass=True):
    meta_mock = EvidenceMetadata(
        source_module="test", raw_value="http://evil.com/login", extraction_method=ExtractionMethod.REGEX,
        confidence=1.0, trust_level=TrustLevel.REPORTED
    )
    url_inds = [
        URLIndicator(raw_url=u, extracted_from="body", extraction_confidence=1.0, meta=meta_mock, indicator_id=f"ind-{i}")
        for i, u in enumerate(urls or [])
    ]
    return EmailEvidencePackage(
        email_sha256="dummy",
        raw_artifact_reference="test",
        headers=HeaderEvidence(message_id="<123@google.com>"),
        body=BodyEvidence(has_plain_text=True),
        sender=SenderEvidence(),
        recipients=RecipientEvidence(),
        authentication=AuthenticationEvidence(),
        urls=url_inds
    )

@pytest.mark.asyncio
async def test_email_with_multiple_urls_propagates_ml_signal(monkeypatch):
    # Mock the url_adapter to return a MALICIOUS ML_SIGNAL
    import app.services.tools.handlers.url_ml as url_mod
    
    class MockAdapter:
        def analyze(self, url, case_id):
            from app.contracts.evidence import EvidenceItem, EvidenceType, EvidenceCategory, TrustLevel, EvidenceStatus
            from app.contracts.common import Provenance, SourceType
            return EvidenceItem(
                evidence_id="mock_evidence_1", case_id=case_id, type=EvidenceType.ML_SIGNAL,
                category=EvidenceCategory.URL, key="url_ml_risk", value="MALICIOUS",
                source="M4", source_type=SourceType.ML_MODEL, confidence=0.9,
                trust_level=TrustLevel.VERIFIED, status=EvidenceStatus.ACTIVE,
                provenance=Provenance(producer_module="url_adapter", extraction_method="model")
            )
            
    monkeypatch.setattr(url_mod, "URLModelAdapter", MockAdapter)

    engine = InvestigationDecisionEngine()
    pkg = make_test_package(urls=["https://malicious.com"])
    
    stage1 = engine.run_stage1(pkg)
    res = to_investigation_result(stage1)
    
    assert "url_ml" in res.tools_used
    assert len(res.ml_signals) > 0, "ML signals disappeared from InvestigationResult"
    assert res.risk_score >= 50.0, "Risk score did not reflect the ML_SIGNAL"
    assert res.verdict != Verdict.BENIGN

@pytest.mark.asyncio
async def test_no_url_does_not_execute_url_ml():
    engine = InvestigationDecisionEngine()
    pkg = make_test_package(urls=[])
    
    stage1 = engine.run_stage1(pkg)
    res = to_investigation_result(stage1)
    
    assert "url_ml" not in res.tools_used
    assert len(res.ml_signals) == 0

@pytest.mark.asyncio
async def test_url_ml_unavailable_fails_gracefully():
    # Force the adapter to fail
    engine = InvestigationDecisionEngine()
    pkg = make_test_package(urls=["https://test.com"])
    
    import app.services.tools.handlers.url_ml as url_mod
    class MockFailingAdapter:
        def analyze(self, url, case_id):
            from app.services.ml.base import ModelFailureError
            raise ModelFailureError("M4 model unavailable")
            
    original_adapter = url_mod.URLModelAdapter
    try:
        url_mod.URLModelAdapter = MockFailingAdapter
        stage1 = engine.run_stage1(pkg)
        res = to_investigation_result(stage1)
        
        assert len(res.ml_signals) == 0
        assert res.verdict != Verdict.BENIGN
    finally:
        url_mod.URLModelAdapter = original_adapter
