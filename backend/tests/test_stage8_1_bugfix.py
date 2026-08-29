import pytest
from app.contracts.common import utcnow
from app.contracts.evidence import EvidenceCategory, EvidenceType
from app.contracts.investigation import InvestigationStatus, StopReason
from app.contracts.risk import Verdict
from app.services.evidence.models import EmailEvidencePackage, HeaderEvidence, BodyEvidence, SenderEvidence, URLIndicator, ExtractionMethod, EvidenceMetadata, TrustLevel, RecipientEvidence, AuthenticationEvidence, SingleAuthResult
from app.services.investigation.decision_engine import InvestigationDecisionEngine
from app.services.investigation.result_factory import to_investigation_result
from app.core.config import settings

def make_test_package(urls: list[str] = None, auth_pass: bool = True) -> EmailEvidencePackage:
    res = "pass" if auth_pass else "fail"
    meta_mock = EvidenceMetadata(
        source_module="test", raw_value="http://evil.com/login", extraction_method=ExtractionMethod.REGEX,
        confidence=1.0, trust_level=TrustLevel.REPORTED
    )
    return EmailEvidencePackage(
        email_sha256="dummy",
        raw_artifact_reference="dummy.eml",
        headers=HeaderEvidence(message_id="<123@google.com>", has_reply_to_mismatch=False, has_return_path_mismatch=False),
        body=BodyEvidence(has_plain_text=True),
        sender=SenderEvidence(),
        recipients=RecipientEvidence(),
        authentication=AuthenticationEvidence(results=[
            SingleAuthResult(protocol="spf", result=res),
            SingleAuthResult(protocol="dkim", result=res),
            SingleAuthResult(protocol="dmarc", result=res),
        ]),
        urls=[URLIndicator(raw_url=u, scheme="http" if "http://" in u else "https", extracted_from="body", extraction_confidence=1.0, meta=meta_mock, indicator_id="ind-1") for u in (urls or [])]
    )

def test_url_present_triggers_investigation():
    engine = InvestigationDecisionEngine()
    pkg = make_test_package(urls=["https://google.com"])
    
    stage1 = engine.run_stage1(pkg)
    assert any(h.investigation_triggered for h in stage1.state.attack_hypotheses)
    
    res = to_investigation_result(stage1)
    
    assert not (res.status == InvestigationStatus.COMPLETED and res.verdict == Verdict.BENIGN and res.iteration_count == 0)

def test_no_url_skips_url_tools():
    engine = InvestigationDecisionEngine()
    pkg = make_test_package()
    stage1 = engine.run_stage1(pkg)
    
    res = to_investigation_result(stage1)
    assert not any("url" in t.lower() for t in res.tools_used)

def test_budget_exhausted_before_url_investigation():
    engine = InvestigationDecisionEngine()
    pkg = make_test_package(urls=["https://google.com"])
    
    from app.services.investigation.budget import DEFAULT_BUDGET
    import app.services.investigation.case_manager as cm
    
    original_budget = cm.DEFAULT_BUDGET
    try:
        cm.DEFAULT_BUDGET = original_budget.model_copy(update={"max_tool_calls": 0})
        stage1 = engine.run_stage1(pkg)
        res = to_investigation_result(stage1)
        
        assert res.status == InvestigationStatus.INCONCLUSIVE
        assert res.verdict != Verdict.BENIGN
        assert res.stop_reason in [StopReason.BUDGET_EXHAUSTED, StopReason.NO_CANDIDATE_TOOLS]
    finally:
        cm.DEFAULT_BUDGET = original_budget

def test_max_llm_tokens_zero():
    engine = InvestigationDecisionEngine()
    pkg = make_test_package(urls=["https://example.com"])
    
    from app.services.investigation.budget import DEFAULT_BUDGET
    import app.services.investigation.case_manager as cm
    
    original_budget = cm.DEFAULT_BUDGET
    try:
        cm.DEFAULT_BUDGET = original_budget.model_copy(update={"max_llm_tokens": 0})
        stage1 = engine.run_stage1(pkg)
        res = to_investigation_result(stage1)
        assert res.budget.max_llm_tokens == 0
        assert res.budget_spent.llm_tokens == 0
    finally:
        cm.DEFAULT_BUDGET = original_budget
