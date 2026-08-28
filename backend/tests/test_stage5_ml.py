import pytest
from app.services.ml.nlp_adapter import NLPModelAdapter
from app.services.ml.url_adapter import URLModelAdapter
from app.services.ml.base import ModelFailureError
from app.services.analysis.header_heuristics import HeaderHeuristicAnalyzer
from app.services.evidence.models import EmailEvidencePackage, HeaderEvidence, SenderEvidence, AuthProtocol, AuthenticationEvidence, SingleAuthResult, AuthResultValue, RecipientEvidence, BodyEvidence
from app.contracts.url_canonical import URLCanonical
from app.contracts.evidence import EvidenceType, EvidenceCategory

def _build_dummy_pkg(sender_kwargs=None, auth_kwargs=None, header_kwargs=None, body_kwargs=None):
    sender = SenderEvidence(**(sender_kwargs or {}))
    auth = AuthenticationEvidence(**(auth_kwargs or {}))
    headers = HeaderEvidence(**(header_kwargs or {}))
    body = BodyEvidence(**(body_kwargs or {}))
    # We will pass plain_text explicitly to the adapter during tests
    return EmailEvidencePackage(
        email_sha256="dummy",
        raw_artifact_reference="dummy.eml",
        case_id="case_123",
        headers=headers,
        sender=sender,
        authentication=auth,
        recipients=RecipientEvidence(),
        body=body
    )

def test_nlp_adapter_loads_and_infers():
    adapter = NLPModelAdapter()
    try:
        adapter.load_model()
    except ModelFailureError:
        pytest.skip("Model runtime blocked by Application Control (DLL load failed)")
    assert adapter.is_loaded
    
    pkg = _build_dummy_pkg()
    evidence = adapter.analyze(pkg, parsed_text="Please verify your password immediately or your account will be suspended. http://evil.com/login")
    
    assert len(evidence) > 0
    # Check for ML signal
    ml_signals = [e for e in evidence if e.type == EvidenceType.ML_SIGNAL]
    assert len(ml_signals) == 1
    assert ml_signals[0].key == "intent"
    
    # Check for deterministic heuristic rules (Urgency, Credential Request)
    heuristics = [e for e in evidence if e.type == EvidenceType.HEURISTIC]
    assert len(heuristics) > 0
    heuristic_keys = [e.key for e in heuristics]
    assert "urgency_score" in heuristic_keys
    assert "se_flag_credential_request" in heuristic_keys

def test_nlp_adapter_benign():
    adapter = NLPModelAdapter()
    pkg = _build_dummy_pkg()
    try:
        evidence = adapter.analyze(pkg, parsed_text="Hey Tarun, let's grab lunch tomorrow at 12.")
    except ModelFailureError:
        pytest.skip("Model runtime blocked by Application Control (DLL load failed)")
    # Could be BENIGN and no heuristics
    ml_signals = [e for e in evidence if e.type == EvidenceType.ML_SIGNAL]
    if ml_signals:
        assert ml_signals[0].related_entity == "BENIGN"

def test_url_adapter_loads_and_infers():
    adapter = URLModelAdapter()
    try:
        adapter.load_model()
    except ModelFailureError:
        pytest.skip("Model runtime blocked by Application Control (DLL load failed)")
    assert adapter.is_loaded
    
    canon = URLCanonical(
        original_url="http://example.com",
        normalized_url="http://example.com",
        domain="example.com",
        registrable_domain="example.com"
    )
    evidence = adapter.analyze(canon, case_id="case_123")
    assert evidence.type == EvidenceType.ML_SIGNAL
    assert evidence.key == "url_ml_risk"
    assert 0.0 <= evidence.value <= 1.0

def test_header_heuristic_from_replyto_mismatch():
    analyzer = HeaderHeuristicAnalyzer()
    pkg = _build_dummy_pkg(
        sender_kwargs={"email_address": "ceo@company.com", "reply_to_email": "hacker@evil.com", "domain": "company.com"}
    )
    evidence = analyzer.analyze(pkg)
    keys = [e.key for e in evidence]
    assert "from_replyto_mismatch" in keys
    assert evidence[0].type == "HEURISTIC"

def test_header_heuristic_spf_failure():
    analyzer = HeaderHeuristicAnalyzer()
    pkg = _build_dummy_pkg(
        sender_kwargs={"email_address": "ceo@company.com", "domain": "company.com"},
        auth_kwargs={"results": [SingleAuthResult(protocol=AuthProtocol.SPF, result=AuthResultValue.FAIL)]}
    )
    evidence = analyzer.analyze(pkg)
    keys = [e.key for e in evidence]
    assert "spf_failure" in keys
    assert "dkim_missing" in keys

def test_header_heuristic_message_id_anomaly():
    analyzer = HeaderHeuristicAnalyzer()
    pkg = _build_dummy_pkg(
        sender_kwargs={"email_address": "ceo@company.com", "domain": "company.com"},
        header_kwargs={"message_id": "<12345@google.com>"}
    )
    evidence = analyzer.analyze(pkg)
    assert any(e.key == "message_id_domain_mismatch" for e in evidence)

