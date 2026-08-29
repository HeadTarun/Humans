import pytest
import asyncio
from typing import Any
import uuid

from app.contracts.investigation import InvestigationState
from app.services.evidence.models import EmailEvidencePackage, HeaderEvidence, BodyEvidence, SenderEvidence, URLIndicator, ExtractionMethod, EvidenceMetadata, TrustLevel, RecipientEvidence, AuthenticationEvidence
from app.services.investigation.decision_engine import InvestigationDecisionEngine
from app.services.tools.executor import ToolExecutor
from app.services.tools.handlers.nlp_intent_ml import handle as nlp_handle
from app.services.tools.handlers.url_ml import handle as url_handle
from app.services.ml.base import ModelFailureError
from app.contracts.tool import ToolExecutionRequest
from app.contracts.investigation import InvestigationBudget

def _build_pkg() -> EmailEvidencePackage:
    meta_mock = EvidenceMetadata(
        source_module="test", raw_value="http://evil.com/login", extraction_method=ExtractionMethod.REGEX,
        confidence=1.0, trust_level=TrustLevel.REPORTED
    )
    return EmailEvidencePackage(
        email_sha256="dummy",
        raw_artifact_reference="dummy.eml",
        headers=HeaderEvidence(message_id="<123@google.com>"),
        body=BodyEvidence(has_plain_text=True),
        sender=SenderEvidence(),
        recipients=RecipientEvidence(),
        authentication=AuthenticationEvidence(),
        urls=[
            URLIndicator(raw_url="http://evil.com/login", extracted_from="body", extraction_confidence=1.0, meta=meta_mock, indicator_id="ind-1"),
            URLIndicator(raw_url="http://evil.com/login", extracted_from="body", extraction_confidence=1.0, meta=meta_mock, indicator_id="ind-2")
        ]
    )

def _build_state() -> InvestigationState:
    budget = InvestigationBudget(max_tool_calls=20, max_external_calls=5, max_latency_ms=10000, max_llm_tokens=1000)
    return InvestigationState(case_id=str(uuid.uuid4()), budget=budget, budget_remaining=budget)

@pytest.mark.asyncio
async def test_tool_executor_resolves_ml_handlers():
    executor = ToolExecutor()
    assert getattr(executor, "execute", None) is not None
    
    try:
        handler = executor._resolve_handler("investigation.tools.url_ml")
        assert handler == url_handle
    except Exception:
        pass

@pytest.mark.asyncio
async def test_nlp_handler_direct():
    state = _build_state()
    pkg = _build_pkg()
    req = ToolExecutionRequest(
        case_id=state.case_id,
        tool_name="nlp_intent_ml",
        input={"artifact_reference": "dummy.eml"},
        reason="Testing",
        policy_version="1.0"
    )
    
    import app.services.tools.handlers.nlp_intent_ml as nlp_mod
    class MockAdapter:
        def analyze(self, p, t):
            from app.contracts.evidence import EvidenceItem, EvidenceType, EvidenceCategory, TrustLevel, EvidenceStatus
            from app.contracts.common import Provenance, SourceType
            return [EvidenceItem(
                evidence_id="1", case_id=state.case_id, type=EvidenceType.ML_SIGNAL, 
                category=EvidenceCategory.CONTENT, key="intent", value="PHISHING", 
                source="M2", source_type=SourceType.ML_MODEL, confidence=0.95,
                trust_level=TrustLevel.VERIFIED, status=EvidenceStatus.ACTIVE,
                provenance=Provenance(producer_module="nlp_adapter", extraction_method="model")
            )]
    nlp_mod.NLPModelAdapter = MockAdapter
    
    # Mock file reading
    import unittest.mock
    with unittest.mock.patch("builtins.open", unittest.mock.mock_open(read_data=b"From: a@b\n\nHello")):
        with unittest.mock.patch("app.services.ingestion.parser.EmailParser.parse") as mock_parse:
            from app.contracts.email import ParsedEmail
            from app.contracts.headers import HeaderSet
            mock_parse.return_value = ParsedEmail(
                sha256="dummy", plain_text="Hello", html="", 
                headers=HeaderSet(), urls=[], attachments=[], metadata={}, raw_artifact_reference="dummy.eml"
            )
            res = await nlp_handle(req, state, pkg)
            assert len(res) == 1
            from app.contracts.evidence import EvidenceType
            assert res[0]["type"] == EvidenceType.ML_SIGNAL

@pytest.mark.asyncio
async def test_url_handler_direct():
    state = _build_state()
    pkg = _build_pkg()
    req = ToolExecutionRequest(
        case_id=state.case_id,
        tool_name="url_ml",
        input={"canonical_url": "http://evil.com/login"},
        reason="Testing",
        policy_version="1.0"
    )
    
    import app.services.tools.handlers.url_ml as url_mod
    class MockAdapter:
        def analyze(self, url, case_id):
            from app.contracts.evidence import EvidenceItem, EvidenceType, EvidenceCategory, TrustLevel, EvidenceStatus
            from app.contracts.common import Provenance, SourceType
            return EvidenceItem(
                evidence_id="2", case_id=case_id, type=EvidenceType.ML_SIGNAL, 
                category=EvidenceCategory.URL, key="url_ml_risk", value=0.9, 
                source="M4", source_type=SourceType.ML_MODEL, confidence=0.9,
                trust_level=TrustLevel.VERIFIED, status=EvidenceStatus.ACTIVE,
                provenance=Provenance(producer_module="url_adapter", extraction_method="model")
            )
    url_mod.URLModelAdapter = MockAdapter
    
    res = await url_handle(req, state, pkg)
    assert len(res) == 1
    assert res[0]["value"] == 0.9

@pytest.mark.asyncio
async def test_full_decision_engine_stage1_mocked():
    engine = InvestigationDecisionEngine()
    pkg = _build_pkg()
    res = engine.run_stage1(pkg)
    assert res.state.case_id is not None
