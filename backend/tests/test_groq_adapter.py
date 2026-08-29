import pytest
from app.services.ml.groq_adapter import GroqAdapter
from app.contracts.groq import ReasoningInput, EvidenceSnapshot

@pytest.mark.asyncio
async def test_groq_adapter_mock():
    adapter = GroqAdapter(api_key="dummy_key")
    
    req = ReasoningInput(
        case_id="case_123",
        task="explain_risk",
        evidence_snapshot=EvidenceSnapshot(facts=[{"evidence_id": "ev1"}]),
        hypotheses=[],
        unresolved_conflicts=[],
        investigation_path=[],
        policy_version="1.0",
        evidence_snapshot_hash="hash123"
    )
    
    res = await adapter.analyze(req)
    
    assert res.summary.startswith("Mock analysis")
    assert "ev1" in res.referenced_evidence_ids
    assert res.requested_action == "NO_ACTION"
