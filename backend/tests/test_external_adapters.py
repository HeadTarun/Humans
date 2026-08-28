import pytest
from app.contracts.investigation import InvestigationState
from app.contracts.tool import ToolExecutionRequest
from app.services.tools.handlers.virustotal_lookup import handle as vt_handle
from app.services.tools.handlers.abuseipdb_lookup import handle as abuse_handle
from app.contracts.threat_intel import ThreatIntelVerdict

@pytest.mark.asyncio
async def test_vt_lookup_mocked():
    req = ToolExecutionRequest(
        case_id="123",
        tool_name="virustotal_lookup",
        input={"indicator": "http://malicious.example.com", "indicator_type": "URL"},
        reason="test",
        policy_version="1.0"
    )
    res = await vt_handle(req, None)
    assert res["verdict"] == ThreatIntelVerdict.MALICIOUS

@pytest.mark.asyncio
async def test_abuseipdb_mocked():
    req = ToolExecutionRequest(
        case_id="123",
        tool_name="abuseipdb_lookup",
        input={"ip_address": "185.1.2.3"},
        reason="test",
        policy_version="1.0"
    )
    res = await abuse_handle(req, None)
    assert res["verdict"] == ThreatIntelVerdict.MALICIOUS
    assert res["provider_score"] == 100

