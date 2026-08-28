import pytest
import asyncio
from app.contracts.investigation import InvestigationState
from app.contracts.tool import ToolExecutionRequest
from app.services.tools.handlers.urlhaus_lookup import handle as urlhaus_handle
from app.contracts.threat_intel import ThreatIntelVerdict

@pytest.mark.asyncio
async def test_urlhaus_hit():
    req = ToolExecutionRequest(
        case_id="123",
        tool_name="urlhaus_feed_lookup",
        input={"canonical_url": "http://malicious.example.com/payload.exe"},
        reason="test",
        policy_version="1.0"
    )
    res = await urlhaus_handle(req, None)
    assert res["verdict"] == ThreatIntelVerdict.MALICIOUS
    assert res["features"]["urlhaus_threat"] == "malware_download"

@pytest.mark.asyncio
async def test_urlhaus_miss():
    req = ToolExecutionRequest(
        case_id="123",
        tool_name="urlhaus_feed_lookup",
        input={"canonical_url": "https://google.com"},
        reason="test",
        policy_version="1.0"
    )
    res = await urlhaus_handle(req, None)
    assert res["verdict"] == ThreatIntelVerdict.CLEAN

