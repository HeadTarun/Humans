"""
services/tools/handlers/virustotal_lookup.py

VirusTotal Tool Handler (Level 2).
"""

from __future__ import annotations

import logging
from typing import Any

from app.contracts.investigation import InvestigationState
from app.contracts.tool import ToolExecutionRequest, ToolExecutionStatus
from app.services.intelligence.threat_intel import VirusTotalAdapter
from app.contracts.ioc import IOCType
from app.contracts.threat_intel import ThreatIntelVerdict

logger = logging.getLogger(__name__)

async def handle(
    request: ToolExecutionRequest, 
    state: InvestigationState,
    package: Any = None
) -> dict[str, Any]:
    
    adapter = VirusTotalAdapter()
    
    indicator = request.input.get("indicator") or request.input.get("url") or request.input.get("hash")
    ioc_type_str = request.input.get("indicator_type", "URL")
    
    if not indicator:
        raise ValueError("virustotal_lookup requires an indicator in input")
        
    if ioc_type_str == "URL":
        result = await adapter.lookup_url(indicator)
    else:
        result = await adapter.lookup_hash(indicator)
        
    if result.verdict == ThreatIntelVerdict.ERROR:
        if result.error == "RATE_LIMITED":
            raise RuntimeError("RATE_LIMITED")
        raise RuntimeError(f"FAILED: {result.error}")
        
    return {
        "provider_name": "VirusTotal",
        "indicator_value": indicator,
        "indicator_type": ioc_type_str,
        "verdict": result.verdict,
        "features": {
            "virustotal_stats": result.raw_result_reference
        }
    }
