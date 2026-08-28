"""
services/tools/handlers/abuseipdb_lookup.py

AbuseIPDB Tool Handler (Level 2).
"""

from __future__ import annotations

import logging
from typing import Any

from app.contracts.investigation import InvestigationState
from app.contracts.tool import ToolExecutionRequest
from app.services.intelligence.ip_intel import AbuseIPDBAdapter
from app.contracts.threat_intel import ThreatIntelVerdict

logger = logging.getLogger(__name__)

async def handle(
    request: ToolExecutionRequest, 
    state: InvestigationState,
    package: Any = None
) -> dict[str, Any]:
    
    adapter = AbuseIPDBAdapter()
    ip_str = request.input.get("ip_address")
    
    if not ip_str:
        raise ValueError("abuseipdb_lookup requires 'ip_address' in input")
        
    result = await adapter.lookup_ip(ip_str)
    
    if "error" in result:
        if result["error"] == "RATE_LIMITED":
            raise RuntimeError("RATE_LIMITED")
        raise RuntimeError(f"FAILED: {result['error']}")
        
    return {
        "provider_name": "AbuseIPDB",
        "indicator_value": ip_str,
        "indicator_type": "IP",
        "verdict": result["verdict"],
        "provider_score": result["score"],
        "features": {
            "abuseipdb_total_reports": result["total_reports"],
            "abuseipdb_country": result["country"]
        }
    }
