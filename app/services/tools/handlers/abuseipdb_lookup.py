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
        
    return (await adapter.lookup_ip(ip_str)).model_dump(mode="json")
