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
        
    ioc_type_str = str(ioc_type_str).upper()
    if ioc_type_str == "URL":
        result = await adapter.lookup_url(indicator)
    elif ioc_type_str == "IP":
        result = await adapter.lookup_ip(indicator)
    elif ioc_type_str == "DOMAIN":
        result = await adapter.lookup_domain(indicator)
    else:
        result = await adapter.lookup_hash(indicator)
    return result.model_dump(mode="json")
