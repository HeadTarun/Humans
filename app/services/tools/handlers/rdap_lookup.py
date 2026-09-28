"""
services/tools/handlers/rdap_lookup.py

RDAP Domain Lookup Tool (Level 2).
"""

from __future__ import annotations

import logging
from typing import Any

from app.contracts.investigation import InvestigationState
from app.contracts.tool import ToolExecutionRequest
from app.services.intelligence.domain_intel import RDAPAdapter

logger = logging.getLogger(__name__)

async def handle(
    request: ToolExecutionRequest, 
    state: InvestigationState,
    package: Any = None
) -> dict[str, Any]:
    
    adapter = RDAPAdapter()
    domain = request.input.get("domain")
    
    if not domain:
        raise ValueError("rdap_lookup requires 'domain' in input")
        
    return (await adapter.lookup_provider_result(domain)).model_dump(mode="json")
