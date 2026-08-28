"""
services/tools/handlers/rdap_lookup.py

RDAP Domain Lookup Tool (Level 2).
"""

from __future__ import annotations

import logging
from typing import Any
from datetime import datetime, timezone

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
        
    result = await adapter.lookup_domain(domain)
    
    if "error" in result:
        raise RuntimeError(f"FAILED: {result['error']}")
        
    reg_date = result.get("registration_date")
    age_days = None
    is_new = False
    
    if reg_date:
        now = datetime.now(timezone.utc)
        age_days = (now - reg_date).days
        is_new = age_days < 30
        
    return {
        "provider_name": "RDAP",
        "indicator_value": domain,
        "indicator_type": "DOMAIN",
        "features": {
            "domain_age_days": age_days,
            "domain_is_newly_registered": is_new,
            "domain_registration_date": reg_date.isoformat() if reg_date else None,
        }
    }
