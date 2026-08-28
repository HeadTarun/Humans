"""
services/tools/handlers/geoip_lookup.py

GeoIP Lookup Tool (Level 2).
Uses the local GeoLite2 database to resolve ASN and Country.
Returns ProviderResult for the Normaliser.
"""

from __future__ import annotations

import logging
from typing import Any

from app.contracts.investigation import InvestigationState
from app.contracts.tool import ToolExecutionRequest, ToolExecutionStatus
from app.services.intelligence.geoip import get_geoip_adapter

logger = logging.getLogger(__name__)

async def handle(
    request: ToolExecutionRequest, 
    state: InvestigationState,
    package: Any = None
) -> dict[str, Any]:
    """
    Input: {"ip_address": "1.2.3.4"}
    """
    ip_str = request.input.get("ip_address")
    if not ip_str:
        raise ValueError("geoip_lookup requires 'ip_address' in input")
        
    adapter = get_geoip_adapter()
    
    # If DB is missing (which it likely is without MaxMind credentials),
    # gracefully skip rather than failing the whole pipeline.
    if not adapter.is_available():
        raise RuntimeError("SKIPPED: GeoLite2 database is not available on this environment")
        
    result_data = adapter.lookup_ip(ip_str)
    
    if result_data is None:
        raise RuntimeError("FAILED: Error querying GeoLite2 database")
        
    return {
        "provider_name": "GeoLite2",
        "indicator_value": ip_str,
        "indicator_type": "IP",
        "features": result_data
    }
