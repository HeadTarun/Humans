"""
services/tools/handlers/geoip_lookup.py

GeoIP Lookup Tool (Level 0).
Delegates to the provider-neutral GeoLocationManager rather than directly
depending on a single local database or agent/tool implementation.
"""

from __future__ import annotations

import logging
from typing import Any

from app.contracts.investigation import InvestigationState
from app.contracts.tool import ToolExecutionRequest
from app.services.intelligence.geoip import get_geolocation_manager

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
        
    max_external_calls = request.input.get("max_external_calls")
    result = await get_geolocation_manager().lookup(
        str(ip_str), max_external_calls=int(max_external_calls) if max_external_calls is not None else None
    )
    # A structured unavailable result is evidence about enrichment state, not
    # an exception that aborts the rest of an email investigation.
    features = {
        "geolocation_success": result.success,
        "geolocation_source": result.source,
        "geolocation_provider": result.provider,
        "geolocation_error": result.error,
        "ip_country": result.country,
        "ip_country_code": result.country_code,
        "ip_region": result.region,
        "ip_city": result.city,
        "ip_latitude": result.latitude,
        "ip_longitude": result.longitude,
        "ip_timezone": result.timezone,
        "ip_asn": result.asn,
        "ip_isp": result.isp,
        "ip_organization": result.organization,
        "ip_is_private": result.is_private,
        "ip_is_reserved": result.is_reserved,
        "ip_is_loopback": result.is_loopback,
        "ip_is_link_local": result.is_link_local,
        "ip_is_multicast": result.is_multicast,
        "ip_is_unspecified": result.is_unspecified,
    }
    return {
        "_execution": {
            "external_calls_made": result.external_calls_made,
            "provider": result.provider,
            "cache_hit": result.source == "cache",
        },
        "provider_name": result.provider or "GeoLocationManager",
        "indicator_value": result.ip,
        "indicator_type": "IP",
        "cache_status": "HIT" if result.source == "cache" else "MISS",
        "raw_result_reference": f"geolocation:{result.provider or result.source}",
        "features": {key: value for key, value in features.items() if value is not None},
    }
