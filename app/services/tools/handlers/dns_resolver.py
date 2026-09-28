"""
services/tools/handlers/dns_resolver.py

DNS Resolver Tool (Level 1).
Resolves domains to check for live A/MX/TXT records.
"""

from __future__ import annotations

import logging
import asyncio
import dns.asyncresolver
from typing import Any

from app.contracts.investigation import InvestigationState
from app.contracts.tool import ToolExecutionRequest

logger = logging.getLogger(__name__)

async def resolve_record(domain: str, rdtype: str) -> list[str]:
    try:
        answers = await dns.asyncresolver.resolve(domain, rdtype, lifetime=2.0)
        return [rdata.to_text().strip('"') for rdata in answers]
    except Exception:
        return []

async def handle(
    request: ToolExecutionRequest, 
    state: InvestigationState,
    package: Any = None
) -> dict[str, Any]:
    """
    Input: {"domain": "example.com"}
    """
    domain = request.input.get("domain")
    if not domain:
        raise ValueError("dns_resolver requires 'domain' in input")
        
    # Gather A, MX, TXT concurrently
    a_task = resolve_record(domain, "A")
    mx_task = resolve_record(domain, "MX")
    txt_task = resolve_record(domain, "TXT")
    
    a_records, mx_records, txt_records = await asyncio.gather(a_task, mx_task, txt_task)
    
    resolves = len(a_records) > 0
    
    return {
        "provider_name": "dns_resolver",
        "indicator_value": domain,
        "indicator_type": "DOMAIN",
        "features": {
            "dns_resolves": resolves,
            "dns_has_mx": len(mx_records) > 0,
            "dns_has_txt": len(txt_records) > 0,
            "dns_a_records": a_records,
        }
    }
