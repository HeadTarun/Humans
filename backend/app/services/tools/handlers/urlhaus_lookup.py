"""
services/tools/handlers/urlhaus_lookup.py

URLhaus Feed Lookup Tool (Level 1).
Queries the local URLhaus SQLite cache for malware signals.
"""

from __future__ import annotations

import logging
from typing import Any
from datetime import datetime, timezone

from app.contracts.investigation import InvestigationState
from app.contracts.tool import ToolExecutionRequest
from app.services.feeds.urlhaus import get_urlhaus_record, get_last_sync_time
from app.contracts.threat_intel import ThreatIntelVerdict

logger = logging.getLogger(__name__)

async def handle(
    request: ToolExecutionRequest, 
    state: InvestigationState,
    package: Any = None
) -> dict[str, Any]:
    """
    Input: {"canonical_url": "http://example.com/payload.exe"}
    """
    canon_url = request.input.get("canonical_url")
    if not canon_url:
        raise ValueError("urlhaus_lookup requires 'canonical_url' in input")
        
    last_sync = get_last_sync_time()
    now = datetime.now(timezone.utc)
    age_seconds = (now - last_sync).total_seconds()
    
    # If feed is extremely stale (e.g., >2 hours), we might not want to 
    # rely on it for negative caching, but for MVP we'll just query it.
    
    record = get_urlhaus_record(canon_url)
    
    features = {}
    verdict = None
    
    if record:
        verdict = ThreatIntelVerdict.MALICIOUS
        features = {
            "urlhaus_threat": record.threat,
            "urlhaus_tags": record.tags,
            "urlhaus_status": record.url_status,
        }
    else:
        # Not found in feed -> CLEAN as far as URLhaus knows
        verdict = ThreatIntelVerdict.CLEAN
        
    return {
        "provider_name": "URLhaus",
        "indicator_value": canon_url,
        "indicator_type": "URL",
        "verdict": verdict,
        "features": features
    }
