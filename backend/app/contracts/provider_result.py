"""
contracts/provider_result.py

Provider-neutral intermediate contract for external adapter results.
This acts as the bridge between raw JSON (from VT, AbuseIPDB, etc.)
and EvidenceItem generation in the EvidenceNormaliser.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import Field

from .common import BaseContract, utcnow
from .ioc import IOCType
from .threat_intel import ThreatIntelVerdict


class ProviderResult(BaseContract):
    """
    Standardized result from any external provider adapter.
    This prevents provider-specific schema from leaking into the Risk Engine.
    """
    provider_name: str = Field(..., description="e.g. 'VirusTotal', 'AbuseIPDB', 'GeoLite2'")
    indicator_value: str
    indicator_type: IOCType
    
    # Generic reputation fields
    verdict: Optional[ThreatIntelVerdict] = None
    provider_score: Optional[int] = Field(default=None, description="Raw provider score (e.g. VT positives, AbuseIPDB confidence)")
    
    # Normalized features extracted from the provider response
    features: dict[str, Any] = Field(
        default_factory=dict,
        description="Key-value pairs to become EvidenceItems (e.g. {'ip_country': 'US', 'domain_age_days': 15})"
    )
    
    # Optional original payload for forensic archiving
    raw_payload: Optional[dict[str, Any]] = None
    
    retrieved_at: datetime = Field(default_factory=utcnow)
