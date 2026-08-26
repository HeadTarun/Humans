"""
contracts/threat_intel.py

Provider-neutral interface (§11). The application depends on
ThreatIntelResult, never on a specific vendor's response shape.
Providers are swappable behind ThreatIntelProvider (implemented in the
service layer, not here — this module only defines the data contract).
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional, Protocol

from pydantic import Field

from .common import BaseContract, utcnow
from .ioc import IOCType


class ThreatIntelVerdict(str, Enum):
    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    CLEAN = "CLEAN"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"


class CacheStatus(str, Enum):
    HIT = "HIT"
    MISS = "MISS"
    STALE = "STALE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class ThreatIntelResult(BaseContract):
    provider: str
    indicator: str
    indicator_type: IOCType
    verdict: ThreatIntelVerdict
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    timestamp: datetime = Field(default_factory=utcnow)
    raw_result_reference: Optional[str] = Field(default=None, description="Pointer to the stored raw provider payload")
    error: Optional[str] = None
    cache_status: CacheStatus = CacheStatus.NOT_APPLICABLE


class ThreatIntelProvider(Protocol):
    """Interface every concrete provider adapter (VirusTotal, AbuseIPDB, ...) must implement."""

    def lookup_ip(self, ip_address: str) -> ThreatIntelResult: ...

    def lookup_domain(self, domain: str) -> ThreatIntelResult: ...

    def lookup_url(self, url: str) -> ThreatIntelResult: ...

    def lookup_hash(self, file_hash: str) -> ThreatIntelResult: ...
