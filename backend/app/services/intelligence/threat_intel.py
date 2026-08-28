"""
services/intelligence/threat_intel.py

VirusTotal v3 adapter implementing ThreatIntelProvider.
"""

from __future__ import annotations

import os
import httpx
import logging
import base64
from typing import Optional, Dict, Any

from app.contracts.threat_intel import ThreatIntelProvider, ThreatIntelResult, ThreatIntelVerdict
from app.contracts.ioc import IOCType

logger = logging.getLogger(__name__)

class VirusTotalAdapter(ThreatIntelProvider):
    """Adapter for VirusTotal API v3."""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY")
        self.base_url = "https://www.virustotal.com/api/v3"
        self._client = httpx.AsyncClient(
            headers={"x-apikey": self.api_key} if self.api_key else {},
            timeout=10.0
        )
        
    def _parse_verdict(self, stats: dict[str, int]) -> ThreatIntelVerdict:
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        
        if malicious >= 3:
            return ThreatIntelVerdict.MALICIOUS
        if malicious > 0 or suspicious >= 2:
            return ThreatIntelVerdict.SUSPICIOUS
        if harmless > 0 and malicious == 0 and suspicious == 0:
            return ThreatIntelVerdict.CLEAN
        return ThreatIntelVerdict.UNKNOWN

    async def lookup_url(self, url: str) -> ThreatIntelResult:
        if not self.api_key:
            return self._mock_result(url, IOCType.URL)
            
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        try:
            resp = await self._client.get(f"{self.base_url}/urls/{url_id}")
            
            if resp.status_code == 404:
                return ThreatIntelResult(
                    provider="VirusTotal", indicator=url, indicator_type=IOCType.URL,
                    verdict=ThreatIntelVerdict.UNKNOWN
                )
            if resp.status_code == 429:
                # Rate limited
                return ThreatIntelResult(
                    provider="VirusTotal", indicator=url, indicator_type=IOCType.URL,
                    verdict=ThreatIntelVerdict.ERROR, error="RATE_LIMITED"
                )
            resp.raise_for_status()
            
            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            verdict = self._parse_verdict(stats)
            
            return ThreatIntelResult(
                provider="VirusTotal", indicator=url, indicator_type=IOCType.URL,
                verdict=verdict, raw_result_reference=str(stats)
            )
        except Exception as e:
            logger.error(f"VT URL lookup error: {e}")
            return ThreatIntelResult(
                provider="VirusTotal", indicator=url, indicator_type=IOCType.URL,
                verdict=ThreatIntelVerdict.ERROR, error=str(e)
            )

    async def lookup_hash(self, file_hash: str) -> ThreatIntelResult:
        if not self.api_key:
            return self._mock_result(file_hash, IOCType.HASH_SHA256)
            
        try:
            resp = await self._client.get(f"{self.base_url}/files/{file_hash}")
            if resp.status_code == 404:
                return ThreatIntelResult(
                    provider="VirusTotal", indicator=file_hash, indicator_type=IOCType.HASH_SHA256,
                    verdict=ThreatIntelVerdict.UNKNOWN
                )
            if resp.status_code == 429:
                return ThreatIntelResult(
                    provider="VirusTotal", indicator=file_hash, indicator_type=IOCType.HASH_SHA256,
                    verdict=ThreatIntelVerdict.ERROR, error="RATE_LIMITED"
                )
            resp.raise_for_status()
            
            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            verdict = self._parse_verdict(stats)
            
            return ThreatIntelResult(
                provider="VirusTotal", indicator=file_hash, indicator_type=IOCType.HASH_SHA256,
                verdict=verdict, raw_result_reference=str(stats)
            )
        except Exception as e:
            return ThreatIntelResult(
                provider="VirusTotal", indicator=file_hash, indicator_type=IOCType.HASH_SHA256,
                verdict=ThreatIntelVerdict.ERROR, error=str(e)
            )
            
    def _mock_result(self, indicator: str, ioc_type: IOCType) -> ThreatIntelResult:
        """Fallback for testing without API keys."""
        if "malicious" in indicator:
            v = ThreatIntelVerdict.MALICIOUS
        elif "suspicious" in indicator:
            v = ThreatIntelVerdict.SUSPICIOUS
        else:
            v = ThreatIntelVerdict.CLEAN
        return ThreatIntelResult(
            provider="VirusTotal", indicator=indicator, indicator_type=ioc_type, verdict=v
        )
        
    # We must implement the sync protocol methods since the original Protocol is sync.
    # However, since Stage 3 is moving to async executor, we will just stub the sync ones
    # or the handler will use the async ones directly.
    def lookup_ip(self, ip_address: str) -> ThreatIntelResult:
        raise NotImplementedError("Use async")
    def lookup_domain(self, domain: str) -> ThreatIntelResult:
        raise NotImplementedError("Use async")

