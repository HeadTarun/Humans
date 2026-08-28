"""
services/intelligence/ip_intel.py

AbuseIPDB adapter.
"""

from __future__ import annotations

import os
import httpx
import logging
from typing import Optional, Dict, Any

from app.contracts.threat_intel import ThreatIntelVerdict

logger = logging.getLogger(__name__)

class AbuseIPDBAdapter:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("ABUSEIPDB_API_KEY")
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self._client = httpx.AsyncClient(
            headers={"Key": self.api_key, "Accept": "application/json"} if self.api_key else {},
            timeout=10.0
        )
        
    async def lookup_ip(self, ip_address: str) -> dict[str, Any]:
        if not self.api_key:
            return self._mock_result(ip_address)
            
        try:
            resp = await self._client.get(f"{self.base_url}/check", params={"ipAddress": ip_address, "maxAgeInDays": 90})
            if resp.status_code == 429:
                return {"error": "RATE_LIMITED"}
            resp.raise_for_status()
            
            data = resp.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            
            if score >= 85:
                verdict = ThreatIntelVerdict.MALICIOUS
            elif score >= 25:
                verdict = ThreatIntelVerdict.SUSPICIOUS
            else:
                verdict = ThreatIntelVerdict.CLEAN
                
            return {
                "verdict": verdict,
                "score": score,
                "total_reports": data.get("totalReports", 0),
                "country": data.get("countryCode")
            }
        except Exception as e:
            return {"error": str(e)}

    def _mock_result(self, ip_address: str) -> dict[str, Any]:
        if ip_address.startswith("185.") or "malicious" in ip_address:
            return {"verdict": ThreatIntelVerdict.MALICIOUS, "score": 100, "total_reports": 50, "country": "RU"}
        return {"verdict": ThreatIntelVerdict.CLEAN, "score": 0, "total_reports": 0, "country": "US"}

