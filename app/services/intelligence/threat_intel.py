"""
services/intelligence/threat_intel.py

VirusTotal v3 adapter implementing ThreatIntelProvider.
"""

from __future__ import annotations

import httpx
import logging
import base64
from typing import Optional

from app.contracts.provider_result import ProviderResult
from app.contracts.threat_intel import ThreatIntelVerdict
from app.contracts.ioc import IOCType
from app.core.config import settings
from app.core.ssrf_guard import SSRFViolation, is_safe_ip

logger = logging.getLogger(__name__)

class VirusTotalAdapter:
    """Adapter for VirusTotal API v3."""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key if api_key is not None else settings.VIRUSTOTAL_API_KEY
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

    async def _lookup(self, indicator: str, indicator_type: IOCType, endpoint: str) -> ProviderResult:
        if not self.api_key:
            raise RuntimeError("PROVIDER_NOT_CONFIGURED")
        try:
            resp = await self._client.get(f"{self.base_url}/{endpoint}")
            if resp.status_code == 404:
                return ProviderResult(provider_name="VirusTotal", indicator_value=indicator,
                                      indicator_type=indicator_type, verdict=ThreatIntelVerdict.UNKNOWN,
                                      raw_result_reference="virustotal:v3:not_found")
            if resp.status_code == 429:
                raise RuntimeError("RATE_LIMITED")
            if resp.status_code in (401, 403):
                raise RuntimeError("PROVIDER_NOT_CONFIGURED")
            resp.raise_for_status()
            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            if not isinstance(stats, dict):
                raise RuntimeError("MALFORMED_PROVIDER_RESPONSE")
            verdict = self._parse_verdict(stats)
            return ProviderResult(
                provider_name="VirusTotal", indicator_value=indicator, indicator_type=indicator_type,
                verdict=verdict, provider_score=float(stats.get("malicious", 0)),
                features={"virustotal_malicious": stats.get("malicious", 0),
                          "virustotal_suspicious": stats.get("suspicious", 0)},
                raw_result_reference="virustotal:v3:last_analysis_stats",
            )
        except RuntimeError:
            raise
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            logger.warning("VirusTotal lookup failed for %s: %s", indicator, type(exc).__name__)
            raise RuntimeError("PROVIDER_UNAVAILABLE") from exc

    async def lookup_url(self, url: str) -> ProviderResult:
        # SSRF protection: validate URL before submitting to VirusTotal
        try:
            from app.core.ssrf_guard import validate_url as _validate_url
            _validate_url(url, resolve_dns=False)  # DNS resolution is optional for VT submission
        except Exception:
            raise RuntimeError("SSRF_BLOCKED_URL")
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        return await self._lookup(url, IOCType.URL, f"urls/{url_id}")

    async def lookup_hash(self, file_hash: str, ioc_type: IOCType = IOCType.HASH_SHA256) -> ProviderResult:
        return await self._lookup(file_hash, ioc_type, f"files/{file_hash}")

    async def lookup_ip(self, ip_address: str) -> ProviderResult:
        # SSRF protection: never submit private/internal IPs to VirusTotal
        if not is_safe_ip(ip_address):
            raise RuntimeError("SSRF_BLOCKED_IP")
        return await self._lookup(ip_address, IOCType.IP, f"ip_addresses/{ip_address}")

    async def lookup_domain(self, domain: str) -> ProviderResult:
        return await self._lookup(domain, IOCType.DOMAIN, f"domains/{domain}")


