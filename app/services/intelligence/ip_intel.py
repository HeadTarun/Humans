"""Provider-neutral AbuseIPDB IP reputation adapter."""

from __future__ import annotations

import httpx
import logging
from typing import Optional

from app.contracts.ioc import IOCType
from app.contracts.provider_result import ProviderResult
from app.contracts.threat_intel import ThreatIntelVerdict
from app.core.config import settings
from app.core.ssrf_guard import is_safe_ip, SSRFViolation

logger = logging.getLogger(__name__)

class AbuseIPDBAdapter:
    provider_name = "AbuseIPDB"

    def __init__(self, api_key: Optional[str] = None, client: Optional[httpx.AsyncClient] = None):
        self.api_key = api_key if api_key is not None else settings.ABUSEIPDB_API_KEY
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self._client = client
        
    async def lookup_ip(self, ip_address: str) -> ProviderResult:
        if not self.api_key:
            raise RuntimeError("PROVIDER_NOT_CONFIGURED")
        # SSRF protection: never send private/reserved IPs to external providers
        if not is_safe_ip(ip_address):
            raise RuntimeError("SSRF_BLOCKED_IP")
        owns_client = self._client is None
        client = self._client or httpx.AsyncClient(
            headers={"Key": self.api_key, "Accept": "application/json"}, timeout=10.0
        )
        try:
            resp = await client.get(f"{self.base_url}/check", params={"ipAddress": ip_address, "maxAgeInDays": 90})
            if resp.status_code == 429:
                raise RuntimeError("RATE_LIMITED")
            if resp.status_code in (401, 403):
                raise RuntimeError("PROVIDER_NOT_CONFIGURED")
            resp.raise_for_status()
            data = resp.json().get("data")
            if not isinstance(data, dict):
                raise RuntimeError("MALFORMED_PROVIDER_RESPONSE")
            score = float(data.get("abuseConfidenceScore", 0))
            
            if score >= 85:
                verdict = ThreatIntelVerdict.MALICIOUS
            elif score >= 25:
                verdict = ThreatIntelVerdict.SUSPICIOUS
            else:
                verdict = ThreatIntelVerdict.CLEAN
                
            return ProviderResult(
                provider_name=self.provider_name, indicator_value=ip_address, indicator_type=IOCType.IP,
                verdict=verdict, provider_score=score,
                features={"abuseipdb_total_reports": data.get("totalReports", 0),
                          "abuseipdb_country": data.get("countryCode")},
                raw_result_reference="abuseipdb:check:v2",
            )
        except RuntimeError:
            raise
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            logger.warning("AbuseIPDB lookup failed for %s: %s", ip_address, type(exc).__name__)
            raise RuntimeError("PROVIDER_UNAVAILABLE") from exc
        finally:
            if owns_client:
                await client.aclose()


