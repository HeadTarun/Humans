"""
services/intelligence/domain_intel.py

Bounded RDAP integration for domain intelligence.
"""

from __future__ import annotations

import logging
import os
import httpx
import re
from typing import Any, Optional
from datetime import datetime
import dateutil.parser

from app.contracts.ioc import IOCType
from app.contracts.provider_result import ProviderResult

logger = logging.getLogger(__name__)

class RDAPAdapter:
    _DOMAIN_RE = re.compile(
        r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
        re.IGNORECASE,
    )

    def __init__(self, client: Optional[httpx.AsyncClient] = None):
        self.base_url = os.getenv("RDAP_BASE_URL", "https://rdap.org/domain").rstrip("/")
        self.timeout_seconds = float(os.getenv("RDAP_TIMEOUT_SECONDS", "2.0"))
        self._client = client
        
    def _parse_date(self, date_str: str) -> Optional[datetime]:
        if not date_str:
            return None
        try:
            return dateutil.parser.isoparse(date_str)
        except Exception:
            return None
            
    async def lookup_domain(self, domain: str) -> dict[str, Any]:
        """Returns raw parsed RDAP data."""
        normalized_domain = domain.strip().rstrip(".").lower()
        try:
            normalized_domain = normalized_domain.encode("idna").decode("ascii")
        except UnicodeError:
            return {"error": "invalid domain"}
        if not self._DOMAIN_RE.fullmatch(normalized_domain):
            return {"error": "invalid domain"}

        owns_client = self._client is None
        client = self._client or httpx.AsyncClient(
            timeout=self.timeout_seconds,
            follow_redirects=True,
        )
        try:
            # rdap.org intentionally responds with 302 to the authoritative
            # registry for many TLDs (e.g. .com -> Verisign). Following that
            # standard redirect is required for valid domains to resolve.
            response = await client.get(f"{self.base_url}/{normalized_domain}")
            response.raise_for_status()
            result = response.json()
            if not isinstance(result, dict):
                return {"error": "invalid RDAP response"}
            
            # Extract key dates
            events = result.get("events", [])
            registration_date = None
            expiration_date = None
            
            for event in events:
                if event.get("eventAction") == "registration":
                    registration_date = self._parse_date(event.get("eventDate"))
                elif event.get("eventAction") == "expiration":
                    expiration_date = self._parse_date(event.get("eventDate"))
                    
            return {
                "registration_date": registration_date,
                "expiration_date": expiration_date,
                "raw_result": "available",
            }
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            logger.warning("RDAP lookup failed for %s: %s", normalized_domain, type(exc).__name__)
            return {"error": "RDAP lookup unavailable"}
        finally:
            if owns_client:
                await client.aclose()

    async def lookup_provider_result(self, domain: str) -> ProviderResult:
        """Provider-neutral RDAP result; retained alongside the legacy raw method."""
        result = await self.lookup_domain(domain)
        if "error" in result:
            raise RuntimeError(str(result["error"]).upper().replace(" ", "_"))
        registration_date = result.get("registration_date")
        age_days = None
        if registration_date:
            now = datetime.now(registration_date.tzinfo) if registration_date.tzinfo else datetime.utcnow()
            age_days = max(0, (now - registration_date).days)
        return ProviderResult(
            provider_name="RDAP", indicator_value=domain, indicator_type=IOCType.DOMAIN,
            features={
                "domain_age_days": age_days,
                "domain_is_newly_registered": age_days is not None and age_days < 30,
                "domain_registration_date": registration_date.isoformat() if registration_date else None,
                "domain_expiration_date": result.get("expiration_date").isoformat() if result.get("expiration_date") else None,
            },
            raw_result_reference="rdap:domain",
        )
