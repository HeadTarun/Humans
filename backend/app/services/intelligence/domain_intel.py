"""
services/intelligence/domain_intel.py

RDAP / Whois Integration using whoisit.
"""

from __future__ import annotations

import logging
import whoisit
from typing import Any, Optional
from datetime import datetime, timezone
import dateutil.parser

logger = logging.getLogger(__name__)

# Initialize whoisit bootstrapping (usually done once)
try:
    whoisit.bootstrap()
    _RDAP_AVAILABLE = True
except Exception as e:
    logger.warning(f"Failed to bootstrap whoisit: {e}")
    _RDAP_AVAILABLE = False

class RDAPAdapter:
    def __init__(self):
        self.is_available = _RDAP_AVAILABLE
        
    def _parse_date(self, date_str: str) -> Optional[datetime]:
        if not date_str:
            return None
        try:
            return dateutil.parser.isoparse(date_str)
        except Exception:
            return None
            
    async def lookup_domain(self, domain: str) -> dict[str, Any]:
        """Returns raw parsed RDAP data."""
        if not self.is_available:
            return self._mock_result(domain)
            
        try:
            # whoisit is synchronous, so in a real async environment we'd run it in a threadpool.
            # For MVP, we just call it directly.
            result = whoisit.domain(domain)
            
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
                "raw_result": "available"
            }
        except Exception as e:
            return {"error": str(e)}

    def _mock_result(self, domain: str) -> dict[str, Any]:
        return {
            "registration_date": datetime(2020, 1, 1, tzinfo=timezone.utc),
            "expiration_date": datetime(2030, 1, 1, tzinfo=timezone.utc),
            "raw_result": "mocked"
        }
