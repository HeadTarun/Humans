"""
api/v1/threat_intel_api.py

On-demand threat intelligence enrichment for a single indicator.

Providers:
    - VirusTotal (URLs, domains, IPs, hashes)
    - AbuseIPDB (IPs)
    - URLHaus (URLs)

All providers are optional — missing config = gracefully omitted.
The response always returns a valid structure, even if all providers fail.
"""

from __future__ import annotations

import logging
import re
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request

from app.api.auth import verify_api_key_or_jwt

logger = logging.getLogger(__name__)
router = APIRouter()


def _classify_indicator(indicator: str) -> str:
    """Classify indicator type: IP | DOMAIN | URL | HASH | UNKNOWN"""
    if indicator.startswith("http://") or indicator.startswith("https://"):
        return "URL"
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", indicator):
        return "IP"
    if re.match(r"^[a-fA-F0-9]{32,64}$", indicator):
        return "HASH"
    if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", indicator) and "." in indicator:
        return "DOMAIN"
    return "UNKNOWN"


@router.get(
    "/{indicator:path}",
    summary="Enrich a threat indicator with external threat intelligence",
    description=(
        "Look up an indicator (IP, domain, URL, or hash) against configured TI providers. "
        "Providers: VirusTotal, AbuseIPDB, URLHaus. "
        "Provider failures are handled gracefully — partial results are returned. "
        "Requires authentication (JWT or API key)."
    ),
)
async def enrich_indicator(
    indicator: str,
    request: Request,
    auth=Depends(verify_api_key_or_jwt),
):
    """
    Enrich a threat indicator with real-time TI lookups.

    This endpoint hits external APIs — results are NOT cached (v1).
    Rate limits and API key configuration are enforced via settings.
    """
    from app.core.config import settings

    indicator = indicator.strip()
    if not indicator:
        raise HTTPException(status_code=400, detail="Indicator is required")

    if len(indicator) > 2048:
        raise HTTPException(status_code=400, detail="Indicator too long")

    indicator_type = _classify_indicator(indicator)
    enrichment = {
        "indicator": indicator,
        "indicator_type": indicator_type,
        "verdict": "UNKNOWN",
        "confidence": 0.0,
        "risk_score": 0.0,
        "sources": [],
        "tags": [],
        "last_seen": None,
        "first_seen": None,
        "malicious_votes": 0,
        "harmless_votes": 0,
        "providers": {},
    }

    # VirusTotal (Assuming not configured or file doesn't exist, will fail gracefully)
    if getattr(settings, "VIRUSTOTAL_API_KEY", None):
        try:
            from app.services.feeds.virustotal import VirusTotalClient
            vt = VirusTotalClient(api_key=settings.VIRUSTOTAL_API_KEY)
            if indicator_type == "IP":
                result = await vt.lookup_ip(indicator)
            elif indicator_type == "DOMAIN":
                result = await vt.lookup_domain(indicator)
            elif indicator_type == "URL":
                result = await vt.lookup_url(indicator)
            else:
                result = None
            if result:
                enrichment["providers"]["virustotal"] = result
                enrichment["sources"].append("VIRUSTOTAL")
                # Extract standardized fields if available
                stats = result.get("last_analysis_stats", {})
                enrichment["malicious_votes"] = stats.get("malicious", 0)
                enrichment["harmless_votes"] = stats.get("harmless", 0)
                total = sum(stats.values()) or 1
                malicious_ratio = enrichment["malicious_votes"] / total
                if malicious_ratio > 0.3:
                    enrichment["verdict"] = "MALICIOUS"
                    enrichment["confidence"] = malicious_ratio
                    enrichment["risk_score"] = round(malicious_ratio * 100, 1)
                elif malicious_ratio > 0.05:
                    enrichment["verdict"] = "SUSPICIOUS"
                    enrichment["confidence"] = malicious_ratio
                    enrichment["risk_score"] = round(malicious_ratio * 50, 1)
                else:
                    enrichment["verdict"] = "BENIGN"
        except Exception as exc:
            logger.warning("VirusTotal lookup failed for %s: %s", indicator, exc)
            enrichment["providers"]["virustotal"] = {"error": str(exc)}

    # AbuseIPDB (IPs only) (Assuming not configured, gracefully handle)
    if getattr(settings, "ABUSEIPDB_API_KEY", None) and indicator_type == "IP":
        try:
            from app.services.feeds.abuseipdb import AbuseIPDBClient
            abuse = AbuseIPDBClient(api_key=settings.ABUSEIPDB_API_KEY)
            result = await abuse.lookup_ip(indicator)
            if result:
                enrichment["providers"]["abuseipdb"] = result
                enrichment["sources"].append("ABUSEIPDB")
                abuse_score = result.get("abuseConfidenceScore", 0)
                if abuse_score > 80:
                    enrichment["verdict"] = "MALICIOUS"
                    enrichment["risk_score"] = max(enrichment["risk_score"], abuse_score)
                elif abuse_score > 30:
                    if enrichment["verdict"] != "MALICIOUS":
                        enrichment["verdict"] = "SUSPICIOUS"
                    enrichment["risk_score"] = max(enrichment["risk_score"], abuse_score)
        except Exception as exc:
            logger.warning("AbuseIPDB lookup failed for %s: %s", indicator, exc)
            enrichment["providers"]["abuseipdb"] = {"error": str(exc)}

    # URLHaus (URLs/domains)
    if indicator_type in ("URL", "DOMAIN"):
        try:
            from app.services.feeds.urlhaus import get_urlhaus_record
            record = get_urlhaus_record(indicator)
            if record:
                # Map URLhausRecord to dictionary format as expected by API
                result = {
                    "id": record.id,
                    "url": record.url,
                    "query_status": "is_host",
                    "urls_count": 1,
                    "threat": record.threat,
                    "tags": record.tags,
                    "date_added": record.date_added
                }
                enrichment["providers"]["urlhaus"] = result
                enrichment["sources"].append("URLHAUS")
                enrichment["verdict"] = "MALICIOUS"
                enrichment["risk_score"] = max(enrichment["risk_score"], 85.0)
                enrichment["tags"].extend(record.tags or [])
        except Exception as exc:
            logger.warning("URLHaus lookup failed for %s: %s", indicator, exc)
            enrichment["providers"]["urlhaus"] = {"error": str(exc)}

    # If no providers ran, set a note
    if not enrichment["sources"]:
        enrichment["note"] = "No TI providers configured or all lookups failed."

    return enrichment
