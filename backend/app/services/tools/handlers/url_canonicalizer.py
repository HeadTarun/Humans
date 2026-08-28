"""
services/tools/handlers/url_canonicalizer.py

URL Canonicalizer Tool (Level 0).
Pre-processor that normalizes and deduplicates URLs from the evidence package
to minimize downstream API calls.
"""

from __future__ import annotations

import logging
import tldextract
from typing import Any, Optional
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

from app.contracts.investigation import InvestigationState
from app.contracts.tool import ToolExecutionRequest
from app.contracts.url_canonical import URLCanonical, URLCanonicalSet
from app.services.evidence.models import EmailEvidencePackage

logger = logging.getLogger(__name__)

# Common tracking parameters to strip during canonicalization
_TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "msclkid", "mc_eid", "_hsenc", "_hsmi",
}

def _canonicalize_url(raw_url: str) -> str:
    """Normalize a URL and strip common tracking parameters/fragments."""
    try:
        parsed = urlparse(raw_url)
        
        # 1. Normalize scheme (default to http if missing but has netloc)
        scheme = parsed.scheme.lower()
        
        # 2. Normalize netloc (lowercase, strip default ports)
        netloc = parsed.netloc.lower()
        if netloc.endswith(":80") and scheme == "http":
            netloc = netloc[:-3]
        elif netloc.endswith(":443") and scheme == "https":
            netloc = netloc[:-4]
            
        # 3. Clean path (remove trailing slash for consistency, unless it's just "/")
        path = parsed.path
        if len(path) > 1 and path.endswith("/"):
            path = path.rstrip("/")
            
        # 4. Strip tracking query parameters
        query_items = parse_qsl(parsed.query, keep_blank_values=True)
        filtered_query = [(k, v) for k, v in query_items if k.lower() not in _TRACKING_PARAMS]
        query = urlencode(filtered_query)
        
        # 5. Drop fragment
        fragment = ""
        
        return urlunparse((scheme, netloc, path, parsed.params, query, fragment))
    except Exception:
        # If parsing fails entirely, return as-is
        return raw_url

def _is_shortener(domain: str) -> bool:
    """Check if domain is a known URL shortener."""
    shorteners = {"bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly"}
    return domain in shorteners

async def handle(
    request: ToolExecutionRequest, 
    state: InvestigationState, 
    package: Optional[EmailEvidencePackage] = None
) -> dict[str, Any]:
    """
    Handle URL canonicalization.
    Unlike standard tools, this uses the package to find all URLs and groups them.
    """
    if not package:
        raise ValueError("url_canonicalizer requires the EmailEvidencePackage")
        
    canonical_map: dict[str, URLCanonical] = {}
    total_original = 0
    
    for url_ind in package.urls:
        total_original += 1
        canon_str = _canonicalize_url(url_ind.raw_url)
        
        if canon_str not in canonical_map:
            ext = tldextract.extract(canon_str)
            domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
            
            canonical_map[canon_str] = URLCanonical(
                canonical_url=canon_str,
                original_urls=[url_ind.raw_url],
                original_evidence_ids=[url_ind.indicator_id],
                domain=domain,
                is_shortened=_is_shortener(domain)
            )
        else:
            # Update existing canonical grouping
            c = canonical_map[canon_str]
            if url_ind.raw_url not in c.original_urls:
                c.original_urls.append(url_ind.raw_url)
            if url_ind.indicator_id not in c.original_evidence_ids:
                c.original_evidence_ids.append(url_ind.indicator_id)
                
    result_set = URLCanonicalSet(
        canonical_urls=list(canonical_map.values()),
        total_original_urls=total_original,
        total_canonical_urls=len(canonical_map)
    )
    
    return result_set.model_dump()
