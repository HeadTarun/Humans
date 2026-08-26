"""
contracts/url.py

Keeps two concepts separate per §10:
  A. URL structural risk (URLStructuralFeatures -> feeds URL ML -> ML_SIGNAL)
  B. Known reputation (fetched separately via threat_intel.py -> THREAT_INTEL)
These must never be merged prematurely into one evidence item.
"""

from __future__ import annotations

from typing import Optional

from pydantic import Field

from .common import BaseContract


class URLRecord(BaseContract):
    url_id: str
    raw_url: str
    normalized_url: str
    domain: str
    tld: Optional[str] = None
    path: Optional[str] = None
    query_params: dict[str, str] = Field(default_factory=dict)
    is_shortened: bool = False
    contains_ip: bool = False
    punycode: bool = False
    extraction_context: Optional[str] = Field(
        default=None, description="e.g. 'body_text', 'html_href', 'html_form_action'"
    )


class URLStructuralFeatures(BaseContract):
    url_id: str
    length: int
    subdomain_count: int
    has_at_symbol: bool
    has_ip_literal: bool
    entropy: float
    suspicious_tld: bool
    homoglyph_suspected: bool
