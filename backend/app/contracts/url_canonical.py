"""
contracts/url_canonical.py

Contracts for URL canonicalization and deduplication.

The url_canonicalizer tool acts as a pre-processor, outputting a
URLCanonicalSet instead of EvidenceItems. This allows the DeduplicationEngine
to map visually distinct URLs (e.g., varying fragments or harmless tracking
parameters) to the same underlying logical endpoint before dispatching
expensive intelligence lookups.
"""

from __future__ import annotations

from typing import Optional

from pydantic import Field

from .common import BaseContract, EvidenceId


class URLCanonical(BaseContract):
    """
    A deduplicated, canonical form of a URL.
    Used by the deduplication engine to avoid redundant lookups.
    """
    
    canonical_url: str = Field(..., description="The normalized, deduplicated URL string")
    original_urls: list[str] = Field(
        ..., description="The raw URLs from the email that mapped to this canonical form"
    )
    original_evidence_ids: list[EvidenceId] = Field(
        ..., description="The URLIndicator evidence_ids that mapped to this canonical form"
    )
    domain: str = Field(..., description="The normalized domain of the canonical URL")
    is_shortened: bool = Field(
        default=False, description="True if the URL appears to be a link shortener (e.g. bit.ly)"
    )
    # The deduplicator may tag certain URLs to bypass cache (e.g., time-sensitive redirects)
    bypass_cache: bool = Field(default=False)


class URLCanonicalSet(BaseContract):
    """
    The output of the url_canonicalizer tool.
    Groups all extracted URLs into their minimal canonical set.
    """
    
    canonical_urls: list[URLCanonical] = Field(default_factory=list)
    total_original_urls: int = Field(..., ge=0)
    total_canonical_urls: int = Field(..., ge=0)
    
    @property
    def deduplication_ratio(self) -> float:
        """Returns the ratio of original URLs to canonical URLs. (1.0 = no dedup)."""
        if self.total_canonical_urls == 0:
            return 0.0
        return self.total_original_urls / self.total_canonical_urls
