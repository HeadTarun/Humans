"""
services/tools/deduplicator.py

DeduplicationEngine coordinates canonicalization of IOCs to minimize
expensive external tool calls.
"""

from __future__ import annotations

from typing import Iterable, Set

from app.contracts.ioc import IOC, IOCType
from app.contracts.url_canonical import URLCanonicalSet

class DeduplicationEngine:
    """
    Handles IOC deduplication logic.
    For Stage 3 MVP, handles URL deduplication using the URLCanonicalSet.
    """
    
    def get_unique_urls(self, urls: Iterable[str]) -> URLCanonicalSet:
        """
        Deduplicates a list of raw URLs into a URLCanonicalSet.
        This normally calls the url_canonicalizer handler.
        For now, we import it directly or assume the executor does it.
        This is a helper for the executor.
        """
        # The executor should call the url_canonicalizer tool.
        # This engine provides helper methods if needed.
        pass
    
    def filter_unique_iocs(self, iocs: list[IOC]) -> list[IOC]:
        """
        Filter out exact duplicate IOCs based on type and value.
        """
        seen: Set[tuple[IOCType, str]] = set()
        unique: list[IOC] = []
        
        for ioc in iocs:
            key = (ioc.ioc_type, ioc.value)
            if key not in seen:
                seen.add(key)
                unique.append(ioc)
                
        return unique
