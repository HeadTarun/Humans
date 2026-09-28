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
        Groups URLs by their canonical form (e.g. normalized path/params).
        """
        import logging
        from urllib.parse import urlparse, urlunparse
        from app.contracts.url_canonical import URLCanonical
        
        logger = logging.getLogger(__name__)
        
        canonical_map: dict[str, URLCanonical] = {}
        total_urls = 0
        
        for url in urls:
            total_urls += 1
            try:
                parsed = urlparse(url)
                if not parsed.scheme or not parsed.netloc:
                    raise ValueError(f"Missing scheme or netloc in URL: {url}")
                
                # Canonicalize by converting to lowercase and stripping fragments
                # (Simple canonicalization approach)
                domain = parsed.netloc.lower()
                canonical_url = urlunparse((
                    parsed.scheme.lower(),
                    domain,
                    parsed.path,
                    parsed.params,
                    parsed.query,
                    ""  # Strip fragment
                ))
                
                if canonical_url not in canonical_map:
                    canonical_map[canonical_url] = URLCanonical(
                        canonical_url=canonical_url,
                        original_urls=[url],
                        original_evidence_ids=[],
                        domain=domain,
                        is_shortened=False,
                    )
                else:
                    # URLCanonical is frozen; rebuild with appended URL
                    existing = canonical_map[canonical_url]
                    canonical_map[canonical_url] = URLCanonical(
                        canonical_url=canonical_url,
                        original_urls=list(existing.original_urls) + [url],
                        original_evidence_ids=list(existing.original_evidence_ids),
                        domain=domain,
                        is_shortened=existing.is_shortened,
                    )
            except Exception as e:
                logger.warning("Skipping malformed URL: %r. Error: %s", url, e)

        return URLCanonicalSet(
            canonical_urls=list(canonical_map.values()),
            total_original_urls=total_urls,
            total_canonical_urls=len(canonical_map)
        )

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


# Module-level convenience wrapper for backwards compatibility
_engine = DeduplicationEngine()


def get_unique_urls(urls: Iterable[str]) -> URLCanonicalSet:
    """
    Module-level wrapper: deduplicate a list of raw URL strings.

    Returns a URLCanonicalSet grouping identical canonical URLs together.
    Malformed URLs are skipped with a warning; they never raise.
    """
    return _engine.get_unique_urls(urls)


def filter_unique_iocs(iocs: list[IOC]) -> list[IOC]:
    """Module-level wrapper: filter duplicate IOCs by type+value."""
    return _engine.filter_unique_iocs(iocs)

