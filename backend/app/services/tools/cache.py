"""
services/tools/cache.py

TTLCache layer for tool execution results.
Designed for drop-in Redis replacement later.
"""

from __future__ import annotations

import logging
from typing import Any, Optional, Protocol, Tuple

from cachetools import TTLCache

logger = logging.getLogger(__name__)

# Key format: (indicator_value, indicator_type, provider_id)
# e.g. ("http://example.com", "URL", "virustotal_lookup")
CacheKey = Tuple[str, str, str]

class ToolCacheProtocol(Protocol):
    def get(self, key: CacheKey) -> Optional[dict[str, Any]]: ...
    def set(self, key: CacheKey, value: dict[str, Any], ttl_seconds: int) -> None: ...

class MemoryToolCache:
    """In-memory TTLCache implementation."""
    
    def __init__(self, maxsize: int = 10000):
        # We use a large shared cache. Items have individual TTLs, but cachetools
        # applies the TTLCache global TTL. To support per-item TTL, we wrap the
        # cache tools or just use a max TTL. For Stage 3 MVP, we use a simple
        # dict with expiration timestamps if we want exact per-item TTL, but
        # cachetools doesn't natively support per-item TTL easily in a single cache.
        # Let's implement a custom minimal TTL dict for accurate per-item TTLs.
        self._cache: dict[CacheKey, tuple[float, dict[str, Any]]] = {}
        self._maxsize = maxsize
        
    def get(self, key: CacheKey) -> Optional[dict[str, Any]]:
        import time
        if key in self._cache:
            expire_at, value = self._cache[key]
            if time.time() < expire_at:
                return value
            else:
                del self._cache[key]
        return None
        
    def set(self, key: CacheKey, value: dict[str, Any], ttl_seconds: int) -> None:
        import time
        if ttl_seconds <= 0:
            return
            
        # Very basic LRU/cleanup if maxsize exceeded
        if len(self._cache) >= self._maxsize:
            # Delete expired first
            now = time.time()
            expired = [k for k, (exp, _) in self._cache.items() if exp <= now]
            for k in expired:
                del self._cache[k]
            # If still full, clear arbitrary items (or just clear all for MVP)
            if len(self._cache) >= self._maxsize:
                self._cache.clear()
                
        expire_at = time.time() + ttl_seconds
        self._cache[key] = (expire_at, value)

# Singleton instance
_TOOL_CACHE = MemoryToolCache()

def get_tool_cache() -> ToolCacheProtocol:
    """Get the active cache provider."""
    return _TOOL_CACHE
