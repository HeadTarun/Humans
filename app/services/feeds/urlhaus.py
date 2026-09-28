"""
services/feeds/urlhaus.py

URLhaus malware feed integration.
For Stage 3 MVP, this uses an in-memory dictionary acting as the local SQLite cache.
In production, a background daemon syncs the CSV feed every 5 minutes.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass(frozen=True)
class URLhausRecord:
    id: str
    url: str
    url_status: str
    threat: str
    tags: list[str]
    date_added: str

# Sample MVP Database
_URLHAUS_DB: dict[str, URLhausRecord] = {
    # Key: canonical URL
    "http://malicious.example.com/payload.exe": URLhausRecord(
        id="1001",
        url="http://malicious.example.com/payload.exe",
        url_status="online",
        threat="malware_download",
        tags=["exe", "payload"],
        date_added="2023-10-01 12:00:00",
    ),
    "https://phishing.example.com/login": URLhausRecord(
        id="1002",
        url="https://phishing.example.com/login",
        url_status="online",
        threat="phishing",
        tags=["credential_harvesting"],
        date_added="2023-10-02 14:00:00",
    ),
}

# Simulate the last sync time (useful for STALE checks)
_LAST_SYNC_TIME: datetime = datetime.now(timezone.utc)

def get_urlhaus_record(canonical_url: str) -> Optional[URLhausRecord]:
    """Query the local URLhaus cache for a canonical URL."""
    return _URLHAUS_DB.get(canonical_url)

def get_last_sync_time() -> datetime:
    """Return the time the feed was last synced."""
    return _LAST_SYNC_TIME
