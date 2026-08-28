"""
services/feeds/tor_exits.py

Loads and caches known TOR exit nodes.
This allows the ip_classifier tool to identify TOR IPs.
"""

from __future__ import annotations

import logging
from typing import Set

logger = logging.getLogger(__name__)

# Pre-compiled list of common TOR exits for Stage 3 MVP.
# In a production environment, this would be periodically synced from
# the Tor Project bulk exit list (https://check.torproject.org/torbulkexitlist)
_TOR_EXITS_STR = [
    # Sample list for MVP testing
    "104.244.72.115", "104.244.76.13", "109.70.100.11", "109.70.100.22",
    "146.70.147.234", "162.247.74.200", "176.10.99.200", "185.220.101.1",
    "185.220.101.2", "185.220.101.3", "185.220.102.1", "185.220.102.2",
    "192.42.116.16", "199.19.120.1", "204.145.74.150", "204.85.191.30",
    "23.129.64.135", "51.159.21.213", "89.234.157.254", "93.95.227.227"
]

_TOR_EXITS: frozenset[str] = frozenset(_TOR_EXITS_STR)

def get_tor_exits() -> frozenset[str]:
    """Return the frozenset of known TOR exit IPs."""
    return _TOR_EXITS

def is_tor_exit(ip: str) -> bool:
    """Check if an IP is a known TOR exit node."""
    return ip in _TOR_EXITS
