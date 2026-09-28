"""
services/feeds/cloud_cidrs.py

Loads and caches known Cloud Provider CIDRs (AWS, GCP, Azure, Oracle).
This allows the ip_classifier tool to identify datacenter IPs.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Set

logger = logging.getLogger(__name__)

# Pre-compiled list of common datacenter/cloud CIDRs for Stage 3 MVP.
# In a production environment, this would be periodically synced from
# provider JSON endpoints (e.g. https://ip-ranges.amazonaws.com/ip-ranges.json).
_CLOUD_CIDRS_STR = [
    # AWS (sample)
    "3.5.140.0/22", "15.230.56.0/21", "54.239.0.0/16", "52.94.0.0/16",
    # GCP (sample)
    "34.80.0.0/15", "35.184.0.0/13", "104.154.0.0/15",
    # Azure (sample)
    "13.64.0.0/11", "20.33.0.0/16", "40.74.0.0/15",
]

_CLOUD_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []

def get_cloud_networks() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Return the list of compiled cloud network objects."""
    global _CLOUD_NETWORKS
    if not _CLOUD_NETWORKS:
        networks = []
        for cidr in _CLOUD_CIDRS_STR:
            try:
                networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                logger.warning(f"Invalid CIDR in cloud feed: {cidr}")
        _CLOUD_NETWORKS = networks
    return _CLOUD_NETWORKS

def is_datacenter_ip(ip: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check if an IP belongs to a known cloud/datacenter range."""
    try:
        ip_obj = ipaddress.ip_address(ip) if isinstance(ip, str) else ip
        # Fast path for local/private IPs
        if ip_obj.is_private or ip_obj.is_loopback:
            return False
            
        networks = get_cloud_networks()
        for net in networks:
            if ip_obj in net:
                return True
        return False
    except ValueError:
        return False
