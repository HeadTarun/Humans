"""
services/tools/handlers/ip_classifier.py

IP Classifier Tool (Level 0).
Determines if an IP is private (RFC1918), loopback, TOR exit node, or cloud datacenter.
Prevents internal/private IPs from leaking to external APIs (SSRF protection).
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any, Optional

from app.contracts.investigation import InvestigationState
from app.contracts.tool import ToolExecutionRequest
from app.services.feeds.cloud_cidrs import is_datacenter_ip
from app.services.feeds.tor_exits import is_tor_exit

logger = logging.getLogger(__name__)

# Security: List of networks that must NEVER be sent to an external API
_BLOCKED_NETWORKS = [
    "0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7",
    "fe80::/10", "100.64.0.0/10",
]
_BLOCKED_NETS_OBJ = [ipaddress.ip_network(n) for n in _BLOCKED_NETWORKS]

def is_blocked_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    for net in _BLOCKED_NETS_OBJ:
        if ip_obj in net:
            return True
    return False

async def handle(
    request: ToolExecutionRequest, 
    state: InvestigationState,
    package: Any = None
) -> dict[str, Any]:
    """
    Handle IP classification.
    Input: {"ip_address": "1.2.3.4"}
    """
    ip_str = request.input.get("ip_address")
    if not ip_str:
        raise ValueError("ip_classifier requires 'ip_address' in input")
        
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        raise ValueError(f"Invalid IP address format: {ip_str}")
        
    is_private = ip_obj.is_private
    is_loopback = ip_obj.is_loopback
    is_multicast = ip_obj.is_multicast
    is_blocked = is_blocked_ip(ip_obj)
    
    tor_exit = False
    datacenter = False
    
    if not (is_private or is_loopback or is_multicast or is_blocked):
        # Only check public feeds if it's a public IP
        tor_exit = is_tor_exit(ip_str)
        datacenter = is_datacenter_ip(ip_obj)
        
    # We output a ProviderResult-like dict that the Normaliser will convert
    # to FACT EvidenceItems (e.g., ip_is_tor, ip_is_datacenter).
    return {
        "provider_name": "ip_classifier",
        "indicator_value": ip_str,
        "indicator_type": "IP",
        "features": {
            "ip_is_private": is_private,
            "ip_is_loopback": is_loopback,
            "ip_is_multicast": is_multicast,
            "ip_is_blocked_from_external": is_blocked,
            "ip_is_tor_exit": tor_exit,
            "ip_is_datacenter": datacenter,
        }
    }
