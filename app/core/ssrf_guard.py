"""
app/core/ssrf_guard.py

SSRF (Server-Side Request Forgery) protection.

Every HTTP call that uses attacker-influenced input (domain from email,
IP from Received headers, URL from email body) MUST validate the target
through this module BEFORE establishing any network connection.

WHAT IS BLOCKED:
  - Loopback:         127.0.0.0/8, ::1
  - Private:          10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7
  - Link-local:       169.254.0.0/16, fe80::/10
  - Multicast:        224.0.0.0/4, ff00::/8
  - Reserved/special: 0.0.0.0/8, 240.0.0.0/4, 100.64.0.0/10 (CGNAT)
  - Unspecified:      ::, 0.0.0.0

WHAT IS ALLOWED:
  - Public routable IPv4 / IPv6 addresses
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import urllib.parse
from typing import Optional

logger = logging.getLogger(__name__)

_BLOCKED_NETWORKS_V4 = [
    ipaddress.IPv4Network("0.0.0.0/8"),
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("100.64.0.0/10"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.0.0.0/24"),
    ipaddress.IPv4Network("192.0.2.0/24"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("198.18.0.0/15"),
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
    ipaddress.IPv4Network("224.0.0.0/4"),
    ipaddress.IPv4Network("240.0.0.0/4"),
    ipaddress.IPv4Network("255.255.255.255/32"),
]

_BLOCKED_NETWORKS_V6 = [
    ipaddress.IPv6Network("::1/128"),
    ipaddress.IPv6Network("::/128"),
    ipaddress.IPv6Network("fc00::/7"),
    ipaddress.IPv6Network("fe80::/10"),
    ipaddress.IPv6Network("ff00::/8"),
    ipaddress.IPv6Network("::ffff:0:0/96"),
    ipaddress.IPv6Network("2001:db8::/32"),
    ipaddress.IPv6Network("100::/64"),
]


class SSRFViolation(ValueError):
    """Raised when a target IP or URL would route to a non-public address."""

    def __init__(self, reason: str, ip: Optional[str] = None, url: Optional[str] = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.ip = ip
        self.url = url


def _is_blocked_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip_obj, ipaddress.IPv4Address):
        return any(ip_obj in net for net in _BLOCKED_NETWORKS_V4)
    else:
        return any(ip_obj in net for net in _BLOCKED_NETWORKS_V6)


class SSRFGuard:
    def validate_ip(self, ip_str: str) -> None:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            raise SSRFViolation(f"Invalid IP address: {ip_str!r}", ip=ip_str)
        if _is_blocked_ip(ip_obj):
            logger.warning("SSRF_BLOCKED ip=%s reason=blocked_network", ip_str)
            raise SSRFViolation(
                f"IP {ip_str} is in a blocked network range",
                ip=ip_str,
            )

    def is_safe_ip(self, ip_str: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return not _is_blocked_ip(ip_obj)
        except ValueError:
            return False

    def validate_url(self, url: str, resolve_dns: bool = True) -> None:
        try:
            parsed = urllib.parse.urlparse(url)
        except Exception as exc:
            raise SSRFViolation(f"Malformed URL: {exc}", url=url) from exc

        if parsed.scheme not in ("http", "https"):
            raise SSRFViolation(
                f"Disallowed URL scheme: {parsed.scheme!r}",
                url=url,
            )

        hostname = parsed.hostname
        if not hostname:
            raise SSRFViolation(f"URL has no hostname: {url!r}", url=url)

        try:
            ip_obj = ipaddress.ip_address(hostname)
            if _is_blocked_ip(ip_obj):
                logger.warning("SSRF_BLOCKED url=%r ip=%s reason=ip_literal_blocked", url, hostname)
                raise SSRFViolation(f"URL target IP {hostname} is in a blocked range", ip=hostname, url=url)
            return
        except ValueError:
            pass

        if not resolve_dns:
            return

        try:
            addrinfos = socket.getaddrinfo(hostname, None)
        except socket.gaierror as exc:
            raise SSRFViolation(f"DNS resolution failed for {hostname!r}: {exc}", url=url) from exc

        for addrinfo in addrinfos:
            ip_str = addrinfo[4][0]
            try:
                ip_obj = ipaddress.ip_address(ip_str)
            except ValueError:
                continue
            if _is_blocked_ip(ip_obj):
                logger.warning(
                    "SSRF_BLOCKED url=%r hostname=%s resolved_ip=%s",
                    url, hostname, ip_str,
                )
                raise SSRFViolation(
                    f"Hostname {hostname!r} resolves to blocked IP {ip_str}",
                    ip=ip_str, url=url,
                )

    def is_safe_url(self, url: str, resolve_dns: bool = True) -> bool:
        try:
            self.validate_url(url, resolve_dns=resolve_dns)
            return True
        except (SSRFViolation, ValueError):
            return False


# Module-level singleton
_guard = SSRFGuard()
validate_ip = _guard.validate_ip
is_safe_ip = _guard.is_safe_ip
validate_url = _guard.validate_url
is_safe_url = _guard.is_safe_url
