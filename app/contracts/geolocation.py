"""Provider-neutral, forensic-safe IP geolocation contract."""

from __future__ import annotations

from typing import Optional

from pydantic import Field

from .common import BaseContract


class GeoLocationResult(BaseContract):
    """Normalized result for one IP lookup, including graceful failures."""

    ip: str
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None
    asn: Optional[str] = None
    isp: Optional[str] = None
    organization: Optional[str] = None
    is_private: bool = False
    is_reserved: bool = False
    is_loopback: bool = False
    is_link_local: bool = False
    is_multicast: bool = False
    is_unspecified: bool = False
    provider: Optional[str] = None
    source: str = Field(..., description="cache, provider, local_geoip, validation, or unavailable")
    success: bool
    error: Optional[str] = None
    external_calls_made: int = Field(default=0, ge=0)
