"""Resilient, provider-neutral IP geolocation.

The manager is independent from the agent/tool layer. It validates an IP,
uses a bounded cache, then tries two independent HTTPS providers and finally
a local MaxMind database. Provider failure never becomes an app exception.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import time
from dataclasses import dataclass
from typing import Any, Optional, Protocol, Sequence

import geoip2.database
import geoip2.errors
import httpx

from app.contracts.geolocation import GeoLocationResult
from app.core.config import settings
from app.core.ssrf_guard import is_safe_ip as _ssrf_is_safe_ip
from app.services.logging import log_json

logger = logging.getLogger(__name__)


class GeoLocationProvider(Protocol):
    name: str

    async def lookup(self, ip: str) -> Optional[GeoLocationResult]: ...


class GeoLocationProviderError(RuntimeError):
    """A provider-local failure that should trigger the next fallback."""


def _optional_float(value: Any) -> Optional[float]:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


class IPWhoIsProvider:
    """Primary no-key HTTPS provider; its response shape remains isolated."""

    name = "ipwho.is"
    is_external = True

    def __init__(self, client: httpx.AsyncClient) -> None:
        self._client = client

    async def lookup(self, ip: str) -> Optional[GeoLocationResult]:
        response = await self._client.get(f"https://ipwho.is/{ip}")
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict) or payload.get("success") is False:
            raise GeoLocationProviderError("provider returned no geolocation")
        connection = payload.get("connection") if isinstance(payload.get("connection"), dict) else {}
        timezone = payload.get("timezone")
        return GeoLocationResult(
            ip=ip, country=payload.get("country"), country_code=payload.get("country_code"),
            region=payload.get("region"), city=payload.get("city"),
            latitude=_optional_float(payload.get("latitude")), longitude=_optional_float(payload.get("longitude")),
            timezone=timezone.get("id") if isinstance(timezone, dict) else timezone,
            asn=str(connection.get("asn")) if connection.get("asn") is not None else None,
            isp=connection.get("isp"), organization=connection.get("org"),
            provider=self.name, source="provider", success=True,
        )


class IPApiCoProvider:
    """Independent fallback provider with a distinct response schema."""

    name = "ipapi.co"
    is_external = True

    def __init__(self, client: httpx.AsyncClient) -> None:
        self._client = client

    async def lookup(self, ip: str) -> Optional[GeoLocationResult]:
        response = await self._client.get(f"https://ipapi.co/{ip}/json/")
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict) or payload.get("error"):
            raise GeoLocationProviderError("provider returned no geolocation")
        return GeoLocationResult(
            ip=ip, country=payload.get("country_name"), country_code=payload.get("country_code"),
            region=payload.get("region"), city=payload.get("city"),
            latitude=_optional_float(payload.get("latitude")), longitude=_optional_float(payload.get("longitude")),
            timezone=payload.get("timezone"), asn=payload.get("asn"), organization=payload.get("org"),
            provider=self.name, source="provider", success=True,
        )


class IPinfoLiteProvider:
    """Token-authenticated IPinfo Lite fallback (country and ASN only)."""

    name = "ipinfo_lite"
    is_external = True

    def __init__(self, client: httpx.AsyncClient, token: Optional[str] = None) -> None:
        self._client = client
        self._token = token if token is not None else settings.IPINFO_TOKEN

    async def lookup(self, ip: str) -> Optional[GeoLocationResult]:
        if not self._token:
            raise GeoLocationProviderError("provider_not_configured")
        response = await self._client.get(
            f"https://api.ipinfo.io/lite/{ip}", params={"token": self._token}
        )
        if response.status_code in (401, 403):
            raise GeoLocationProviderError("provider_not_configured")
        if response.status_code == 429:
            raise GeoLocationProviderError("rate_limited")
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict) or not payload.get("ip"):
            raise GeoLocationProviderError("provider returned no geolocation")
        # Lite deliberately does not claim city, region, coordinates, or timezone.
        return GeoLocationResult(
            ip=ip, country=payload.get("country"), country_code=payload.get("country_code"),
            asn=payload.get("asn"), organization=payload.get("as_name"),
            provider=self.name, source="provider", success=True,
        )


class GeoLite2Adapter:
    """Synchronous MaxMind reader retained for local/offline compatibility."""

    def __init__(self, db_path: Optional[str] = None, asn_db_path: Optional[str] = None) -> None:
        self.db_path = db_path or settings.GEOIP_CITY_DB_PATH
        self.asn_db_path = asn_db_path or settings.GEOIP_ASN_DB_PATH
        self._reader = self._open_reader(self.db_path)
        self._asn_reader = self._open_reader(self.asn_db_path)

    @staticmethod
    def _open_reader(path: str) -> Optional[geoip2.database.Reader]:
        if not path or not os.path.exists(path):
            return None
        try:
            return geoip2.database.Reader(path)
        except Exception as exc:
            logger.warning("GeoLite2 database unavailable at %s: %s", path, type(exc).__name__)
            return None

    def is_available(self) -> bool:
        return self._reader is not None or self._asn_reader is not None

    def lookup_ip(self, ip_address: str) -> Optional[dict[str, Any]]:
        if not self.is_available():
            return None
        result: dict[str, Any] = {}
        try:
            if self._reader:
                city = self._reader.city(ip_address)
                result.update({
                    "country": city.country.name, "country_code": city.country.iso_code,
                    "region": city.subdivisions.most_specific.name, "city": city.city.name,
                    "latitude": city.location.latitude, "longitude": city.location.longitude,
                    "timezone": city.location.time_zone,
                })
            if self._asn_reader:
                asn = self._asn_reader.asn(ip_address)
                result.update({
                    "asn": str(asn.autonomous_system_number) if asn.autonomous_system_number else None,
                    "organization": asn.autonomous_system_organization,
                })
            return result or None
        except geoip2.errors.AddressNotFoundError:
            return None
        except Exception as exc:
            logger.warning("GeoLite2 lookup failed for a validated IP: %s", type(exc).__name__)
            return None

    def close(self) -> None:
        for reader in (self._reader, self._asn_reader):
            if reader:
                reader.close()


class LocalGeoIPProvider:
    name = "maxmind_geolite2"
    is_external = False

    def __init__(self, adapter: Optional[GeoLite2Adapter] = None) -> None:
        self._adapter = adapter or GeoLite2Adapter()

    async def lookup(self, ip: str) -> Optional[GeoLocationResult]:
        data = await asyncio.to_thread(self._adapter.lookup_ip, ip)
        if not data:
            return None
        return GeoLocationResult(
            ip=ip, country=data.get("country"), country_code=data.get("country_code"),
            region=data.get("region"), city=data.get("city"),
            latitude=_optional_float(data.get("latitude")), longitude=_optional_float(data.get("longitude")),
            timezone=data.get("timezone"), asn=data.get("asn"), organization=data.get("organization"),
            provider=self.name, source="local_geoip", success=True,
        )


@dataclass(frozen=True)
class _IPClassification:
    is_private: bool
    is_reserved: bool
    is_loopback: bool
    is_link_local: bool
    is_multicast: bool
    is_unspecified: bool

    @property
    def is_public(self) -> bool:
        return not any((self.is_private, self.is_reserved, self.is_loopback, self.is_link_local,
                        self.is_multicast, self.is_unspecified))


def _classify_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> _IPClassification:
    return _IPClassification(ip.is_private, ip.is_reserved, ip.is_loopback, ip.is_link_local,
                             ip.is_multicast, ip.is_unspecified)


class GeoLocationManager:
    """Single public interface: ``await manager.lookup(ip)``."""

    def __init__(self, providers: Optional[Sequence[GeoLocationProvider]] = None,
                 cache_ttl_seconds: Optional[int] = None,
                 client: Optional[httpx.AsyncClient] = None) -> None:
        self._cache: dict[str, tuple[float, GeoLocationResult]] = {}
        self._cache_ttl_seconds = max(0, cache_ttl_seconds if cache_ttl_seconds is not None
                                      else settings.GEOLOCATION_CACHE_TTL_SECONDS)
        self._client = client or httpx.AsyncClient(timeout=httpx.Timeout(settings.GEOLOCATION_TIMEOUT_SECONDS))
        if providers is not None:
            self._providers = list(providers)
        else:
            external: list[GeoLocationProvider] = []
            if settings.GEOLOCATION_EXTERNAL_ENABLED:
                external = [
                    IPWhoIsProvider(self._client),
                    IPinfoLiteProvider(self._client),
                    IPApiCoProvider(self._client),
                ]
            # Offline data is authoritative enough for the compact response
            # and costs no network budget; only then use bounded fallbacks.
            self._providers = [LocalGeoIPProvider(), *external]

    async def lookup(self, raw_ip: str, max_external_calls: Optional[int] = None) -> GeoLocationResult:
        """Return a structured result for every input; enrichment failures never raise."""
        candidate = str(raw_ip).strip()
        try:
            ip_obj = ipaddress.ip_address(candidate)
        except ValueError:
            log_json(__name__, logging.INFO, "lookup_failed", reason="invalid_ip")
            return GeoLocationResult(ip=candidate, source="validation", success=False, error="invalid_ip")

        ip = str(ip_obj)
        classification = _classify_ip(ip_obj)
        flags = {
            "is_private": classification.is_private, "is_reserved": classification.is_reserved,
            "is_loopback": classification.is_loopback, "is_link_local": classification.is_link_local,
            "is_multicast": classification.is_multicast, "is_unspecified": classification.is_unspecified,
        }
        if not classification.is_public:
            log_json(__name__, logging.INFO, "lookup_failed", ip=ip, reason="non_public_ip")
            return GeoLocationResult(ip=ip, source="validation", success=False, error="non_public_ip", **flags)

        cached = self._cache.get(ip)
        if cached and cached[0] > time.monotonic():
            log_json(__name__, logging.INFO, "lookup_cache_hit", ip=ip)
            return cached[1].model_copy(update={"source": "cache"})

        log_json(__name__, logging.INFO, "lookup_started", ip=ip)
        external_calls_made = 0
        for index, provider in enumerate(self._providers):
            is_external = bool(getattr(provider, "is_external", True))
            if is_external and max_external_calls is not None and external_calls_made >= max_external_calls:
                break
            try:
                if is_external:
                    external_calls_made += 1
                result = await provider.lookup(ip)
            except Exception as exc:  # provider boundary; type is logged, details remain internal
                event = "lookup_primary_failure" if index == 0 else "lookup_fallback_failure"
                log_json(__name__, logging.WARNING, event, ip=ip, provider=provider.name,
                         error_type=type(exc).__name__)
                continue
            if result and result.success:
                enriched = result.model_copy(update={**flags, "external_calls_made": external_calls_made})
                if self._cache_ttl_seconds:
                    self._cache[ip] = (time.monotonic() + self._cache_ttl_seconds, enriched)
                event = "lookup_local_success" if enriched.source == "local_geoip" else (
                    "lookup_primary_success" if external_calls_made == 1 else "lookup_fallback_success"
                )
                log_json(__name__, logging.INFO, event, ip=ip, provider=provider.name)
                return enriched

        log_json(__name__, logging.WARNING, "lookup_failed", ip=ip, reason="all_providers_unavailable")
        return GeoLocationResult(ip=ip, source="unavailable", success=False,
                                 error=("external_call_budget_exhausted" if max_external_calls == 0 else "all_providers_unavailable"),
                                 external_calls_made=external_calls_made, **flags)

    async def lookup_many(self, ips: Sequence[str]) -> list[GeoLocationResult]:
        """Look up unique IPs concurrently while preserving input order and duplicates."""
        unique = list(dict.fromkeys(str(ip) for ip in ips))
        results = await asyncio.gather(*(self.lookup(ip) for ip in unique))
        by_ip = dict(zip(unique, results))
        return [by_ip[str(ip)] for ip in ips]

    async def aclose(self) -> None:
        await self._client.aclose()


# Compatibility entry points for existing callers.
_ADAPTER = GeoLite2Adapter()
_MANAGER: Optional[GeoLocationManager] = None


def get_geoip_adapter() -> GeoLite2Adapter:
    return _ADAPTER


def get_geolocation_manager() -> GeoLocationManager:
    global _MANAGER
    if _MANAGER is None:
        _MANAGER = GeoLocationManager()
    return _MANAGER
