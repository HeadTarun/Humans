"""
services/intelligence/geoip.py

GeoIP lookup interface for MaxMind GeoLite2.
"""

from __future__ import annotations

import logging
from typing import Optional, Dict, Any
import geoip2.database
import geoip2.errors
import os

logger = logging.getLogger(__name__)

class GeoLite2Adapter:
    """Adapter for local MaxMind GeoLite2 databases."""
    
    def __init__(self, db_path: str = "GeoLite2-City.mmdb"):
        self.db_path = db_path
        self._reader: Optional[geoip2.database.Reader] = None
        self._is_available = False
        
        # In a real environment we'd load this, for the MVP we will mock or
        # gracefully fail if the file is missing (since MaxMind requires an account)
        if os.path.exists(self.db_path):
            try:
                self._reader = geoip2.database.Reader(self.db_path)
                self._is_available = True
            except Exception as e:
                logger.warning(f"Failed to load GeoLite2 DB at {self.db_path}: {e}")
        else:
            logger.info(f"GeoLite2 DB not found at {self.db_path}. Lookups will return None.")
            
    def is_available(self) -> bool:
        return self._is_available
        
    def lookup_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Return GeoIP info, or None if not found or DB unavailable."""
        if not self._is_available or not self._reader:
            return None
            
        try:
            response = self._reader.city(ip_address)
            
            return {
                "ip_country": response.country.iso_code,
                "ip_city": response.city.name,
                "ip_lat": response.location.latitude,
                "ip_lon": response.location.longitude,
            }
        except geoip2.errors.AddressNotFoundError:
            return {}  # Not an error, just not found
        except Exception as e:
            logger.error(f"GeoIP lookup error for {ip_address}: {e}")
            return None
            
    def close(self):
        if self._reader:
            self._reader.close()
            
# Singleton for reuse
_ADAPTER = GeoLite2Adapter()

def get_geoip_adapter() -> GeoLite2Adapter:
    return _ADAPTER
