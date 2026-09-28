"""app/integrations/geoip.py
Wrapper delegating to services/intelligence/geoip.py.
"""
from app.services.intelligence.geoip import GeoLocationManager
__all__ = ["GeoLocationManager"]
