"""app/integrations/abuseipdb.py
Wrapper delegating to services/intelligence/ip_intel.py (AbuseIPDB adapter).
The actual implementation lives in the intelligence service layer.
"""
from app.services.intelligence.ip_intel import AbuseIPDBAdapter
__all__ = ["AbuseIPDBAdapter"]
