"""app/integrations/virustotal.py
Wrapper delegating to services/intelligence/threat_intel.py (VirusTotal adapter).
"""
from app.services.intelligence.threat_intel import VirusTotalAdapter
__all__ = ["VirusTotalAdapter"]
