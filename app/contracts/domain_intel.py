"""
contracts/domain_intel.py

Domain intelligence specific contracts (RDAP, DNS, Whois).
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import Field

from .common import BaseContract, utcnow


class DomainIntelResult(BaseContract):
    """
    Standardized result for domain intelligence lookups (RDAP/Whois).
    """
    domain: str
    
    # Registration dates
    registration_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None
    updated_date: Optional[datetime] = None
    
    # Derivations
    domain_age_days: Optional[int] = None
    is_newly_registered: Optional[bool] = Field(
        default=None, 
        description="True if domain is less than 30 days old"
    )
    
    # Registrar/Registrant info
    registrar_name: Optional[str] = None
    registrant_country: Optional[str] = None
    registrant_organization: Optional[str] = None
    
    nameservers: list[str] = Field(default_factory=list)
    
    # DNS Resolution
    resolves_to_ips: list[str] = Field(default_factory=list)
    has_mx_records: Optional[bool] = None
    has_txt_records: Optional[bool] = None
    
    retrieved_at: datetime = Field(default_factory=utcnow)
