"""contracts/authentication.py — SPF / DKIM / DMARC as structured observation."""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import Field

from .common import BaseContract


class AuthResult(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    NONE = "none"
    NEUTRAL = "neutral"
    SOFTFAIL = "softfail"
    TEMPERROR = "temperror"
    PERMERROR = "permerror"
    UNKNOWN = "unknown"


class AuthenticationEvidence(BaseContract):
    spf: AuthResult = AuthResult.UNKNOWN
    spf_domain: Optional[str] = None
    dkim: AuthResult = AuthResult.UNKNOWN
    dkim_domain: Optional[str] = None
    dkim_selector: Optional[str] = None
    dmarc: AuthResult = AuthResult.UNKNOWN
    dmarc_policy: Optional[str] = Field(default=None, description="p= value, e.g. 'none', 'quarantine', 'reject'")
    alignment_spf: Optional[bool] = None
    alignment_dkim: Optional[bool] = None
    raw_auth_results_header: Optional[str] = None
