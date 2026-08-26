"""
contracts/headers.py

RAW OBSERVATION vs INTERPRETATION must stay separate (PS 26106 §6).
HeaderSet holds observed structure only. HeaderFinding holds a heuristic
interpretation and must reference the observed fields it was derived from.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import Field

from .common import BaseContract


class ReceivedHop(BaseContract):
    hop_index: int = Field(..., ge=0)
    from_host: Optional[str] = None
    by_host: Optional[str] = None
    protocol: Optional[str] = None
    timestamp: Optional[datetime] = None
    raw_line: str


class HeaderSet(BaseContract):
    """Pure structural observation. Must NOT decide phishing/malicious (§5)."""

    from_address: Optional[str] = None
    from_domain: Optional[str] = None
    reply_to: Optional[str] = None
    reply_to_domain: Optional[str] = None
    return_path: Optional[str] = None
    return_path_domain: Optional[str] = None
    message_id: Optional[str] = None
    subject: Optional[str] = None
    date: Optional[datetime] = None
    received_hops: list[ReceivedHop] = Field(default_factory=list)
    authentication_results_raw: Optional[str] = None
    raw_headers: dict[str, str] = Field(default_factory=dict)


class HeaderFinding(BaseContract):
    """
    An interpretation derived from HeaderSet observations, e.g.
    'reply_to_mismatch = true'. Kept as a HEURISTIC-shaped structure but
    materialized into an EvidenceItem(type=HEURISTIC) by the header
    analyzer, not consumed directly downstream.
    """

    finding_id: str
    key: str = Field(..., description="e.g. 'reply_to_mismatch', 'display_name_spoof'")
    observed_fields: dict[str, Optional[str]] = Field(
        ..., description="The raw HeaderSet fields this interpretation was computed from"
    )
    interpretation: bool | str
    is_heuristic: bool = True
