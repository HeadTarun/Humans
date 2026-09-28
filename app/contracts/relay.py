"""contracts/relay.py — mail relay hop chain, derived from Received: headers."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import Field

from .common import BaseContract


class RelayHop(BaseContract):
    hop_index: int = Field(..., ge=0)
    received_from: Optional[str] = None
    received_by: Optional[str] = None
    timestamp: Optional[datetime] = None
    ip_address: Optional[str] = None
    is_internal: Optional[bool] = None


class RelayPath(BaseContract):
    hops: list[RelayHop] = Field(default_factory=list)
    hop_count: int = 0
    origin_ip: Optional[str] = None
    anomalies: list[str] = Field(default_factory=list, description="e.g. 'hop_order_inconsistent', 'timestamp_regression'")
