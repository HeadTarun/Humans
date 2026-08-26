"""contracts/ioc.py — indicators of compromise, provider-neutral."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import Field

from .common import BaseContract, utcnow


class IOCType(str, Enum):
    IP = "IP"
    DOMAIN = "DOMAIN"
    URL = "URL"
    HASH_MD5 = "HASH_MD5"
    HASH_SHA1 = "HASH_SHA1"
    HASH_SHA256 = "HASH_SHA256"
    EMAIL_ADDRESS = "EMAIL_ADDRESS"


class IOC(BaseContract):
    ioc_id: str
    ioc_type: IOCType
    value: str
    first_seen: datetime = Field(default_factory=utcnow)
    source: str = Field(..., description="Where this IOC was extracted from, e.g. 'url_extractor', 'attachment_hash'")
    context: Optional[str] = None
