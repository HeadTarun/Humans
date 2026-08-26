"""
contracts/email.py

The parser's ONLY job is structure extraction (§5). It must never emit
a verdict like "phishing" or "malicious" — that judgment belongs to the
Risk Engine, operating over EvidenceItems built from this structure.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import Field

from .attachment import AttachmentRef
from .common import BaseContract
from .headers import HeaderSet


class ParsedEmail(BaseContract):
    message_id: Optional[str] = None
    headers: HeaderSet
    plain_text: Optional[str] = None
    html: Optional[str] = None
    urls: list[str] = Field(default_factory=list, description="Raw URLs extracted from body/html, pre-normalization")
    attachments: list[AttachmentRef] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict, description="Non-authoritative parser metadata only")
    raw_artifact_reference: str = Field(..., description="Pointer to the stored raw .eml/.msg artifact")
    sha256: str = Field(..., description="Hash of the raw artifact, for integrity/audit chaining")
