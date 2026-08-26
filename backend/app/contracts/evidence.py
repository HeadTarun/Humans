"""
contracts/evidence.py

The canonical EvidenceItem. This is the heart of the system (PS 26106 §3).

HARD RULE: a model score is NEVER stored as type=FACT.
    WRONG:   type=FACT,       key="phishing",             value=0.91
    CORRECT: type=ML_SIGNAL,  key="phishing_probability",  value=0.91

This module enforces that rule structurally (validator below) rather than
relying on caller discipline.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import Field, field_validator, model_validator

from .common import BaseContract, CaseId, EvidenceId, Provenance, SourceType, utcnow


class EvidenceType(str, Enum):
    FACT = "FACT"
    HEURISTIC = "HEURISTIC"
    ML_SIGNAL = "ML_SIGNAL"
    THREAT_INTEL = "THREAT_INTEL"
    HISTORICAL = "HISTORICAL"
    CORRELATION = "CORRELATION"
    INFERENCE = "INFERENCE"


class TrustLevel(str, Enum):
    VERIFIED = "VERIFIED"
    REPORTED = "REPORTED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"


class EvidenceCategory(str, Enum):
    AUTHENTICATION = "AUTHENTICATION"
    HEADER = "HEADER"
    CONTENT = "CONTENT"
    URL = "URL"
    HTML = "HTML"
    ATTACHMENT = "ATTACHMENT"
    RELAY = "RELAY"
    IOC = "IOC"
    THREAT_INTEL = "THREAT_INTEL"
    HISTORICAL = "HISTORICAL"
    CORRELATION = "CORRELATION"
    SENDER_BEHAVIOR = "SENDER_BEHAVIOR"


class EvidenceStatus(str, Enum):
    ACTIVE = "ACTIVE"
    SUPERSEDED = "SUPERSEDED"
    DISPUTED = "DISPUTED"
    RETRACTED = "RETRACTED"


# Key-name patterns that are only legitimate on non-FACT evidence. This is a
# best-effort structural guard for the rule in §3; it does not replace code
# review, but it catches the most common producer mistake at contract
# construction time instead of at report time.
_SCORE_LIKE_SUFFIXES = ("_probability", "_score", "_confidence_score")


class EvidenceItem(BaseContract):
    evidence_id: EvidenceId
    case_id: CaseId
    type: EvidenceType
    category: EvidenceCategory
    key: str = Field(..., description="Machine-readable field name, e.g. 'dmarc' or 'phishing_probability'")
    value: Any = Field(..., description="FACT/HEURISTIC values are discrete observations; ML_SIGNAL values are scores")
    source: str = Field(..., description="Producing analyzer/tool/provider name")
    source_type: SourceType
    confidence: float = Field(..., ge=0.0, le=1.0)
    trust_level: TrustLevel
    timestamp: datetime = Field(default_factory=utcnow)
    provenance: Provenance
    related_entity: Optional[str] = Field(default=None, description="e.g. a domain, IP, URL, or attachment hash")
    evidence_reference: Optional[EvidenceId] = Field(
        default=None, description="Set when this evidence supersedes or is derived from another EvidenceItem"
    )
    status: EvidenceStatus = EvidenceStatus.ACTIVE

    @field_validator("key")
    @classmethod
    def _key_is_machine_readable(cls, v: str) -> str:
        if not v or " " in v:
            raise ValueError("evidence key must be a machine-readable identifier, e.g. 'dmarc' not 'DMARC result'")
        return v

    @model_validator(mode="after")
    def _forbid_score_as_fact(self) -> "EvidenceItem":
        if self.type == EvidenceType.FACT and any(self.key.endswith(suf) for suf in _SCORE_LIKE_SUFFIXES):
            raise ValueError(
                f"key '{self.key}' looks like a model score and cannot be stored as type=FACT. "
                f"Use type=ML_SIGNAL instead (PS 26106 §3)."
            )
        if self.type == EvidenceType.ML_SIGNAL and self.source_type != SourceType.ML_MODEL:
            raise ValueError("type=ML_SIGNAL requires source_type=ML_MODEL")
        if self.type == EvidenceType.THREAT_INTEL and self.source_type != SourceType.THREAT_INTEL_API:
            raise ValueError("type=THREAT_INTEL requires source_type=THREAT_INTEL_API")
        if self.type == EvidenceType.HISTORICAL and self.source_type != SourceType.HISTORICAL_CORRELATION:
            raise ValueError("type=HISTORICAL requires source_type=HISTORICAL_CORRELATION")
        return self
