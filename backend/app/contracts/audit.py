"""
contracts/audit.py

The audit trail is itself evidence (§28). Every AuditRecord chains to the
previous one via hash_prev/hash_self so tampering is detectable — this
is what the "hash chain" and optional blockchain anchor (§41) rest on.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import Field, model_validator

from .common import BaseContract, CaseId, utcnow

GENESIS_HASH = "0" * 64


class AuditEventType(str, Enum):
    TOOL_EXECUTED = "TOOL_EXECUTED"
    POLICY_DECISION = "POLICY_DECISION"
    EVIDENCE_CREATED = "EVIDENCE_CREATED"
    RISK_UPDATED = "RISK_UPDATED"
    CONFIDENCE_UPDATED = "CONFIDENCE_UPDATED"
    GROQ_CALLED = "GROQ_CALLED"
    GROQ_REJECTED = "GROQ_REJECTED"
    STOP = "STOP"
    ESCALATION = "ESCALATION"
    REPORT_GENERATED = "REPORT_GENERATED"


def _canonical_json(data: dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, default=str, separators=(",", ":"))


def compute_record_hash(hash_prev: str, record_fields: dict[str, Any]) -> str:
    """
    Deterministic hash for one audit record given the previous record's
    hash and this record's own content (everything except hash_self,
    which is what we're computing).
    """
    payload = {"hash_prev": hash_prev, **record_fields}
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


class AuditRecord(BaseContract):
    case_id: CaseId
    step: int = Field(..., ge=0)
    event_type: AuditEventType
    tool: Optional[str] = None
    policy_decision: Optional[dict[str, Any]] = None
    reason_code: Optional[str] = None
    reason_data: dict[str, Any] = Field(default_factory=dict)
    evidence_before: list[str] = Field(default_factory=list)
    evidence_after: list[str] = Field(default_factory=list)
    risk_before: Optional[float] = None
    risk_after: Optional[float] = None
    confidence_before: Optional[float] = None
    confidence_after: Optional[float] = None
    stop_reason: Optional[str] = None
    escalation_reason: Optional[str] = None
    timestamp: datetime = Field(default_factory=utcnow)
    hash_prev: str
    hash_self: str

    @model_validator(mode="after")
    def _hash_self_is_consistent(self) -> "AuditRecord":
        expected = compute_record_hash(
            self.hash_prev,
            self.model_dump(mode="json", exclude={"hash_self", "hash_prev"}),
        )
        if expected != self.hash_self:
            raise ValueError(
                "hash_self does not match recomputed hash of (hash_prev + record content); "
                "audit chain integrity violation detected at construction time"
            )
        return self

    @classmethod
    def create(cls, *, hash_prev: str, **fields: Any) -> "AuditRecord":
        """
        Convenience constructor: computes hash_self for you so callers
        never have to (and can't accidentally) get it wrong.

        The timestamp default is pinned once here (rather than left to
        each model's own default_factory) so the provisional hashing pass
        and the final constructed record are guaranteed to see the same
        content — otherwise two independent `utcnow()` calls would drift
        by microseconds and the hash_self consistency check would fail.
        """
        fields.setdefault("timestamp", utcnow())
        draft_fields = {**fields, "hash_prev": hash_prev}
        # Build once without hash_self to get canonical serialized content,
        # using a temporary permissive instance for hashing purposes only.
        provisional = _PreHashRecord(**draft_fields)
        content = provisional.model_dump(mode="json", exclude={"hash_prev"})
        hash_self = compute_record_hash(hash_prev, content)
        return cls(hash_self=hash_self, **draft_fields)


class _PreHashRecord(BaseContract):
    """Internal mirror of AuditRecord's fields minus hash_self, used only to compute it."""

    case_id: CaseId
    step: int
    event_type: AuditEventType
    tool: Optional[str] = None
    policy_decision: Optional[dict[str, Any]] = None
    reason_code: Optional[str] = None
    reason_data: dict[str, Any] = Field(default_factory=dict)
    evidence_before: list[str] = Field(default_factory=list)
    evidence_after: list[str] = Field(default_factory=list)
    risk_before: Optional[float] = None
    risk_after: Optional[float] = None
    confidence_before: Optional[float] = None
    confidence_after: Optional[float] = None
    stop_reason: Optional[str] = None
    escalation_reason: Optional[str] = None
    timestamp: datetime = Field(default_factory=utcnow)
    hash_prev: str
