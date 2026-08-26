"""
contracts/common.py

Shared primitives used by every other contract module.

Nothing in this system should import raw dict/JSON across a module
boundary. Everything imports from `contracts.*` instead.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Type aliases (documentation-level; kept as str for JSON/DB portability)
# ---------------------------------------------------------------------------

CaseId = str
EvidenceId = str
ExecutionId = str
ConflictId = str
HypothesisId = str
CorrelationId = str


class BaseContract(BaseModel):
    """
    Base class for every contract in the system.

    - extra="forbid": a producer cannot silently smuggle undeclared fields
      through a boundary. If a new field is needed, the contract itself
      must be updated (see PS 26106 section 2).
    - frozen=True: contracts are immutable snapshots. A module that wants
      to change a value must construct a new instance (`model_copy`),
      never mutate in place. This preserves provenance and audit
      integrity guarantees.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        validate_assignment=True,
    )


class ContractError(BaseContract):
    """Standard error contract returned by API/service boundaries."""

    error_code: str
    message: str
    detail: Optional[dict[str, Any]] = None
    occurred_at: datetime = Field(default_factory=utcnow)


class Provenance(BaseContract):
    """
    Answers: WHO produced this? FROM WHAT? WHEN? HOW?

    Required on every EvidenceItem and every derived artifact that
    claims investigative significance.
    """

    producer_module: str = Field(
        ..., description="Dotted module/service path that created this, e.g. 'analyzers.header'"
    )
    source_artifact: Optional[str] = Field(
        default=None, description="Reference to the raw artifact this was derived from (e.g. raw_artifact_reference)"
    )
    extraction_method: Optional[str] = Field(
        default=None, description="Deterministic rule name, ML inference, API call, correlation, etc."
    )
    created_at: datetime = Field(default_factory=utcnow)
    model_name: Optional[str] = None
    model_version: Optional[str] = None
    api_provider: Optional[str] = Field(
        default=None, description="External provider name if this came from a third-party API/service"
    )
    original_evidence_reference: Optional[EvidenceId] = Field(
        default=None, description="If derived from another EvidenceItem, its evidence_id"
    )


class SourceType(str, Enum):
    DETERMINISTIC = "deterministic"
    ML_MODEL = "ml_model"
    THREAT_INTEL_API = "threat_intel_api"
    HISTORICAL_CORRELATION = "historical_correlation"
    TOOL_EXECUTION = "tool_execution"
    GROQ_REASONING = "groq_reasoning"
    ANALYST = "analyst"


class Recommendation(str, Enum):
    """Generic recommended-action vocabulary reused by Risk/Report contracts."""

    NO_ACTION = "no_action"
    MONITOR = "monitor"
    QUARANTINE = "quarantine"
    BLOCK_SENDER = "block_sender"
    BLOCK_URL = "block_url"
    ESCALATE_TO_ANALYST = "escalate_to_analyst"
    REQUEST_MORE_EVIDENCE = "request_more_evidence"
