"""
services/investigation/audit_logger.py

Append-only, hash-chained audit trail for investigation decisions.

DESIGN RULES:
    - The audit trail is APPEND-ONLY. Previous records are never modified.
    - Hash chaining: record[n].hash_prev == record[n-1].hash_self
    - The genesis record has hash_prev == GENESIS_HASH ("000...0")
    - Reasons are produced by deterministic state values, NOT by an LLM.
    - AuditRecord.create() (from contracts/audit.py) handles hash computation.
    - AuditLogger is per-case; instantiate one per investigation case.

CHAIN INTEGRITY:
    verify_chain() re-computes each record's hash and checks linkage.
    Any tampering causes verify_chain() to return False with details.
"""

from __future__ import annotations

from typing import Optional

from app.contracts.audit import (
    GENESIS_HASH,
    AuditEventType,
    AuditRecord,
    compute_record_hash,
)
from app.contracts.common import CaseId


class AuditChainIntegrityError(Exception):
    """Raised when hash-chain verification fails."""


class AuditLogger:
    """
    Per-case append-only audit logger with hash chaining.

    Usage:
        logger = AuditLogger(case_id="case_abc123")
        logger.log_initialization(state)
        logger.log_stop(state, stop_reason="MAX_ITERATIONS_REACHED")
        chain_ok = logger.verify_chain()
        records = logger.records
    """

    def __init__(self, case_id: CaseId) -> None:
        self._case_id: CaseId = case_id
        self._records: list[AuditRecord] = []
        self._step: int = 0

    @property
    def records(self) -> list[AuditRecord]:
        """Read-only view of the audit chain."""
        return list(self._records)

    @property
    def last_hash(self) -> str:
        """The hash_self of the most recent record, or GENESIS_HASH if chain is empty."""
        if not self._records:
            return GENESIS_HASH
        return self._records[-1].hash_self

    def _next_step(self) -> int:
        step = self._step
        self._step += 1
        return step

    def _append(self, record: AuditRecord) -> None:
        """Append a record. Enforces that hash_prev matches current chain tail."""
        if record.hash_prev != self.last_hash:
            raise AuditChainIntegrityError(
                f"AuditRecord at step {record.step} has hash_prev "
                f"'{record.hash_prev[:16]}…' but expected "
                f"'{self.last_hash[:16]}…' (current chain tail). "
                "Audit chain integrity violation."
            )
        self._records.append(record)

    # ------------------------------------------------------------------
    # Convenience log methods (deterministic reason generation)
    # ------------------------------------------------------------------

    def log_investigation_started(
        self,
        *,
        evidence_ids: list[str] | None = None,
        initial_risk: Optional[float] = None,
        initial_confidence: Optional[float] = None,
    ) -> AuditRecord:
        """Log the creation and initialization of the investigation state."""
        record = AuditRecord.create(
            hash_prev=self.last_hash,
            case_id=self._case_id,
            step=self._next_step(),
            event_type=AuditEventType.POLICY_DECISION,
            reason_code="INVESTIGATION_INITIALIZED",
            reason_data={"sm_status": "INITIALIZED", "investigation_level": "L0_TRIAGE"},
            evidence_before=[],
            evidence_after=evidence_ids or [],
            risk_before=None,
            risk_after=initial_risk,
            confidence_before=None,
            confidence_after=initial_confidence,
        )
        self._append(record)
        return record

    def log_transition(
        self,
        *,
        from_status: str,
        to_status: str,
        reason_code: str,
        evidence_ids: list[str] | None = None,
        risk_before: Optional[float] = None,
        risk_after: Optional[float] = None,
        confidence_before: Optional[float] = None,
        confidence_after: Optional[float] = None,
    ) -> AuditRecord:
        """Log a state machine transition."""
        record = AuditRecord.create(
            hash_prev=self.last_hash,
            case_id=self._case_id,
            step=self._next_step(),
            event_type=AuditEventType.POLICY_DECISION,
            reason_code=reason_code,
            reason_data={"from_status": from_status, "to_status": to_status},
            evidence_before=evidence_ids or [],
            evidence_after=evidence_ids or [],
            risk_before=risk_before,
            risk_after=risk_after,
            confidence_before=confidence_before,
            confidence_after=confidence_after,
        )
        self._append(record)
        return record

    def log_tool_executed(
        self,
        *,
        tool_name: str,
        evidence_before: list[str],
        evidence_after: list[str],
        risk_before: Optional[float] = None,
        risk_after: Optional[float] = None,
        confidence_before: Optional[float] = None,
        confidence_after: Optional[float] = None,
        reason_code: str = "TOOL_EXECUTED",
    ) -> AuditRecord:
        """Log a tool execution event."""
        record = AuditRecord.create(
            hash_prev=self.last_hash,
            case_id=self._case_id,
            step=self._next_step(),
            event_type=AuditEventType.TOOL_EXECUTED,
            tool=tool_name,
            reason_code=reason_code,
            reason_data={"tool": tool_name},
            evidence_before=evidence_before,
            evidence_after=evidence_after,
            risk_before=risk_before,
            risk_after=risk_after,
            confidence_before=confidence_before,
            confidence_after=confidence_after,
        )
        self._append(record)
        return record

    def log_evidence_created(
        self,
        *,
        evidence_ids: list[str],
        risk_before: Optional[float] = None,
        risk_after: Optional[float] = None,
        confidence_before: Optional[float] = None,
        confidence_after: Optional[float] = None,
        reason_code: str = "EVIDENCE_CREATED",
    ) -> AuditRecord:
        """Log creation of new evidence items."""
        record = AuditRecord.create(
            hash_prev=self.last_hash,
            case_id=self._case_id,
            step=self._next_step(),
            event_type=AuditEventType.EVIDENCE_CREATED,
            reason_code=reason_code,
            reason_data={"evidence_count": len(evidence_ids)},
            evidence_before=[],
            evidence_after=evidence_ids,
            risk_before=risk_before,
            risk_after=risk_after,
            confidence_before=confidence_before,
            confidence_after=confidence_after,
        )
        self._append(record)
        return record

    def log_stop(
        self,
        *,
        stop_reason: str,
        risk_before: Optional[float] = None,
        confidence_before: Optional[float] = None,
        evidence_ids: list[str] | None = None,
        escalation_reason: Optional[str] = None,
    ) -> AuditRecord:
        """Log the investigation stop event with the deterministic stop reason."""
        record = AuditRecord.create(
            hash_prev=self.last_hash,
            case_id=self._case_id,
            step=self._next_step(),
            event_type=AuditEventType.STOP,
            reason_code=stop_reason,
            reason_data={"stop_reason": stop_reason, "escalation_reason": escalation_reason},
            evidence_before=evidence_ids or [],
            evidence_after=evidence_ids or [],
            risk_before=risk_before,
            risk_after=risk_before,  # risk unchanged on stop
            confidence_before=confidence_before,
            confidence_after=confidence_before,
            stop_reason=stop_reason,
            escalation_reason=escalation_reason,
        )
        self._append(record)
        return record

    def log_escalation(
        self,
        *,
        escalation_reason: str,
        risk_before: Optional[float] = None,
        confidence_before: Optional[float] = None,
    ) -> AuditRecord:
        """Log an escalation request."""
        record = AuditRecord.create(
            hash_prev=self.last_hash,
            case_id=self._case_id,
            step=self._next_step(),
            event_type=AuditEventType.ESCALATION,
            reason_code="ESCALATION_REQUESTED",
            reason_data={"escalation_reason": escalation_reason},
            evidence_before=[],
            evidence_after=[],
            risk_before=risk_before,
            risk_after=risk_before,
            confidence_before=confidence_before,
            confidence_after=confidence_before,
            escalation_reason=escalation_reason,
        )
        self._append(record)
        return record

    # ------------------------------------------------------------------
    # Chain verification
    # ------------------------------------------------------------------

    def verify_chain(self) -> bool:
        """
        Re-verify the entire audit chain from genesis.

        Returns True if the chain is intact, False if any record has been
        tampered with. Raises AuditChainIntegrityError with details on failure.
        """
        if not self._records:
            return True

        prev_hash = GENESIS_HASH

        for record in self._records:
            # Check hash_prev linkage
            if record.hash_prev != prev_hash:
                raise AuditChainIntegrityError(
                    f"Chain broken at step {record.step}: "
                    f"record.hash_prev='{record.hash_prev[:16]}…' "
                    f"but expected='{prev_hash[:16]}…'"
                )
            # Re-compute hash_self
            content = record.model_dump(mode="json", exclude={"hash_self", "hash_prev"})
            expected_hash = compute_record_hash(record.hash_prev, content)
            if record.hash_self != expected_hash:
                raise AuditChainIntegrityError(
                    f"Integrity failure at step {record.step}: "
                    f"stored hash_self='{record.hash_self[:16]}…' "
                    f"does not match recomputed='{expected_hash[:16]}…'. "
                    "Record may have been tampered."
                )
            prev_hash = record.hash_self

        return True
