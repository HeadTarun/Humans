"""
app/repositories/audit_repository.py
Audit record persistence.
"""
from __future__ import annotations
from sqlalchemy.orm import Session
from app.models.schema import AuditRecordModel
from sqlalchemy import select

class AuditRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def save_records(self, records: list[dict], case_id: str) -> None:
        for rec in records:
            model = AuditRecordModel(
                case_id=case_id,
                event_type=rec.get("event_type", "UNKNOWN"),
                payload=rec,
            )
            self._session.add(model)
        self._session.commit()

    def get_records_for_case(self, case_id: str) -> list[AuditRecordModel]:
        result = self._session.execute(
            select(AuditRecordModel).where(AuditRecordModel.case_id == case_id)
        )
        return list(result.scalars().all())
