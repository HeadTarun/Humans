"""
app/repositories/email_repository.py
Minimal email metadata repository.
"""
from typing import Optional
from sqlalchemy.orm import Session
from sqlalchemy import select
from app.models.schema import CaseModel

class EmailRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def update_email_metadata(self, case_id: str, eml_sha256: str, eml_storage_path: str) -> Optional[CaseModel]:
        """Update email metadata (raw .eml storage) for a specific case."""
        case = self._session.execute(
            select(CaseModel).where(CaseModel.case_id == case_id)
        ).scalar_one_or_none()
        
        if case:
            case.eml_sha256 = eml_sha256
            case.eml_storage_path = eml_storage_path
            self._session.commit()
            self._session.refresh(case)
        return case

    def get_email_metadata(self, case_id: str) -> Optional[dict]:
        """Get email metadata for a case."""
        case = self._session.execute(
            select(CaseModel).where(CaseModel.case_id == case_id)
        ).scalar_one_or_none()
        
        if case and (case.eml_sha256 or case.eml_storage_path):
            return {
                "case_id": case.case_id,
                "eml_sha256": case.eml_sha256,
                "eml_storage_path": case.eml_storage_path
            }
        return None
