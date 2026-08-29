from datetime import datetime
from typing import List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import select, and_

from app.models.schema import CaseModel, EvidenceModel, IndicatorModel, AuditRecordModel, ReportModel
from app.contracts.evidence import EvidenceItem
from app.contracts.result import InvestigationResult
from app.contracts.audit import AuditRecord
from app.contracts.common import utcnow

class HistoricalRepository:
    def __init__(self, session: Session):
        self.session = session
        
    def save_case(self, case_id: str, status: str, result: Optional[InvestigationResult] = None, original_case_id: Optional[str] = None):
        case = self.session.execute(select(CaseModel).where(CaseModel.case_id == case_id)).scalar_one_or_none()
        if not case:
            case = CaseModel(
                case_id=case_id,
                created_at=utcnow(),
                status=status,
                original_case_id=original_case_id
            )
            self.session.add(case)
            
        if result:
            case.verdict = result.verdict.value if result.verdict else None
            case.risk_score = result.risk_score
            case.confidence = result.confidence
            case.status = result.status.value
            
        self.session.commit()

    def save_evidence(self, item: EvidenceItem):
        # Insert evidence
        ev = self.session.execute(select(EvidenceModel).where(EvidenceModel.evidence_id == item.evidence_id)).scalar_one_or_none()
        if not ev:
            ev = EvidenceModel(
                evidence_id=item.evidence_id,
                case_id=item.case_id,
                evidence_type=item.type.value,
                category=item.category.value,
                key=item.key,
                raw_json=item.model_dump(mode="json"),
                timestamp=item.timestamp
            )
            self.session.add(ev)
        else:
            ev.raw_json = item.model_dump(mode="json")
        self.session.commit()
        
    def save_indicator(self, case_id: str, evidence_id: Optional[str], indicator_type: str, indicator_value: str, timestamp: datetime):
        # We index exactly
        idx = self.session.execute(
            select(IndicatorModel)
            .where(
                and_(
                    IndicatorModel.case_id == case_id,
                    IndicatorModel.indicator_type == indicator_type,
                    IndicatorModel.indicator_value == indicator_value
                )
            )
        ).scalar_one_or_none()
        
        if not idx:
            idx = IndicatorModel(
                case_id=case_id,
                evidence_id=evidence_id,
                indicator_type=indicator_type,
                indicator_value=indicator_value,
                first_seen=timestamp
            )
            self.session.add(idx)
            self.session.commit()

    def find_historical_indicators(self, indicator_type: str, indicator_value: str, current_case_id: str) -> List[IndicatorModel]:
        """Find matches for a specific indicator, excluding the current case."""
        stmt = select(IndicatorModel).where(
            and_(
                IndicatorModel.indicator_type == indicator_type,
                IndicatorModel.indicator_value == indicator_value,
                IndicatorModel.case_id != current_case_id
            )
        )
        return list(self.session.execute(stmt).scalars().all())

    def get_case(self, case_id: str) -> Optional[CaseModel]:
        return self.session.execute(select(CaseModel).where(CaseModel.case_id == case_id)).scalar_one_or_none()
        
    def get_evidence_by_case(self, case_id: str) -> List[EvidenceModel]:
        return list(self.session.execute(select(EvidenceModel).where(EvidenceModel.case_id == case_id)).scalars().all())
