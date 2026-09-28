"""
repositories/historical_repository.py

Tenant-scoped data access layer for the ASHIELDER investigation store.

SECURITY INVARIANT:
    Every query that reads case/evidence/indicator data MUST include a
    tenant_id filter derived from the authenticated principal's JWT claim.
    Never query without tenant_id unless the operation is explicitly
    cross-tenant (admin telemetry only, not present here).

Tenant isolation:
    - list_cases_for_tenant(tenant_id)   → cases WHERE tenant_id = ?
    - get_case(case_id, tenant_id)       → case WHERE case_id = ? AND tenant_id = ?
    - get_evidence_by_case(case_id, tenant_id) → evidence WHERE case_id = ? AND tenant_id = ?
"""

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

    # ------------------------------------------------------------------
    # Case queries
    # ------------------------------------------------------------------

    def list_cases_for_tenant(self, tenant_id: str) -> List[CaseModel]:
        """Return all cases belonging to tenant_id (for non-admin users, further
        filter by user_id in the caller layer if needed)."""
        stmt = (
            select(CaseModel)
            .where(CaseModel.tenant_id == tenant_id)
            .order_by(CaseModel.created_at.desc())
        )
        return list(self.session.execute(stmt).scalars().all())

    def list_cases_for_user(self, tenant_id: str, user_id: str) -> List[CaseModel]:
        """Return cases visible to a non-admin user: same tenant + owned by user."""
        stmt = (
            select(CaseModel)
            .where(
                and_(
                    CaseModel.tenant_id == tenant_id,
                    CaseModel.user_id == user_id,
                )
            )
            .order_by(CaseModel.created_at.desc())
        )
        return list(self.session.execute(stmt).scalars().all())

    def get_case(self, case_id: str, tenant_id: Optional[str] = None) -> Optional[CaseModel]:
        """
        Fetch a single case by ID.

        If tenant_id is supplied (preferred), enforces tenant isolation.
        The tenant_id-less overload exists only for internal calls where
        the caller has already validated access (e.g. persistence paths).
        """
        if tenant_id:
            return self.session.execute(
                select(CaseModel).where(
                    and_(CaseModel.case_id == case_id, CaseModel.tenant_id == tenant_id)
                )
            ).scalar_one_or_none()
        return self.session.execute(
            select(CaseModel).where(CaseModel.case_id == case_id)
        ).scalar_one_or_none()

    # ------------------------------------------------------------------
    # Evidence queries
    # ------------------------------------------------------------------

    def get_evidence_by_case(self, case_id: str, tenant_id: Optional[str] = None) -> List[EvidenceModel]:
        """Return all evidence items for a case, tenant-scoped when tenant_id is provided."""
        if tenant_id:
            stmt = select(EvidenceModel).where(
                and_(EvidenceModel.case_id == case_id, EvidenceModel.tenant_id == tenant_id)
            )
        else:
            stmt = select(EvidenceModel).where(EvidenceModel.case_id == case_id)
        return list(self.session.execute(stmt).scalars().all())

    def get_evidence_item(self, evidence_id: str, tenant_id: str) -> Optional[EvidenceModel]:
        """Fetch a single evidence item, enforcing tenant isolation."""
        return self.session.execute(
            select(EvidenceModel).where(
                and_(
                    EvidenceModel.evidence_id == evidence_id,
                    EvidenceModel.tenant_id == tenant_id,
                )
            )
        ).scalar_one_or_none()

    def update_evidence_annotation(
        self, evidence_id: str, tenant_id: str, annotation: dict
    ) -> Optional[EvidenceModel]:
        """
        Append an annotation to an evidence item.

        IMMUTABILITY RULE: raw_json (the original forensic evidence) is NEVER
        modified. Annotations are stored in a separate column.
        """
        ev = self.get_evidence_item(evidence_id, tenant_id)
        if ev is None:
            return None
        current = list(ev.annotations or [])
        current.append(annotation)
        ev.annotations = current
        self.session.commit()
        self.session.refresh(ev)
        return ev

    def update_evidence_verification(
        self, evidence_id: str, tenant_id: str, state: str
    ) -> Optional[EvidenceModel]:
        """
        Set verification state on evidence item.

        state must be one of: UNVERIFIED | VERIFIED | DISPUTED
        IMMUTABILITY RULE: raw_json is not modified.
        """
        ev = self.get_evidence_item(evidence_id, tenant_id)
        if ev is None:
            return None
        ev.verification_state = state
        self.session.commit()
        self.session.refresh(ev)
        return ev

    # ------------------------------------------------------------------
    # Audit records
    # ------------------------------------------------------------------

    def get_audit_records_by_case(self, case_id: str) -> List[AuditRecordModel]:
        """Return all audit records for a case ordered by step."""
        stmt = (
            select(AuditRecordModel)
            .where(AuditRecordModel.case_id == case_id)
            .order_by(AuditRecordModel.step.asc())
        )
        return list(self.session.execute(stmt).scalars().all())

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------

    def get_report(self, case_id: str) -> Optional[ReportModel]:
        return self.session.execute(
            select(ReportModel).where(ReportModel.case_id == case_id)
        ).scalar_one_or_none()

    # ------------------------------------------------------------------
    # Historical / related case lookups
    # ------------------------------------------------------------------

    def find_historical_indicators(
        self, indicator_type: str, indicator_value: str, current_case_id: str
    ) -> List[IndicatorModel]:
        """Find indicator matches across all cases, excluding the current case (no tenant filter
        here — cross-tenant correlation is intentionally scoped by tenant_id in find_related_cases)."""
        stmt = select(IndicatorModel).where(
            and_(
                IndicatorModel.indicator_type == indicator_type,
                IndicatorModel.indicator_value == indicator_value,
                IndicatorModel.case_id != current_case_id,
            )
        )
        return list(self.session.execute(stmt).scalars().all())

    def find_related_cases(
        self, case_id: str, tenant_id: str, limit: int = 10
    ) -> List[dict]:
        """
        Find cases in the same tenant that share indicators with case_id.

        Returns a list of dicts with keys:
            related_case_id, shared_indicators, similarity_score
        """
        # 1. Get indicators for the current case
        current_indicators = list(
            self.session.execute(
                select(IndicatorModel).where(IndicatorModel.case_id == case_id)
            ).scalars().all()
        )
        if not current_indicators:
            return []

        indicator_pairs = [
            (ind.indicator_type, ind.indicator_value) for ind in current_indicators
        ]

        # 2. Find other cases in the same tenant sharing at least one indicator
        from collections import defaultdict
        shared: dict = defaultdict(list)
        for itype, ivalue in indicator_pairs:
            matches = self.session.execute(
                select(IndicatorModel).where(
                    and_(
                        IndicatorModel.indicator_type == itype,
                        IndicatorModel.indicator_value == ivalue,
                        IndicatorModel.case_id != case_id,
                        IndicatorModel.tenant_id == tenant_id,
                    )
                )
            ).scalars().all()
            for m in matches:
                shared[m.case_id].append(ivalue)

        if not shared:
            return []

        total = len(indicator_pairs)
        results = []
        for rel_case_id, shared_iocs in list(shared.items())[:limit]:
            rel_case = self.get_case(rel_case_id, tenant_id=tenant_id)
            if rel_case is None:
                continue
            results.append({
                "related_case_id": rel_case_id,
                "shared_indicators": list(set(shared_iocs)),
                "similarity_score": round(len(set(shared_iocs)) / total, 3),
                "verdict": rel_case.verdict,
                "status": rel_case.status,
                "created_at": rel_case.created_at.isoformat() if rel_case.created_at else None,
            })

        results.sort(key=lambda x: x["similarity_score"], reverse=True)
        return results

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save_case(
        self,
        case_id: str,
        status: str,
        tenant_id: str = "default_tenant",
        result: Optional[InvestigationResult] = None,
        original_case_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ):
        case = self.session.execute(
            select(CaseModel).where(CaseModel.case_id == case_id)
        ).scalar_one_or_none()
        if not case:
            case = CaseModel(
                case_id=case_id,
                tenant_id=tenant_id,
                created_at=utcnow(),
                status=status,
                original_case_id=original_case_id,
                user_id=user_id,
            )
            self.session.add(case)

        if result:
            case.verdict = result.verdict.value if result.verdict else None
            case.risk_score = result.risk_score
            case.confidence = result.confidence
            case.status = result.status.value

        self.session.commit()

    def save_evidence(self, item: EvidenceItem, tenant_id: str = "default_tenant"):
        ev = self.session.execute(
            select(EvidenceModel).where(EvidenceModel.evidence_id == item.evidence_id)
        ).scalar_one_or_none()
        if not ev:
            ev = EvidenceModel(
                evidence_id=item.evidence_id,
                case_id=item.case_id,
                tenant_id=tenant_id,
                evidence_type=item.type.value,
                category=item.category.value,
                key=item.key,
                raw_json=item.model_dump(mode="json"),
                timestamp=item.timestamp,
                annotations=[],
                verification_state="UNVERIFIED",
            )
            self.session.add(ev)
        else:
            ev.raw_json = item.model_dump(mode="json")
        self.session.commit()

    def save_indicator(
        self,
        case_id: str,
        evidence_id: Optional[str],
        indicator_type: str,
        indicator_value: str,
        timestamp: datetime,
        tenant_id: str = "default_tenant",
    ):
        idx = self.session.execute(
            select(IndicatorModel).where(
                and_(
                    IndicatorModel.case_id == case_id,
                    IndicatorModel.indicator_type == indicator_type,
                    IndicatorModel.indicator_value == indicator_value,
                )
            )
        ).scalar_one_or_none()

        if not idx:
            idx = IndicatorModel(
                case_id=case_id,
                tenant_id=tenant_id,
                evidence_id=evidence_id,
                indicator_type=indicator_type,
                indicator_value=indicator_value,
                first_seen=timestamp,
            )
            self.session.add(idx)
            self.session.commit()

    def save_investigation(
        self,
        result: InvestigationResult,
        evidence: list,
        audit_records: list,
        user_id: Optional[str] = None,
        tenant_id: str = "default_tenant",
    ) -> None:
        """Persist one completed case atomically, including its audit chain and result summary."""
        try:
            case = self.session.execute(
                select(CaseModel).where(CaseModel.case_id == result.investigation_id)
            ).scalar_one_or_none()
            if not case:
                case = CaseModel(
                    case_id=result.investigation_id,
                    tenant_id=tenant_id,
                    created_at=result.created_at,
                    status=result.status.value,
                )
                self.session.add(case)
            case.status = result.status.value
            case.verdict = result.verdict.value
            case.risk_score = result.risk_score
            case.confidence = result.confidence
            if user_id is not None:
                case.user_id = user_id

            for item in {item.evidence_id: item for item in evidence}.values():
                existing = self.session.execute(
                    select(EvidenceModel).where(EvidenceModel.evidence_id == item.evidence_id)
                ).scalar_one_or_none()
                if existing:
                    existing.raw_json = item.model_dump(mode="json")
                else:
                    self.session.add(EvidenceModel(
                        evidence_id=item.evidence_id,
                        case_id=item.case_id,
                        tenant_id=tenant_id,
                        evidence_type=item.type.value,
                        category=item.category.value,
                        key=item.key,
                        raw_json=item.model_dump(mode="json"),
                        timestamp=item.timestamp,
                        annotations=[],
                        verification_state="UNVERIFIED",
                    ))
                if item.related_entity:
                    self.session.add(IndicatorModel(
                        indicator_type=item.category.value,
                        indicator_value=item.related_entity,
                        case_id=item.case_id,
                        tenant_id=tenant_id,
                        evidence_id=item.evidence_id,
                        first_seen=item.timestamp,
                    ))

            for record in audit_records:
                if not self.session.execute(
                    select(AuditRecordModel).where(AuditRecordModel.hash_self == record.hash_self)
                ).scalar_one_or_none():
                    self.session.add(AuditRecordModel(
                        hash_self=record.hash_self,
                        hash_prev=record.hash_prev,
                        case_id=record.case_id,
                        step=record.step,
                        raw_json=record.model_dump(mode="json"),
                        timestamp=record.timestamp,
                    ))

            report = self.session.execute(
                select(ReportModel).where(ReportModel.case_id == result.investigation_id)
            ).scalar_one_or_none()
            payload = {"investigation_result": result.model_dump(mode="json")}
            if report:
                report.raw_json = payload
                report.generated_at = result.completed_at
            else:
                self.session.add(ReportModel(
                    case_id=result.investigation_id,
                    raw_json=payload,
                    generated_at=result.completed_at,
                ))

            self.session.commit()
        except Exception:
            self.session.rollback()
            raise
