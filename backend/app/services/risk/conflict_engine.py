import uuid
from typing import List
from app.contracts.evidence import EvidenceItem
from app.contracts.risk import EvidenceConflict, ConflictType, ConflictSeverity, ConflictStatus

class ConflictEngine:
    def detect_conflicts(self, evidence_items: List[EvidenceItem]) -> List[EvidenceConflict]:
        conflicts = []
        
        # URL ML vs URL Reputation (must be same URL)
        url_mls = [e for e in evidence_items if e.key in ['url_ml_suspicious', 'url_ml_phishing']]
        url_reps = [e for e in evidence_items if e.key == 'url_reputation']
        
        for ml in url_mls:
            for rep in url_reps:
                if ml.related_entity == rep.related_entity and ml.related_entity:
                    ml_is_suspicious = (float(ml.value) > 0.5)
                    rep_is_clean = (str(rep.value).lower() == 'clean')
                    if ml_is_suspicious and rep_is_clean:
                        # HIGH severity because reputation is reliable but ML thinks bad
                        conflicts.append(
                            EvidenceConflict(
                                conflict_id=f"cf_{uuid.uuid4().hex[:8]}",
                                evidence_a_id=ml.evidence_id,
                                evidence_b_id=rep.evidence_id,
                                conflict_type=ConflictType.ML_VS_REPUTATION,
                                severity=ConflictSeverity.HIGH,
                                status=ConflictStatus.OPEN
                            )
                        )
                        
        # Historical vs Current
        # Add logic if necessary.
        
        return conflicts
