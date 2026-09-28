import uuid
from typing import List
from app.contracts.evidence import EvidenceItem
from app.contracts.risk import EvidenceConflict, ConflictType, ConflictSeverity, ConflictStatus

class ConflictEngine:
    def detect_conflicts(self, evidence_items: List[EvidenceItem]) -> List[EvidenceConflict]:
        conflicts = []
        
        url_mls = [e for e in evidence_items if e.key == 'url_ml_risk']
        url_reps = [e for e in evidence_items if e.key == 'url_reputation']
        
        for ml in url_mls:
            for rep in url_reps:
                if ml.related_entity == rep.related_entity and ml.related_entity:
                    ml_is_suspicious = str(ml.value).upper() in ["MALICIOUS", "SUSPICIOUS"]
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

        # Provider disagreement is material forensic context. It is kept in
        # the evidence set and surfaced here; scoring independently applies
        # a severity-precedence rule to avoid double counting it.
        reputation = [e for e in evidence_items if e.type.value == "THREAT_INTEL" and e.related_entity]
        for index, first in enumerate(reputation):
            for second in reputation[index + 1:]:
                if (first.related_entity == second.related_entity and first.key == second.key
                        and first.source != second.source and str(first.value) != str(second.value)):
                    conflicts.append(EvidenceConflict(
                        conflict_id=f"cf_{uuid.uuid4().hex[:8]}",
                        evidence_a_id=first.evidence_id,
                        evidence_b_id=second.evidence_id,
                        conflict_type=ConflictType.CROSS_TOOL_DISAGREEMENT,
                        severity=ConflictSeverity.HIGH,
                        status=ConflictStatus.OPEN,
                    ))
                        
        # Historical vs Current
        # Add logic if necessary.
        
        return conflicts
