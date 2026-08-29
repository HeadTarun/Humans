import pytest
import asyncio
from app.contracts.evidence import EvidenceItem, EvidenceType, EvidenceCategory, TrustLevel, SourceType
from app.contracts.common import utcnow, Provenance
from app.services.risk.conflict_engine import ConflictEngine
from app.services.risk.confidence import calculate_confidence
from app.contracts.risk import ConflictSeverity

def test_conflict_url_ml_vs_reputation():
    engine = ConflictEngine()
    ev1 = EvidenceItem(
        evidence_id="ml1", case_id="c1", type=EvidenceType.ML_SIGNAL, category=EvidenceCategory.URL,
        key="url_ml_suspicious", value=0.9, confidence=0.9, source="url_ml",
        source_type=SourceType.ML_MODEL, trust_level=TrustLevel.INFERRED,
        timestamp=utcnow(), provenance=Provenance(producer_module="test", extraction_method="test"),
        related_entity="http://evil.com"
    )
    ev2 = EvidenceItem(
        evidence_id="rep1", case_id="c1", type=EvidenceType.FACT, category=EvidenceCategory.URL,
        key="url_reputation", value="clean", confidence=1.0, source="url_reputation",
        source_type=SourceType.DETERMINISTIC, trust_level=TrustLevel.VERIFIED,
        timestamp=utcnow(), provenance=Provenance(producer_module="test", extraction_method="test"),
        related_entity="http://evil.com"
    )
    
    conflicts = engine.detect_conflicts([ev1, ev2])
    assert len(conflicts) == 1
    assert conflicts[0].severity == ConflictSeverity.HIGH
    assert conflicts[0].evidence_a_id == "ml1"
    assert conflicts[0].evidence_b_id == "rep1"

def test_no_conflict_different_entities():
    engine = ConflictEngine()
    ev1 = EvidenceItem(
        evidence_id="ml1", case_id="c1", type=EvidenceType.ML_SIGNAL, category=EvidenceCategory.URL,
        key="url_ml_suspicious", value=0.9, confidence=0.9, source="url_ml",
        source_type=SourceType.ML_MODEL, trust_level=TrustLevel.INFERRED,
        timestamp=utcnow(), provenance=Provenance(producer_module="test", extraction_method="test"),
        related_entity="http://evil.com"
    )
    ev2 = EvidenceItem(
        evidence_id="rep1", case_id="c1", type=EvidenceType.FACT, category=EvidenceCategory.URL,
        key="url_reputation", value="clean", confidence=1.0, source="url_reputation",
        source_type=SourceType.DETERMINISTIC, trust_level=TrustLevel.VERIFIED,
        timestamp=utcnow(), provenance=Provenance(producer_module="test", extraction_method="test"),
        related_entity="http://other.com"
    )
    
    conflicts = engine.detect_conflicts([ev1, ev2])
    assert len(conflicts) == 0

def test_conflict_reduces_confidence():
    ev1 = EvidenceItem(
        evidence_id="ml1", case_id="c1", type=EvidenceType.ML_SIGNAL, category=EvidenceCategory.URL,
        key="url_ml_suspicious", value=0.9, confidence=0.9, source="url_ml",
        source_type=SourceType.ML_MODEL, trust_level=TrustLevel.INFERRED,
        timestamp=utcnow(), provenance=Provenance(producer_module="test", extraction_method="test"),
        related_entity="http://evil.com"
    )
    ev2 = EvidenceItem(
        evidence_id="rep1", case_id="c1", type=EvidenceType.FACT, category=EvidenceCategory.URL,
        key="url_reputation", value="clean", confidence=1.0, source="url_reputation",
        source_type=SourceType.DETERMINISTIC, trust_level=TrustLevel.VERIFIED,
        timestamp=utcnow(), provenance=Provenance(producer_module="test", extraction_method="test"),
        related_entity="http://evil.com"
    )
    
    # Without conflict
    conf1 = calculate_confidence([ev1, ev2], expected_evidence_count=2)
    
    # With active conflict
    conflicts = ConflictEngine().detect_conflicts([ev1, ev2])
    active_conflicts = [c.model_dump() for c in conflicts]
    conf2 = calculate_confidence([ev1, ev2], active_conflicts=active_conflicts, expected_evidence_count=2)
    
    assert conf2.confidence_score < conf1.confidence_score

def test_historical_evidence_cap():
    ev1 = EvidenceItem(
        evidence_id="hist1", case_id="c1", type=EvidenceType.FACT, category=EvidenceCategory.IOC,
        key="historical_exact_match", value=True, confidence=1.0, source="db",
        source_type=SourceType.DETERMINISTIC, trust_level=TrustLevel.VERIFIED,
        timestamp=utcnow(), provenance=Provenance(producer_module="test", extraction_method="test"),
    )
    # Only historical
    conf = calculate_confidence([ev1], expected_evidence_count=1)
    assert conf.confidence_score <= 0.70
