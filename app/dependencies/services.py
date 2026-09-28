"""app/dependencies/services.py — FastAPI dependency injection for services."""
from functools import lru_cache
from app.services.ingestion.parser import EmailParser
from app.services.evidence import EvidenceNormalizer
from app.services.investigation import InvestigationDecisionEngine

@lru_cache(maxsize=1)
def get_email_parser() -> EmailParser:
    return EmailParser()

@lru_cache(maxsize=1)
def get_evidence_normalizer() -> EvidenceNormalizer:
    return EvidenceNormalizer()

@lru_cache(maxsize=1)
def get_investigation_engine() -> InvestigationDecisionEngine:
    return InvestigationDecisionEngine()

__all__ = ["get_email_parser", "get_evidence_normalizer", "get_investigation_engine"]
