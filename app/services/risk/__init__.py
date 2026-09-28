"""
services/risk — Deterministic Risk Assessment Engine (Stage 2)

Public API:

    RiskEngine        — main engine class, call .assess()
    RiskEngineResult  — output dataclass (risk_assessment, confidence_assessment, verdict)
    EVIDENCE_WEIGHTS  — the weight table (single source of truth)
    MIN_CONFIDENCE_FOR_VERDICT — threshold below which verdict → INCONCLUSIVE
    MALICIOUS_RISK_THRESHOLD   — risk score threshold for MALICIOUS
    SUSPICIOUS_RISK_THRESHOLD  — risk score threshold for SUSPICIOUS
"""

from .engine import RiskEngine, RiskEngineResult
from .scoring import EVIDENCE_WEIGHTS, score_evidence_items
from .confidence import calculate_confidence
from .verdict import (
    MIN_CONFIDENCE_FOR_VERDICT,
    MALICIOUS_RISK_THRESHOLD,
    SUSPICIOUS_RISK_THRESHOLD,
    assign_verdict,
    assign_verdict_with_stop_guard,
)

__all__ = [
    "RiskEngine",
    "RiskEngineResult",
    "EVIDENCE_WEIGHTS",
    "score_evidence_items",
    "calculate_confidence",
    "MIN_CONFIDENCE_FOR_VERDICT",
    "MALICIOUS_RISK_THRESHOLD",
    "SUSPICIOUS_RISK_THRESHOLD",
    "assign_verdict",
    "assign_verdict_with_stop_guard",
]
