import uuid
from datetime import datetime
from typing import Any, Dict, Optional, List
import time

from app.contracts.evidence import EvidenceItem, EvidenceType, EvidenceCategory, TrustLevel, EvidenceStatus
from app.contracts.common import SourceType, Provenance
from app.contracts.ml import Prediction, ModelTask

class ModelFailureError(Exception):
    pass

class BaseModelAdapter:
    """Base class for ML adapters."""
    
    def __init__(self, model_name: str, model_version: str, task: ModelTask, category: EvidenceCategory):
        self.model_name = model_name
        self.model_version = model_version
        self.task = task
        self.category = category
        self.latency_stats = []
        
    def record_latency(self, latency_ms: float):
        self.latency_stats.append(latency_ms)

    def _create_ml_signal(self, prediction: Prediction, case_id: str, key: str, related_entity: Optional[str] = None) -> EvidenceItem:
        return EvidenceItem(
            evidence_id=f"evd_{uuid.uuid4().hex[:12]}",
            case_id=case_id,
            type=EvidenceType.ML_SIGNAL,
            category=self.category,
            key=key,
            value=prediction.calibrated_score,
            source=self.model_name,
            source_type=SourceType.ML_MODEL,
            confidence=prediction.confidence,
            trust_level=TrustLevel.INFERRED,
            provenance=Provenance(
                tool_name=self.model_name,
                execution_id=f"exec_{uuid.uuid4().hex[:8]}"
            ),
            related_entity=related_entity,
            status=EvidenceStatus.ACTIVE
        )
