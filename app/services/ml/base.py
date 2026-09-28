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

    def _create_ml_signal(
        self,
        prediction: Prediction,
        case_id: str,
        key: str,
        related_entity: Optional[str] = None,
        value: Optional[Any] = None, calibration_status: str = "calibrated",
    ) -> EvidenceItem:
        # NOTE: this previously constructed Provenance(tool_name=...,
        # execution_id=...), but the Provenance contract has neither field
        # (it requires `producer_module` and has no extra fields allowed).
        # That meant EVERY successful ML prediction — from url_ml or
        # nlp_intent_ml, shared through this base class — raised a Pydantic
        # ValidationError right here, uncaught by the ModelFailureError
        # handling in the callers. In practice this meant ML tools could
        # never produce evidence even when a model successfully returned a
        # prediction; only the "model unavailable" path was ever reachable.
        #
        # `value` defaults to the raw calibrated score, matching the
        # EvidenceItem.value docstring ("ML_SIGNAL values are scores").
        # Callers whose evidence key is scored categorically in
        # risk/scoring.py's EVIDENCE_WEIGHTS table (e.g. "url_ml_risk:
        # MALICIOUS"/"SUSPICIOUS"/"BENIGN") must pass the categorical
        # `value=prediction.label` explicitly — a raw float score can never
        # match a "key:LABEL" lookup, which silently zeroed out url_ml's
        # contribution to risk regardless of how confident the model was.
        return EvidenceItem(
            evidence_id=f"evd_{uuid.uuid4().hex[:12]}",
            case_id=case_id,
            type=EvidenceType.ML_SIGNAL,
            category=self.category,
            key=key,
            value=value if value is not None else prediction.calibrated_score,
            source=self.model_name,
            source_type=SourceType.ML_MODEL,
            confidence=prediction.confidence,
            trust_level=TrustLevel.INFERRED,
            provenance=Provenance(
                producer_module=f"app.services.ml.{self.model_name}",
                extraction_method="model_inference",
                model_name=self.model_name,
                model_version=prediction.model_version,
            ),
            related_entity=related_entity,

            status=EvidenceStatus.ACTIVE,
            metadata={"calibration_status": calibration_status},
        )
