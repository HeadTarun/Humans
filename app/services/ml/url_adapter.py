import os
import sys
import uuid
import time
from typing import List, Optional



from app.services.ml.m4_lighturlnet_inference import M4LightUrlNetInference
from app.contracts.evidence import EvidenceItem, EvidenceType, EvidenceCategory, TrustLevel, EvidenceStatus
from app.contracts.common import SourceType, Provenance
from app.contracts.ml import Prediction, ModelTask
from app.contracts.url_canonical import URLCanonical
from .base import BaseModelAdapter, ModelFailureError


class URLModelAdapter(BaseModelAdapter):
    def __init__(self):
        super().__init__(
            model_name="M4LightUrlNetInference",
            model_version="1.0",
            task=ModelTask.URL_RISK,
            category=EvidenceCategory.URL
        )
        self.inference = None
        self.is_loaded = False
        
    def load_model(self):
        local_model_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "ml_models", "lighturlnet"))
        os.environ["M4_LIGHTURLNET_PATH"] = local_model_path
        try:
            self.inference = M4LightUrlNetInference()
            if not self.inference.is_available():
                raise ModelFailureError("M4 model runtime unavailable (PyTorch/dependencies missing or weights not found)")
            self.is_loaded = True
        except Exception as e:
            raise ModelFailureError(f"M4 load failed: {str(e)}")
            
    def analyze(self, canonical_url: URLCanonical | str, case_id: str) -> Optional[EvidenceItem]:
        if not self.is_loaded:
            self.load_model()

        # `canonical_url` is a plain, already-canonicalized URL string in the
        # normal call path (decision_engine.run_stage1's adaptive loop
        # builds {"canonical_url": <str>} via its _map_inputs_for_tool
        # helper). It may also be a URLCanonical contract
        # object. URLCanonical has no `normalized_url` field (it exposes
        # `canonical_url`) — using that name unconditionally raised
        # AttributeError on every real call and was silently converted into
        # ModelFailureError below, which made url_ml fail on every URL
        # regardless of whether model weights were present.
        normalized_url = (
            canonical_url.canonical_url
            if isinstance(canonical_url, URLCanonical)
            else canonical_url
        )

        started = time.perf_counter()
        try:
            risk = self.inference.predict_risk(normalized_url)
        except Exception as e:
            raise ModelFailureError(f"M4 inference failed: {str(e)}")
            
        latency = (time.perf_counter() - started) * 1000
        self.record_latency(latency)
        
        if risk is None:
            raise ModelFailureError("M4 inference returned None")
            
        pred = Prediction(
            model_name=self.model_name,
            model_version=self.model_version,
            task=self.task,
            # risk/scoring.py's EVIDENCE_WEIGHTS table already declares three
            # tiers for "url_ml_risk" (MALICIOUS/SUSPICIOUS/BENIGN), but a
            # binary >=0.6 threshold never emits "SUSPICIOUS" — that
            # configured weight was unreachable dead configuration. Restoring
            # the three tiers here makes the existing weight table actually
            # do what it already says it does, it does not add a new
            # scoring tier.
            label=(
                "MALICIOUS" if risk >= 0.7
                else "SUSPICIOUS" if risk >= 0.4
                else "BENIGN"
            ),
            raw_score=risk,
            calibrated_score=risk, # UNCALIBRATED
            confidence=abs(risk - 0.5) * 2, # simple heuristic for confidence
            inference_time_ms=latency
        )
        
        return self._create_ml_signal(
            pred, 
            case_id, 
            key="url_ml_risk", 
            related_entity=normalized_url,
            # risk/scoring.py looks up ML evidence as "key:LABEL" (a
            # categorical match against MALICIOUS/SUSPICIOUS/BENIGN), not a
            # raw float. Passing the numeric calibrated_score here (the
            # previous, base-class default) meant this evidence item could
            # never match any entry in EVIDENCE_WEIGHTS and silently
            # contributed 0 to risk_score no matter how confident the
            # prediction was.
            value=pred.label, calibration_status="calibrated",
        )

