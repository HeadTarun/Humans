import os
import sys
import uuid
import time
from typing import List, Optional, Tuple



from app.services.ml.m2_intent_classifier import M2IntentClassifier
from app.contracts.evidence import EvidenceItem, EvidenceType, EvidenceCategory, TrustLevel, EvidenceStatus
from app.contracts.common import SourceType, Provenance
from app.contracts.ml import Prediction, ModelTask
from app.services.evidence.models import EmailEvidencePackage
from .base import BaseModelAdapter, ModelFailureError


class NLPModelAdapter(BaseModelAdapter):
    def __init__(self):
        super().__init__(
            model_name="M2IntentClassifier",
            model_version="1.0",
            task=ModelTask.PHISHING_BEC,
            category=EvidenceCategory.CONTENT
        )
        self.classifier = None
        self.is_loaded = False
        
    def load_model(self):
        # Allow the legacy module to init
        local_model_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "ml_models", "lightclassifier"))
        os.environ["M2_MODEL_PATH"] = local_model_path
        try:
            self.classifier = M2IntentClassifier()
            # If the model fails to load in the backend, it will set _MODEL_AVAILABLE to False
            if not getattr(self.classifier, "_MODEL_AVAILABLE", False):
                raise ModelFailureError("M2 model runtime unavailable")
            self.is_loaded = True
        except Exception as e:
            raise ModelFailureError(f"M2 load failed: {str(e)}")
            
    def analyze(self, package: EmailEvidencePackage, parsed_text: str = "") -> List[EvidenceItem]:
        if not self.is_loaded:
            self.load_model()
            
        evidence = []
        
        # 1. Prepare legacy input
        input_data = {
            "module": "M1",
            "status": "success",
            "normalized_text": parsed_text,
            "language": "en",
            "metadata": {
                "sender_domain": package.sender.domain if package.sender else ""
            }
        }
        
        if not input_data["normalized_text"]:
            return evidence
            
        # 2. Run inference
        started = time.perf_counter()
        try:
            result = self.classifier.process(input_data)
        except Exception as e:
            raise ModelFailureError(f"M2 processing failed: {str(e)}")
            
        latency = (time.perf_counter() - started) * 1000
        self.record_latency(latency)
        
        # 3. Model Output -> ML_SIGNAL
        status = result.get("status")
        intent_label = result.get("intent_label", "UNKNOWN")
        confidence = float(result.get("intent_confidence", 0.0))
        
        if status == "success" and intent_label != "UNKNOWN":
            pred = Prediction(
                model_name=self.model_name,
                model_version=self.model_version,
                task=self.task,
                label=intent_label,
                raw_score=confidence,
                calibrated_score=confidence, # UNCALIBRATED
                confidence=confidence,
                inference_time_ms=latency
            )
            
            # Map prediction to ML_SIGNAL evidence
            ml_signal = self._create_ml_signal(pred, package.case_id, key="intent", related_entity=intent_label)
            evidence.append(ml_signal)
            
            # If deterministic guard triggered this, it's captured in social_engineering_flags
            # "Model prediction was supported/overridden by deterministic guard conditions."
            
        # 4. Deterministic rules -> HEURISTIC
        urgency = float(result.get("urgency_score", 0.0))
        if urgency > 0.0:
            evidence.append(
                self._create_heuristic(
                    package.case_id,
                    key="urgency_score",
                    value=urgency,
                    confidence=1.0,
                    category=EvidenceCategory.SENDER_BEHAVIOR
                )
            )
            
        se_flags = result.get("social_engineering_flags", [])
        for flag in se_flags:
            evidence.append(
                self._create_heuristic(
                    package.case_id,
                    key=f"se_flag_{flag.lower()}",
                    value=True,
                    confidence=1.0,
                    category=EvidenceCategory.SENDER_BEHAVIOR
                )
            )
            
        # 5. Entity extraction -> FACT/EXTRACTED
        entities = result.get("entities", {})
        orgs = entities.get("organizations", [])
        for org in orgs:
            evidence.append(
                self._create_fact(
                    package.case_id,
                    key="mentioned_organization",
                    value=org,
                    confidence=1.0,
                    category=EvidenceCategory.CONTENT
                )
            )
            
        return evidence

    def _create_heuristic(self, case_id: str, key: str, value: any, confidence: float, category: EvidenceCategory) -> EvidenceItem:
        return EvidenceItem(
            evidence_id=f"evd_{uuid.uuid4().hex[:12]}",
            case_id=case_id,
            type=EvidenceType.HEURISTIC,
            category=category,
            key=key,
            value=value,
            source="M2IntentClassifier_Deterministic",
            source_type=SourceType.DETERMINISTIC,
            confidence=confidence,
            trust_level=TrustLevel.INFERRED,
            provenance=Provenance(
                producer_module="app.services.ml.nlp_adapter",
                extraction_method="deterministic_rule",
                model_name=self.model_name
            ),
            status=EvidenceStatus.ACTIVE
        )

    def _create_fact(self, case_id: str, key: str, value: any, confidence: float, category: EvidenceCategory) -> EvidenceItem:
        return EvidenceItem(
            evidence_id=f"evd_{uuid.uuid4().hex[:12]}",
            case_id=case_id,
            type=EvidenceType.FACT,
            category=category,
            key=key,
            value=value,
            source="M2IntentClassifier_Extractor",
            source_type=SourceType.DETERMINISTIC,
            confidence=confidence,
            trust_level=TrustLevel.EXTRACTED,
            provenance=Provenance(
                producer_module="app.services.ml.nlp_adapter",
                extraction_method="regex_extraction",
                model_name=self.model_name
            ),
            status=EvidenceStatus.ACTIVE
        )
