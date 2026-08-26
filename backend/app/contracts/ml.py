"""
contracts/ml.py

Model-agnostic prediction envelope (§7-10). Model adapters (see §33) are
the ONLY code that knows about tokenizers, checkpoints, or framework
internals; everything else consumes `Prediction` / its subtypes.

A Prediction is never itself an EvidenceItem — it is converted into one
(type=ML_SIGNAL) by the calling adapter, which attaches Provenance.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import Field, field_validator

from .common import BaseContract


class ModelTask(str, Enum):
    HEADER_RISK = "HEADER_RISK"
    PHISHING_BEC = "PHISHING_BEC"
    URL_RISK = "URL_RISK"


class Prediction(BaseContract):
    model_name: str
    model_version: str
    task: ModelTask
    label: str
    raw_score: float = Field(..., ge=0.0, le=1.0)
    calibrated_score: float = Field(..., ge=0.0, le=1.0)
    confidence: float = Field(..., ge=0.0, le=1.0)
    inference_time_ms: float = Field(..., ge=0.0)
    features_reference: Optional[str] = Field(
        default=None, description="Pointer to the feature vector used, for reproducibility/audit"
    )


class HeaderFeatures(BaseContract):
    case_id: str
    feature_vector_reference: str
    raw_features: dict[str, float] = Field(default_factory=dict)


class HeaderPrediction(Prediction):
    @field_validator("task")
    @classmethod
    def _fixed_task(cls, v: ModelTask) -> ModelTask:
        if v != ModelTask.HEADER_RISK:
            raise ValueError("HeaderPrediction.task must be HEADER_RISK")
        return v


class NLPLabel(str, Enum):
    PHISHING = "phishing"
    CREDENTIAL_PHISHING = "credential_phishing"
    BEC = "bec"
    EXECUTIVE_IMPERSONATION = "executive_impersonation"
    VENDOR_FRAUD = "vendor_fraud"
    PAYMENT_DIVERSION = "payment_diversion"
    SOCIAL_ENGINEERING = "social_engineering"
    URGENCY = "urgency"


class NLPAnalysisResult(BaseContract):
    """Multi-label output (§9). Converted into one ML_SIGNAL EvidenceItem per label."""

    case_id: str
    model_name: str
    model_version: str
    label_scores: dict[NLPLabel, float] = Field(default_factory=dict)
    inference_time_ms: float = Field(..., ge=0.0)
    features_reference: Optional[str] = None

    @field_validator("label_scores")
    @classmethod
    def _scores_in_range(cls, v: dict[NLPLabel, float]) -> dict[NLPLabel, float]:
        for label, score in v.items():
            if not (0.0 <= score <= 1.0):
                raise ValueError(f"label {label} score {score} out of [0,1] range")
        return v


class URLPrediction(Prediction):
    url_id: str

    @field_validator("task")
    @classmethod
    def _fixed_task(cls, v: ModelTask) -> ModelTask:
        if v != ModelTask.URL_RISK:
            raise ValueError("URLPrediction.task must be URL_RISK")
        return v
