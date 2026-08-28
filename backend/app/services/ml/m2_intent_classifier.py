# COPILOT-GUARD: This file is part of the Threat Intelligence Brain pipeline.
# Class name MUST be M{N}{PascalName}. Entry method MUST be process(input_data: dict) -> dict.
# Output MUST match contracts.json M{N}_OUTPUT schema exactly.
# DO NOT suggest generic names, extra output fields, or cross-module imports.

import os
import re
import threading
import time
from pathlib import Path
from typing import Any

import json

from jsonschema import Draft7Validator, RefResolver


class ContractValidator:
    """Central schema validator backed by contracts/contracts.json."""

    def __init__(self, contracts_path: str = "contracts/contracts.json") -> None:
        self._contracts_path = Path(contracts_path)
        with self._contracts_path.open("r", encoding="utf-8") as file_pointer:
            self._contracts_document = json.load(file_pointer)
        self._resolver = RefResolver.from_schema(self._contracts_document)
        self._last_error = ""

    def validate(self, payload: dict, contract_name: str) -> bool:
        schema = self._contracts_document["contracts"][contract_name]
        validator = Draft7Validator(schema, resolver=self._resolver)
        validation_errors = sorted(validator.iter_errors(payload), key=lambda err: list(err.path))
        if validation_errors:
            self._last_error = validation_errors[0].message
            return False
        self._last_error = ""
        return True

    def get_last_error(self) -> str:
        return self._last_error

    def get_contract(self, contract_name: str) -> dict[str, Any]:
        return self._contracts_document["contracts"][contract_name]


from app.services.logging import log_json


from abc import ABC, abstractmethod


class ModuleProcessingError(Exception):
    """Base exception for module-level processing failures."""


class M1ProcessingError(ModuleProcessingError):
    """M1 processing failure."""


class M2ProcessingError(ModuleProcessingError):
    """M2 processing failure."""


class M4ProcessingError(ModuleProcessingError):
    """M4 processing failure."""


class M3ProcessingError(ModuleProcessingError):
    """M3 processing failure."""


class OrchestratorProcessingError(Exception):
    """Pipeline orchestrator failure."""

class BaseModule(ABC):
    """Abstract base class for all pipeline modules."""

    @abstractmethod
    def process(self, input_data: dict) -> dict:
        """Process input and return a contract-compliant JSON dict."""

    @abstractmethod
    def validate_input(self, data: dict) -> bool:
        """Validate input against the module input contract."""

    @abstractmethod
    def build_output(self, **kwargs) -> dict:
        """Build a module output object that matches the contract."""

class M2SchemaValidator:
    """Schema validator for M2 input payloads."""

    MODULE_INPUT_CONTRACT = "M2_INPUT"

    def __init__(self) -> None:
        self._contract_validator = ContractValidator()

    def validate(self, data: dict) -> bool:
        return self._contract_validator.validate(data, self.MODULE_INPUT_CONTRACT)

    def get_last_error(self) -> str:
        return self._contract_validator.get_last_error()

class M2IntentClassifier(BaseModule):
    """Module M2: ML intent and entity analysis."""

    MODULE_CODE = "M2"
    _CONFIDENCE_GATE = 0.55
    _LABEL_MAP = {0: "BENIGN", 1: "SPAM", 2: "SUSPICIOUS", 3: "THREAT"}
    _MODEL_PATH_ENV = "M2_MODEL_PATH"
    _MODEL_LOCK = threading.Lock()
    _MODEL_INITIALIZED = False
    _TOKENIZER: Any = None
    _MODEL: Any = None
    _TORCH: Any = None
    _MODEL_AVAILABLE = False

    def __init__(self) -> None:
        self._validator = M2SchemaValidator()
        self._ensure_model_runtime()

    def process(self, input_data: dict) -> dict:
        if not self.validate_input(input_data):
            return {
                "module": self.MODULE_CODE,
                "status": "error",
                "intent_label": "UNKNOWN",
                "intent_confidence": 0.0,
                "entities": {"urls": [], "emails": [], "phone_numbers": [], "organizations": []},
                "urgency_score": 0.0,
                "social_engineering_flags": [],
                "language": "und",
                "error_code": "SCHEMA_VIOLATION",
                "error_message": "Invalid or missing required fields",
            }
        if input_data.get("module") != "M1" or input_data.get("status") != "success":
            return {
                "module": self.MODULE_CODE,
                "status": "error",
                "intent_label": "UNKNOWN",
                "intent_confidence": 0.0,
                "entities": {"urls": [], "emails": [], "phone_numbers": [], "organizations": []},
                "urgency_score": 0.0,
                "social_engineering_flags": [],
                "language": str(input_data.get("language", "und")),
                "error_code": "SCHEMA_VIOLATION",
                "error_message": "M2 input must originate from successful M1 output",
            }
        try:
            _text = input_data["normalized_text"]
            _entities = self._extract_entities(_text, input_data)
            _intent_started_at = time.perf_counter()
            _intent_label, _intent_confidence = self._analyze_intent(_text)
            log_json(
                __name__,
                20,
                "m2_model_latency",
                diagnostic_only=True,
                location="modules.m2_intent_brain.m2_intent_classifier.process",
                model="DistilBERT",
                duration_ms=int((time.perf_counter() - _intent_started_at) * 1000),
                intent_label=_intent_label,
                intent_confidence=_intent_confidence,
            )
            _urgency_score = self._detect_urgency(_text)
            _social_engineering_flags = self._detect_social_engineering(_text)
            _before_guard = (_intent_label, _intent_confidence)
            _intent_label, _intent_confidence = self._apply_deterministic_intent_guard(
                _text,
                _intent_label,
                _intent_confidence,
                _entities,
                _social_engineering_flags,
            )
            if _before_guard != (_intent_label, _intent_confidence):
                log_json(
                    __name__,
                    20,
                    "m2_deterministic_guard_override",
                    diagnostic_only=True,
                    location="modules.m2_intent_brain.m2_intent_classifier._apply_deterministic_intent_guard",
                    original_intent_label=_before_guard[0],
                    original_intent_confidence=_before_guard[1],
                    final_intent_label=_intent_label,
                    final_intent_confidence=_intent_confidence,
                    entities=_entities,
                    social_engineering_flags=_social_engineering_flags,
                )
            return self.build_output(
                intent_label=_intent_label,
                intent_confidence=_intent_confidence,
                entities=_entities,
                urgency_score=_urgency_score,
                social_engineering_flags=_social_engineering_flags,
                language=input_data["language"],
            )
        except Exception as exc:
            _error = M2ProcessingError(str(exc))
            # Preserve the M2_MODEL_UNAVAILABLE sentinel so the orchestrator
            # can activate its degraded-mode path instead of hard-aborting.
            _error_str = str(exc)
            _error_code = (
                "M2_MODEL_UNAVAILABLE"
                if "M2_MODEL_UNAVAILABLE" in _error_str
                else "PROCESSING_FAILURE"
            )
            return {
                "module": self.MODULE_CODE,
                "status": "error",
                "intent_label": "UNKNOWN",
                "intent_confidence": 0.0,
                "entities": locals().get(
                    "_entities",
                    {"urls": [], "emails": [], "phone_numbers": [], "organizations": []},
                ),
                "urgency_score": 0.0,
                "social_engineering_flags": [],
                "language": str(input_data.get("language", "und")),
                "error_code": _error_code,
                "error_message": str(_error),
            }

    def validate_input(self, data: dict) -> bool:
        return self._validator.validate(data)

    def build_output(
        self,
        intent_label: str,
        intent_confidence: float,
        entities: dict,
        urgency_score: float,
        social_engineering_flags: list[str],
        language: str,
    ) -> dict:
        _allowed_intents = {"PHISHING", "MALWARE", "SPAM", "BENIGN", "UNKNOWN"}
        _allowed_flags = {
            "URGENCY",
            "AUTHORITY_IMPERSONATION",
            "FEAR_TRIGGER",
            "REWARD_TRIGGER",
            "CREDENTIAL_REQUEST",
            "IMPERSONATION_MISMATCH",
            "UNUSUAL_SENDER",
        }
        _safe_intent = intent_label if intent_label in _allowed_intents else "UNKNOWN"
        _safe_confidence = min(max(float(intent_confidence), 0.0), 1.0)
        _safe_urgency = min(max(float(urgency_score), 0.0), 1.0)
        _safe_flags: list[str] = []
        for _flag in social_engineering_flags:
            if _flag in _allowed_flags and _flag not in _safe_flags:
                _safe_flags.append(_flag)
        return {
            "module": self.MODULE_CODE,
            "status": "success",
            "intent_label": _safe_intent,
            "intent_confidence": _safe_confidence,
            "entities": entities,
            "urgency_score": _safe_urgency,
            "social_engineering_flags": _safe_flags,
            "language": language,
        }

    def _analyze_intent(self, text: str) -> tuple[str, float]:
        if not self.__class__._MODEL_AVAILABLE:
            # Return a sentinel that the orchestrator can detect
            log_json(
                __name__,
                30,
                "m2_model_unavailable",
                diagnostic_only=True,
                location="modules.m2_intent_brain.m2_intent_classifier._analyze_intent",
                model="DistilBERT",
                model_path=str(self.__class__._resolve_model_path()),
            )
            raise RuntimeError("M2_MODEL_UNAVAILABLE: DistilBERT model not loaded. "
                            "Set M2_MODEL_PATH or place model at modules/m2_intent_brain/distilbert_m2/")
        _tokenizer = self.__class__._TOKENIZER
        _model = self.__class__._MODEL
        _torch = self.__class__._TORCH
        if _tokenizer is None or _model is None or _torch is None:
            return "UNKNOWN", 0.0

        try:
            _inputs = _tokenizer(
                text,
                return_tensors="pt",
                truncation=True,
                max_length=512,
            )
            with _torch.no_grad():
                _outputs = _model(**_inputs)
                _probabilities = _torch.nn.functional.softmax(_outputs.logits, dim=-1)
                _confidence_tensor, _index_tensor = _torch.max(_probabilities, dim=-1)

            _predicted_index = int(_index_tensor.item())
            _confidence = round(float(_confidence_tensor.item()), 3)
            _predicted_label = self._LABEL_MAP.get(_predicted_index, "UNKNOWN")
            _final_label = _predicted_label if _confidence >= self._CONFIDENCE_GATE else "UNKNOWN"
            log_json(
                __name__,
                20,
                "m2_model_prediction",
                diagnostic_only=True,
                location="modules.m2_intent_brain.m2_intent_classifier._analyze_intent",
                model="DistilBERT",
                model_path=str(self.__class__._resolve_model_path()),
                predicted_index=_predicted_index,
                predicted_label=_predicted_label,
                confidence=_confidence,
                confidence_gate=self._CONFIDENCE_GATE,
                gate_passed=_confidence >= self._CONFIDENCE_GATE,
                final_label=_final_label,
            )
            if _confidence < self._CONFIDENCE_GATE:
                return "UNKNOWN", _confidence
            return _predicted_label, _confidence
        except (RuntimeError, ValueError, TypeError) as exc:
            log_json(
                __name__,
                30,
                "m2_model_prediction_failed",
                diagnostic_only=True,
                location="modules.m2_intent_brain.m2_intent_classifier._analyze_intent",
                model="DistilBERT",
                error_type=type(exc).__name__,
                error_message=str(exc),
            )
            return "UNKNOWN", 0.0

    @classmethod
    def _resolve_model_path(cls) -> Path:
        _configured_path = os.getenv(cls._MODEL_PATH_ENV)
        if _configured_path:
            return Path(_configured_path).expanduser()
        return Path(__file__).resolve().parent / "distilbert_m2"

    @classmethod
    def _ensure_model_runtime(cls) -> None:
        if cls._MODEL_INITIALIZED:
            return

        with cls._MODEL_LOCK:
            if cls._MODEL_INITIALIZED:
                return

            try:
                import torch
                from transformers import AutoModelForSequenceClassification, AutoTokenizer

                _model_path = str(cls._resolve_model_path())
                _tokenizer = AutoTokenizer.from_pretrained(_model_path, local_files_only=True)
                _model = AutoModelForSequenceClassification.from_pretrained(_model_path, local_files_only=True)
                _model.to("cpu")
                _model.eval()

                cls._TOKENIZER = _tokenizer
                cls._MODEL = _model
                cls._TORCH = torch
                cls._MODEL_AVAILABLE = True
                log_json(
                    __name__,
                    20,
                    "m2_model_runtime_loaded",
                    diagnostic_only=True,
                    location="modules.m2_intent_brain.m2_intent_classifier._ensure_model_runtime",
                    model="DistilBERT",
                    model_path=_model_path,
                    model_available=True,
                )
            except (ImportError, OSError, RuntimeError, ValueError) as exc:
                cls._TOKENIZER = None
                cls._MODEL = None
                cls._TORCH = None
                cls._MODEL_AVAILABLE = False
                log_json(
                    __name__,
                    30,
                    "m2_model_runtime_unavailable",
                    diagnostic_only=True,
                    location="modules.m2_intent_brain.m2_intent_classifier._ensure_model_runtime",
                    model="DistilBERT",
                    model_path=str(cls._resolve_model_path()),
                    model_available=False,
                    error_type=type(exc).__name__,
                    error_message=str(exc),
                )
            finally:
                cls._MODEL_INITIALIZED = True

    def _extract_entities(self, text: str, input_data: dict | None = None) -> dict:
        _url_pattern = r"https?://[^\s<>\"')\]]+"
        _email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
        _phone_pattern = r"\b(?:\+?\d[\d\-\s().]{7,}\d)\b"

        _raw_urls = re.findall(_url_pattern, text)
        _raw_emails = re.findall(_email_pattern, text)
        _raw_phones = re.findall(_phone_pattern, text)

        _urls: list[str] = []
        for _item in _raw_urls:
            _cleaned = _item.rstrip(".,;!?")
            if _cleaned not in _urls:
                _urls.append(_cleaned)

        _emails: list[str] = []
        for _item in _raw_emails:
            _normalized = _item.lower()
            if _normalized not in _emails:
                _emails.append(_normalized)

        _phones: list[str] = []
        for _item in _raw_phones:
            _normalized = re.sub(r"\s+", " ", _item.strip())
            if _normalized not in _phones:
                _phones.append(_normalized)

        # Use word-boundary regex instead of substring match to avoid false org detection
        _org_keywords = {
            "microsoft": r"\bmicrosoft\b",
            "google": r"\bgoogle\b",
            "amazon": r"\bamazon\b",
            "apple": r"\bapple\b",
            "paypal": r"\bpaypal\b",
            "bank": r"\bbank\b",
            "security team": r"\bsecurity\s+team\b",
            "it support": r"\bit\s+support\b",
        }
        # Trusted domains: if sender domain matches the org, it's NOT an impersonation signal
        _trusted_domain_map = {
            "google": ["google.com", "gmail.com", "googlemail.com", "googleapis.com"],
            "microsoft": ["microsoft.com", "outlook.com", "hotmail.com", "live.com"],
            "amazon": ["amazon.com", "amazonaws.com"],
            "apple": ["apple.com", "icloud.com"],
            "paypal": ["paypal.com"],
        }
        _sender_domain = ""
        if input_data:
            _sender_domain = str(input_data.get("metadata", {}).get("sender_domain", "")).lower()

        _organizations: list[str] = []
        _lower_text = text.lower()
        for _org_name, _pattern in _org_keywords.items():
            if re.search(_pattern, _lower_text):
                _trusted = _trusted_domain_map.get(_org_name, [])
                # Only flag if sender domain does NOT match the mentioned org
                if _sender_domain and any(_sender_domain.endswith(_d) for _d in _trusted):
                    continue
                _display = _org_name.upper() if " " not in _org_name else _org_name.title()
                _organizations.append(_display)

        return {
            "urls": _urls,
            "emails": _emails,
            "phone_numbers": _phones,
            "organizations": _organizations,
        }

    def _detect_urgency(self, text: str) -> float:
        _text = text.lower()
        # Multi-word phrases only — bare "now" / "today" appear in every transactional email
        _urgency_terms = (
            "urgent:",
            "urgent verify",
            "urgent action",
            "immediately verify",
            "immediately or",
            "action required:",
            "action required immediately",
            "asap",
            "within 24 hours",
            "within 48 hours",
            "respond immediately",
            "account will be suspended",
            "verify now or",
            "limited time",
        )
        _single_word_terms = ("asap",)
        _hits = sum(1 for _term in _urgency_terms if _term in _text and len(_term.split()) > 1)
        _single_hits = sum(1 for _term in _single_word_terms if _term in _text)
        if _hits == 0 and _single_hits == 0:
            return 0.0
        _score = min(0.15 * _hits + 0.05 * _single_hits, 1.0)
        if "!" in text:
            _score = min(_score + 0.1, 1.0)
        return round(_score, 3)

    def _apply_deterministic_intent_guard(
        self,
        text: str,
        intent_label: str,
        intent_confidence: float,
        entities: dict,
        social_engineering_flags: list[str],
    ) -> tuple[str, float]:
        _text = text.lower()
        _has_credential_request = "CREDENTIAL_REQUEST" in social_engineering_flags
        _has_url = bool(entities.get("urls"))
        _has_phishing_phrase = any(
            _phrase in _text
            for _phrase in (
                "verify your password",
                "verify account",
                "login to verify",
                "password at http",
            )
        )
        if _has_url and _has_credential_request and _has_phishing_phrase:
            return "PHISHING", max(float(intent_confidence), 0.9)
        return intent_label, intent_confidence

    def _detect_social_engineering(self, text: str) -> list[str]:
        _text = text.lower()
        _flags: list[str] = []

        if self._detect_urgency(text) > 0.0:
            _flags.append("URGENCY")

        if any(_phrase in _text for _phrase in ("ceo", "hr team", "it support", "bank security", "official notice")):
            _flags.append("AUTHORITY_IMPERSONATION")

        if any(_phrase in _text for _phrase in ("account suspended", "legal action", "breach", "compromised", "locked")):
            _flags.append("FEAR_TRIGGER")

        if any(_phrase in _text for _phrase in ("reward", "winner", "prize", "gift card", "bonus")):
            _flags.append("REWARD_TRIGGER")

        if any(_phrase in _text for _phrase in ("password", "login", "verify account", "otp", "security code")):
            _flags.append("CREDENTIAL_REQUEST")

        if any(_phrase in _text for _phrase in ("from ceo but", "different domain", "spoofed sender")):
            _flags.append("IMPERSONATION_MISMATCH")

        if any(_phrase in _text for _phrase in ("external sender", "unknown sender", "unrecognized sender")):
            _flags.append("UNUSUAL_SENDER")

        return _flags
