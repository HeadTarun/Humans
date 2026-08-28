import json
import math
import os
import threading
import time
import warnings
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from app.services.logging import log_json


class M4LightUrlNetInference:
    """Lazy local inference wrapper for the M4 LightURLNet URL classifier."""

    _MODEL_PATH_ENV = "M4_LIGHTURLNET_PATH"
    _MODEL_LOCK = threading.Lock()
    _MODEL_INITIALIZED = False
    _MODEL_AVAILABLE = False
    _MODEL: Any = None
    _SCALER: Any = None
    _CHAR2IDX: dict[str, int] = {}
    _CONFIG: dict[str, Any] = {}
    _TORCH: Any = None

    def __init__(self) -> None:
        self._ensure_model_runtime()

    @classmethod
    def is_available(cls) -> bool:
        cls._ensure_model_runtime()
        return cls._MODEL_AVAILABLE

    @classmethod
    def _resolve_model_path(cls) -> Path:
        _configured_path = os.getenv(cls._MODEL_PATH_ENV)
        if _configured_path:
            return Path(_configured_path).expanduser()
        return Path(__file__).resolve().parent / "lighturlnet"

    @classmethod
    def _ensure_model_runtime(cls) -> None:
        if cls._MODEL_INITIALIZED:
            return

        with cls._MODEL_LOCK:
            if cls._MODEL_INITIALIZED:
                return

            try:
                import joblib
                import torch
                import torch.nn as nn
                import torch.nn.functional as functional

                class _LightURLNet(nn.Module):
                    def __init__(self, vocab_size: int, embed_dim: int, numerical_features: int) -> None:
                        super().__init__()
                        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
                        self.conv3 = nn.Conv1d(embed_dim, 64, kernel_size=3, padding=1)
                        self.conv5 = nn.Conv1d(embed_dim, 64, kernel_size=5, padding=2)
                        self.conv7 = nn.Conv1d(embed_dim, 64, kernel_size=7, padding=3)
                        self.fc1 = nn.Linear(64 * 3 + numerical_features, 128)
                        self.fc2 = nn.Linear(128, 1)

                    def forward(self, char_input, numeric_input):
                        _embedded = self.embedding(char_input).permute(0, 2, 1)
                        _pooled = [
                            functional.max_pool1d(functional.relu(_conv(_embedded)), kernel_size=_embedded.shape[-1]).squeeze(-1)
                            for _conv in (self.conv3, self.conv5, self.conv7)
                        ]
                        _features = torch.cat([*_pooled, numeric_input], dim=1)
                        return self.fc2(functional.relu(self.fc1(_features)))

                _model_path = cls._resolve_model_path()
                with (_model_path / "config.json").open("r", encoding="utf-8") as _config_file:
                    _config = json.load(_config_file)
                with (_model_path / "char2idx.json").open("r", encoding="utf-8") as _char_file:
                    _char2idx = json.load(_char_file)

                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    _scaler = joblib.load(_model_path / "scaler.pkl")
                _numerical_features = int(getattr(_scaler, "n_features_in_", 5))
                _model = _LightURLNet(
                    vocab_size=int(_config["vocab_size"]),
                    embed_dim=int(_config["embed_dim"]),
                    numerical_features=_numerical_features,
                )
                _state_dict = torch.load(_model_path / "lighturlnet.pth", map_location="cpu")
                _model.load_state_dict(_state_dict)
                _model.to("cpu")
                _model.eval()

                cls._MODEL = _model
                cls._SCALER = _scaler
                cls._CHAR2IDX = {str(_key): int(_value) for _key, _value in _char2idx.items()}
                cls._CONFIG = _config
                cls._TORCH = torch
                cls._MODEL_AVAILABLE = True
                log_json(
                    __name__,
                    20,
                    "m4_lighturlnet_runtime_loaded",
                    diagnostic_only=True,
                    location="modules.m4_link_intelligence.m4_lighturlnet_inference._ensure_model_runtime",
                    model="LightURLNet",
                    model_path=str(_model_path),
                    model_available=True,
                )
            except (ImportError, OSError, RuntimeError, ValueError, KeyError, AttributeError) as exc:
                cls._MODEL = None
                cls._SCALER = None
                cls._CHAR2IDX = {}
                cls._CONFIG = {}
                cls._TORCH = None
                cls._MODEL_AVAILABLE = False
                log_json(
                    __name__,
                    30,
                    "m4_lighturlnet_runtime_unavailable",
                    diagnostic_only=True,
                    location="modules.m4_link_intelligence.m4_lighturlnet_inference._ensure_model_runtime",
                    model="LightURLNet",
                    model_path=str(cls._resolve_model_path()),
                    model_available=False,
                    error_type=type(exc).__name__,
                    error_message=str(exc),
                )
            finally:
                cls._MODEL_INITIALIZED = True

    def predict_risk(self, normalized_url: str) -> float | None:
        if not self.__class__._MODEL_AVAILABLE:
            log_json(
                __name__,
                30,
                "m4_lighturlnet_fallback_to_heuristics",
                diagnostic_only=True,
                location="modules.m4_link_intelligence.m4_lighturlnet_inference.predict_risk",
                model="LightURLNet",
                reason="model_unavailable",
                normalized_url=normalized_url,
            )
            return None

        _torch = self.__class__._TORCH
        _model = self.__class__._MODEL
        _scaler = self.__class__._SCALER
        if _torch is None or _model is None or _scaler is None:
            log_json(
                __name__,
                30,
                "m4_lighturlnet_fallback_to_heuristics",
                diagnostic_only=True,
                location="modules.m4_link_intelligence.m4_lighturlnet_inference.predict_risk",
                model="LightURLNet",
                reason="runtime_missing",
                normalized_url=normalized_url,
            )
            return None

        try:
            _started_at = time.perf_counter()
            _char_tensor = self._encode_url(normalized_url)
            _numeric_tensor = self._encode_numeric_features(normalized_url)
            with _torch.no_grad():
                _logit = _model(_char_tensor, _numeric_tensor)
                _probability = _torch.sigmoid(_logit).item()
            _risk = round(max(0.0, min(1.0, float(_probability))), 3)
            log_json(
                __name__,
                20,
                "m4_lighturlnet_prediction",
                diagnostic_only=True,
                location="modules.m4_link_intelligence.m4_lighturlnet_inference.predict_risk",
                model="LightURLNet",
                normalized_url=normalized_url,
                probability=_risk,
                duration_ms=int((time.perf_counter() - _started_at) * 1000),
            )
            return _risk
        except (RuntimeError, ValueError, TypeError, AttributeError) as exc:
            log_json(
                __name__,
                30,
                "m4_lighturlnet_fallback_to_heuristics",
                diagnostic_only=True,
                location="modules.m4_link_intelligence.m4_lighturlnet_inference.predict_risk",
                model="LightURLNet",
                reason="prediction_error",
                normalized_url=normalized_url,
                error_type=type(exc).__name__,
                error_message=str(exc),
            )
            return None

    def _encode_url(self, normalized_url: str):
        _torch = self.__class__._TORCH
        _max_len = int(self.__class__._CONFIG.get("max_len", 200))
        _ids = [self.__class__._CHAR2IDX.get(_char, 0) for _char in normalized_url[:_max_len]]
        if len(_ids) < _max_len:
            _ids.extend([0] * (_max_len - len(_ids)))
        return _torch.tensor([_ids], dtype=_torch.long)

    def _encode_numeric_features(self, normalized_url: str):
        _torch = self.__class__._TORCH
        _features = self._extract_numeric_features(normalized_url)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            _scaled_features = self.__class__._SCALER.transform([_features])
        return _torch.tensor(_scaled_features, dtype=_torch.float32)

    def _extract_numeric_features(self, normalized_url: str) -> list[float]:
        _parsed = urlparse(normalized_url)
        _domain = (_parsed.hostname or "").strip().lower()
        _tld = _domain.rsplit(".", 1)[-1] if "." in _domain else ""
        return [
            float(len(normalized_url)),
            float(normalized_url.count(".")),
            float(normalized_url.count("-")),
            self._entropy(normalized_url),
            1.0 if _tld in {"tk", "ml", "ga", "cf", "gq", "xyz", "top"} else 0.0,
        ]

    def _entropy(self, value: str) -> float:
        if not value:
            return 0.0
        _counts: dict[str, int] = {}
        for _char in value:
            _counts[_char] = _counts.get(_char, 0) + 1
        _entropy = 0.0
        _total = len(value)
        for _count in _counts.values():
            _probability = _count / _total
            _entropy -= _probability * math.log2(_probability)
        return float(_entropy)
