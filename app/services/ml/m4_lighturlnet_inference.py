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
    _SESSION: Any = None
    _INPUT_NAME: str = "input_ids"
    _CHAR2IDX: dict[str, int] = {}
    _CONFIG: dict[str, Any] = {}
    _NP: Any = None

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
            
        # Fallback 1: backend/ml_models/lighturlnet
        _root_ml_models = Path.cwd() / "ml_models" / "lighturlnet"
        if _root_ml_models.exists():
            return _root_ml_models
            
        # Fallback 2: legacy lighturlnet location
        return Path(__file__).resolve().parent / "lighturlnet"

    @classmethod
    def _ensure_model_runtime(cls) -> None:
        if cls._MODEL_INITIALIZED:
            return

        with cls._MODEL_LOCK:
            if cls._MODEL_INITIALIZED:
                return

            try:
                import numpy as np
                from app.services.ml.onnx_runtime_manager import get_manager

                _model_path = cls._resolve_model_path()
                with (_model_path / "config.json").open("r", encoding="utf-8") as _config_file:
                    _config = json.load(_config_file)
                with (_model_path / "char2idx.json").open("r", encoding="utf-8") as _char_file:
                    _char2idx = json.load(_char_file)

                _manager = get_manager()
                _session = _manager.get_session(_model_path / "lighturlnet.onnx")

                _inputs = _session.get_inputs()
                _input_name = _inputs[0].name
                if len(_inputs) != 1 or _inputs[0].type != "tensor(int64)":
                    raise ValueError(f"Model missing expected int64 input, got {_inputs}")
                _outputs = _session.get_outputs()
                if len(_outputs) == 0 or _outputs[0].type != "tensor(float)":
                    raise ValueError("Model missing expected float output")

                cls._SESSION = _session
                cls._INPUT_NAME = _input_name
                cls._CHAR2IDX = {str(_key): int(_value) for _key, _value in _char2idx.items()}
                cls._CONFIG = _config
                cls._NP = np
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
            except Exception as exc:
                cls._SESSION = None
                cls._CHAR2IDX = {}
                cls._CONFIG = {}
                cls._NP = None
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

        _session = self.__class__._SESSION
        _np = self.__class__._NP
        if _session is None or _np is None:
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
            _input_ids = self._encode_url(normalized_url)
            _outputs = _session.run(None, {self.__class__._INPUT_NAME: _input_ids})
            _logit = _outputs[0][0][0] if _outputs[0].ndim == 3 else _outputs[0][0]
            if isinstance(_logit, _np.ndarray):
                 _logit = _logit.item()
            _probability = 1.0 / (1.0 + _np.exp(-_logit))
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
        except Exception as exc:
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
        _np = self.__class__._NP
        # The ONNX model requires a specific sequence length (e.g. 256), ignoring config.json
        _max_len = self.__class__._SESSION.get_inputs()[0].shape[1]
        if not isinstance(_max_len, int):
            _max_len = 200
        _ids = [self.__class__._CHAR2IDX.get(_char, 0) for _char in normalized_url[:_max_len]]
        if len(_ids) < _max_len:
            _ids.extend([0] * (_max_len - len(_ids)))
        return _np.array([_ids], dtype=_np.int64)
