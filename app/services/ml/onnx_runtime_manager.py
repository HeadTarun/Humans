"""
app/services/ml/onnx_runtime_manager.py

Single shared ONNX Runtime "server" used by every local model adapter —
the M2 NLP transformer (DistilBERT intent classifier) and the M4 URL
model (LightURLNet), and any future ONNX model. Model adapters are the
only callers of this module; everything above them in the stack only
ever sees a Prediction / EvidenceItem, never a tensor or session handle.

Why one shared manager instead of each model owning its own
onnxruntime.InferenceSession:
  - one thread-safe cache -> a given .onnx file is loaded at most once
    per process, no matter how many adapters/requests ask for it.
  - one place to tune ORT SessionOptions (thread counts, graph
    optimization level, execution providers) for every model.
  - one availability surface ("is the ONNX server up, which models are
    currently loaded") for diagnostics.

This module deliberately knows nothing about tokenizers, char-vocab
encoding, or feature scaling — that preprocessing stays in the model
adapters (M2IntentClassifier, M4LightUrlNetInference). This module only
ever deals in numpy arrays in, numpy arrays out.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

from app.services.logging import log_json


class OnnxRuntimeUnavailableError(Exception):
    """Raised when onnxruntime itself, or a specific .onnx file, can't be loaded."""


class OnnxRuntimeManager:
    """Process-wide cache of onnxruntime.InferenceSession objects (the "ONNX server")."""

    def __init__(self, intra_op_threads: int = 1, inter_op_threads: int = 1) -> None:
        self._lock = threading.Lock()
        self._sessions: dict[str, Any] = {}
        self._ort: Any = None
        self._ort_import_error: Exception | None = None
        self._intra_op_threads = intra_op_threads
        self._inter_op_threads = inter_op_threads

    def _ensure_ort_imported(self) -> Any:
        if self._ort is not None:
            return self._ort
        if self._ort_import_error is not None:
            raise OnnxRuntimeUnavailableError(str(self._ort_import_error))
        try:
            import onnxruntime as ort
        except ImportError as exc:
            self._ort_import_error = exc
            raise OnnxRuntimeUnavailableError(f"onnxruntime is not installed: {exc}") from exc
        self._ort = ort
        return ort

    def get_session(self, model_path: Path | str, *, model_key: str | None = None) -> Any:
        """Return a cached onnxruntime.InferenceSession for `model_path`.

        Loads and caches it on first use. Thread-safe: concurrent callers
        racing to load the same `model_key` will block on the lock rather
        than each spinning up their own session.
        """
        model_path = Path(model_path)
        key = model_key or str(model_path)

        cached = self._sessions.get(key)
        if cached is not None:
            return cached

        with self._lock:
            cached = self._sessions.get(key)
            if cached is not None:
                return cached

            ort = self._ensure_ort_imported()

            if not model_path.exists():
                raise OnnxRuntimeUnavailableError(f"ONNX model file not found: {model_path}")

            try:
                _options = ort.SessionOptions()
                _options.intra_op_num_threads = self._intra_op_threads
                _options.inter_op_num_threads = self._inter_op_threads
                _options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL

                _session = ort.InferenceSession(
                    str(model_path),
                    sess_options=_options,
                    providers=["CPUExecutionProvider"],
                )
            except Exception as exc:  # onnxruntime raises its own C++-backed exception types
                raise OnnxRuntimeUnavailableError(
                    f"Failed to load ONNX model at {model_path}: {exc}"
                ) from exc

            self._sessions[key] = _session
            log_json(
                __name__,
                20,
                "onnx_server_model_loaded",
                diagnostic_only=True,
                location="app.services.ml.onnx_runtime_manager.get_session",
                model_key=key,
                model_path=str(model_path),
                input_names=[i.name for i in _session.get_inputs()],
                output_names=[o.name for o in _session.get_outputs()],
            )
            return _session

    def is_loaded(self, model_key: str) -> bool:
        return model_key in self._sessions

    def loaded_models(self) -> list[str]:
        return list(self._sessions.keys())

    def unload_all(self) -> None:
        """Drop all cached sessions. Used by tests to reset process-wide state."""
        with self._lock:
            self._sessions.clear()


_MANAGER_LOCK = threading.Lock()
_MANAGER: OnnxRuntimeManager | None = None


def get_manager() -> OnnxRuntimeManager:
    """Return the single process-wide ONNX server instance (created lazily)."""
    global _MANAGER
    if _MANAGER is not None:
        return _MANAGER
    with _MANAGER_LOCK:
        if _MANAGER is None:
            _MANAGER = OnnxRuntimeManager()
        return _MANAGER
