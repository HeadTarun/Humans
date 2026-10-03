"""
services/reasoning/service.py

ReasoningService — the core bounded reasoning layer.

Uses LangChain + langchain-groq + ChatGroq with structured output.

Architecture:
    - Stateless: no LangChain memory, no LangGraph, no agent loops
    - Zero tool authority: no Tool objects, no AgentExecutor, no create_agent
    - Single call: exactly ONE LLM invocation per reason() call
    - All provider errors → ReasoningUnavailable (never breaks deterministic pipeline)
    - Result always passes through ReasoningValidator before returning

MVP rule: The reasoning service has ZERO tool authority.
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Optional, Union

from app.contracts.reasoning import (
    ReasoningEvidenceSnapshot,
    ReasoningFailureCategory,
    ReasoningResult,
    ReasoningUnavailable,
    ValidatedReasoningArtifact,
)
from app.contracts.common import utcnow
from app.core.config import settings

from .prompts import PROMPT_VERSION, REASONING_SYSTEM_PROMPT, build_user_message
from .validator import ReasoningValidationError, ReasoningValidator

logger = logging.getLogger(__name__)


class ReasoningService:
    """Bounded reasoning service using LangChain + Groq.

    Input:  ReasoningEvidenceSnapshot
    Output: ReasoningResult or ReasoningUnavailable

    The service:
        - Uses ChatGroq.with_structured_output(ReasoningResult, method="function_calling")
        - Is completely stateless (no memory, no state, no graph)
        - Has ZERO tool authority (no Tool objects passed to the model)
        - Makes exactly ONE LLM call per invocation
        - Validates all output through ReasoningValidator
        - Never exposes raw provider errors
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        timeout: Optional[int] = None,
        max_tokens: Optional[int] = None,
    ):
        self._api_key = api_key or settings.GROQ_API_KEY
        self._model = model or settings.GROQ_REASONING_MODEL
        self._timeout = timeout or settings.GROQ_REASONING_TIMEOUT_SECONDS
        self._max_tokens = max_tokens or settings.GROQ_REASONING_MAX_TOKENS
        self._validator = ReasoningValidator()
        self._llm = None  # Lazy initialization
        self._cache: dict[str, dict] = {}  # Simple in-memory cache

    def _get_llm(self):
        """Lazily initialize the ChatGroq LLM with structured output.

        Lazy init avoids import errors when langchain-groq is not installed
        and REASONING_ENABLED=false.
        """
        if self._llm is None:
            from langchain_groq import ChatGroq

            base_llm = ChatGroq(
                api_key=self._api_key,
                model=self._model,
                temperature=0.1,
                max_tokens=self._max_tokens,
                timeout=self._timeout,
            )
            # with_structured_output ensures the model returns a ReasoningResult
            # using function calling — NOT free-form JSON parsing
            self._llm = base_llm.with_structured_output(
                ReasoningResult,
                method="function_calling",
            )
        return self._llm

    async def reason(
        self,
        snapshot: ReasoningEvidenceSnapshot,
    ) -> Union[ReasoningResult, ReasoningUnavailable]:
        """Execute one bounded reasoning call.

        Args:
            snapshot: Sanitized investigation snapshot (allowlist-built).

        Returns:
            ReasoningResult if reasoning succeeds and validates.
            ReasoningUnavailable if anything fails.
        """
        correlation_id = str(uuid.uuid4())
        start_time = time.monotonic()

        # Check if reasoning is enabled
        if not settings.REASONING_ENABLED:
            return ReasoningUnavailable(
                category=ReasoningFailureCategory.REASONING_DISABLED,
                reason="Reasoning layer is disabled via REASONING_ENABLED=false",
                request_correlation_id=correlation_id,
            )

        # Check API key
        if not self._api_key or self._api_key in ("", "dummy_key"):
            return ReasoningUnavailable(
                category=ReasoningFailureCategory.PROVIDER_UNAVAILABLE,
                reason="GROQ_API_KEY not configured",
                request_correlation_id=correlation_id,
            )

        # Check cache
        snapshot_hash = snapshot.compute_hash()
        cache_key = f"{snapshot.case_id}:{snapshot_hash}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            try:
                result = ReasoningResult.model_validate(cached)
                logger.info(
                    "REASONING_CACHE_HIT case=%s hash=%s",
                    snapshot.case_id,
                    snapshot_hash[:16],
                )
                return result
            except Exception:
                # Cache corrupted — proceed with fresh call
                del self._cache[cache_key]

        # Build messages
        snapshot_dict = snapshot.model_dump(mode="json")
        untrusted_items = [
            item.model_dump(mode="json")
            for item in snapshot.untrusted_content
        ]
        user_message = build_user_message(snapshot_dict, untrusted_items)

        # Execute ONE LLM call
        try:
            llm = self._get_llm()

            from langchain_core.messages import HumanMessage, SystemMessage

            messages = [
                SystemMessage(content=REASONING_SYSTEM_PROMPT),
                HumanMessage(content=user_message),
            ]

            # ainvoke for async compatibility
            result = await llm.ainvoke(messages)

            latency_ms = int((time.monotonic() - start_time) * 1000)

            logger.info(
                "REASONING_LLM_CALL case=%s model=%s prompt_version=%s latency_ms=%d hash=%s",
                snapshot.case_id,
                self._model,
                PROMPT_VERSION,
                latency_ms,
                snapshot_hash[:16],
            )

        except Exception as e:
            import traceback
            full_traceback = traceback.format_exc()
            latency_ms = int((time.monotonic() - start_time) * 1000)
            category = self._classify_error(e)

            logger.warning(
                "REASONING_LLM_FAILED case=%s category=%s latency_ms=%d error_type=%s\nTraceback:\n%s",
                snapshot.case_id,
                category.value,
                latency_ms,
                type(e).__name__,
                full_traceback,
            )

            return ReasoningUnavailable(
                category=category,
                reason=f"LLM call failed: {type(e).__name__} - {str(e)}",
                request_correlation_id=correlation_id,
                safe_diagnostic={
                    "model": self._model,
                    "latency_ms": str(latency_ms),
                    "error_type": type(e).__name__,
                    "traceback": full_traceback[:500],
                },
            )


        # Validate the result
        try:
            validated = self._validator.validate(result, snapshot)

            # Cache the validated result (scoped to case_id to prevent cross-case leaks)
            self._cache[cache_key] = validated.model_dump(mode="json")

            logger.info(
                "REASONING_VALIDATED case=%s hash=%s",
                snapshot.case_id,
                snapshot_hash[:16],
            )

            return validated

        except ReasoningValidationError as e:
            logger.warning(
                "REASONING_VALIDATION_FAILED case=%s reason=%s",
                snapshot.case_id,
                e.reason,
            )

            return ReasoningUnavailable(
                category=ReasoningFailureCategory.VALIDATION_FAILED,
                reason=f"Validation failed: {e.reason}",
                request_correlation_id=correlation_id,
                safe_diagnostic={
                    "model": self._model,
                    "validation_error": e.reason[:200],
                },
            )

    def build_artifact(
        self,
        result: ReasoningResult,
        snapshot_hash: str,
    ) -> ValidatedReasoningArtifact:
        """Wrap a validated result with full provenance metadata."""
        return ValidatedReasoningArtifact(
            source_type="reasoning_model",
            model=self._model,
            prompt_version=PROMPT_VERSION,
            snapshot_hash=snapshot_hash,
            result=result.model_dump(mode="json"),
        )

    @staticmethod
    def _classify_error(error: Exception) -> ReasoningFailureCategory:
        """Classify a provider error into a safe failure category."""
        error_str = str(error).lower()
        error_type = type(error).__name__

        if "timeout" in error_str or "timed out" in error_str:
            return ReasoningFailureCategory.PROVIDER_TIMEOUT
        if "429" in error_str or "rate" in error_str:
            return ReasoningFailureCategory.RATE_LIMITED
        if "validation" in error_str or "ValidationError" in error_type:
            return ReasoningFailureCategory.SCHEMA_VALIDATION_FAILED
        if any(code in error_str for code in ("500", "502", "503", "connection")):
            return ReasoningFailureCategory.PROVIDER_UNAVAILABLE

        return ReasoningFailureCategory.INTERNAL_ERROR
