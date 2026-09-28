"""
services/reasoning/validator.py

Deterministic post-LLM validator for reasoning output.

This is a SEPARATE module from the LLM service — independently unit-testable
with no LLM dependency.

Responsibilities:
    - Revalidate Pydantic schema
    - Ensure case_id / investigation_id match snapshot
    - Ensure all evidence IDs exist in snapshot (reject hallucinated IDs)
    - Validate output sizes and field counts
    - Scan free text for forbidden content patterns
    - Detect risk/verdict/confidence leakage in free text

CRITICAL: If validation fails, the entire reasoning result is rejected.
          We NEVER partially trust a response.
"""

from __future__ import annotations

import logging
import re

from pydantic import ValidationError

from app.contracts.reasoning import (
    ReasoningEvidenceSnapshot,
    ReasoningResult,
)

logger = logging.getLogger(__name__)


class ReasoningValidationError(Exception):
    """Raised when reasoning output fails deterministic validation."""

    def __init__(self, reason: str, category: str = "VALIDATION_FAILED"):
        self.reason = reason
        self.category = category
        super().__init__(reason)


# ---------------------------------------------------------------------------
# Forbidden content patterns (defense-in-depth)
#
# The PRIMARY defense is the typed schema (no risk/verdict/confidence fields).
# These regex patterns are SECONDARY defense-in-depth checks on free text.
#
# IMPORTANT: Patterns must be conservative. Normal cybersecurity language
# like "high risk indicators" or "malicious URL found" must NOT be blocked.
# We only flag structured authoritative assertions.
# ---------------------------------------------------------------------------

# Matches patterns like "risk_score: 85", "risk: 92.5", "final risk = 45"
_RISK_SCORE_PATTERN = re.compile(
    r"(?:final\s+)?risk[\s_]?(?:score)?[\s:=]+\d+(?:\.\d+)?(?:\s*/\s*100)?",
    re.IGNORECASE,
)

# Matches patterns like "confidence: 0.85", "confidence_score = 0.9"
_CONFIDENCE_PATTERN = re.compile(
    r"(?:final\s+)?confidence[\s_]?(?:score)?[\s:=]+[01]?\.\d+",
    re.IGNORECASE,
)

# Matches authoritative verdict assertions like "VERDICT: MALICIOUS" or "final_verdict = BENIGN"
_VERDICT_PATTERN = re.compile(
    r"(?:final[\s_]?)?verdict[\s:=]+(?:BENIGN|MALICIOUS|SUSPICIOUS|INCONCLUSIVE)\b",
    re.IGNORECASE,
)

# API key / secret patterns — hex/base64 strings that look like credentials
_SECRET_PATTERN = re.compile(
    r"(?:api[_\s]?key|secret[_\s]?key|password|token|bearer)\s*[:=]\s*['\"]?[A-Za-z0-9+/=_\-]{20,}",
    re.IGNORECASE,
)

# Direct tool execution instruction patterns
_TOOL_EXEC_PATTERN = re.compile(
    r"(?:execute|run|call|invoke)\s+(?:tool|function|command)\s*[:=]",
    re.IGNORECASE,
)

# System prompt extraction attempts
_PROMPT_EXTRACTION_PATTERN = re.compile(
    r"(?:system\s+prompt|system\s+message|initial\s+instructions?)[\s:]*['\"]",
    re.IGNORECASE,
)


class ReasoningValidator:
    """Deterministic validator for reasoning model output.

    Independently unit-testable — has no LLM dependency.
    """

    # Maximum allowed sizes
    MAX_SUMMARY_LENGTH = 2000
    MAX_EXPLANATION_LENGTH = 5000
    MAX_HYPOTHESES_COUNT = 10
    MAX_ACTIONS_COUNT = 5
    MAX_EVIDENCE_IDS = 50

    def validate(
        self,
        result: ReasoningResult,
        snapshot: ReasoningEvidenceSnapshot,
    ) -> ReasoningResult:
        """Validate a reasoning result against the snapshot.

        Args:
            result: The raw structured output from the LLM.
            snapshot: The input snapshot that was sent to the LLM.

        Returns:
            The validated ReasoningResult (unchanged if valid).

        Raises:
            ReasoningValidationError: If any validation check fails.
        """
        # 1. Re-validate Pydantic schema
        self._validate_schema(result)

        # 2. Verify identity fields match
        self._validate_identity(result, snapshot)

        # 3. Verify evidence IDs exist in snapshot
        self._validate_evidence_ids(result, snapshot)

        # 4. Validate output sizes
        self._validate_sizes(result)

        # 5. Scan free text for forbidden content
        self._validate_free_text(result)

        return result

    def _validate_schema(self, result: ReasoningResult) -> None:
        """Re-validate the Pydantic schema to catch any tampering."""
        try:
            ReasoningResult.model_validate(result.model_dump())
        except ValidationError as e:
            raise ReasoningValidationError(
                f"Schema revalidation failed: {e}",
                category="SCHEMA_VALIDATION_FAILED",
            )

    def _validate_identity(
        self, result: ReasoningResult, snapshot: ReasoningEvidenceSnapshot
    ) -> None:
        """Ensure case_id and investigation_id match the snapshot."""
        if result.case_id != snapshot.case_id:
            raise ReasoningValidationError(
                f"case_id mismatch: result='{result.case_id}' vs snapshot='{snapshot.case_id}'"
            )
        if result.investigation_id != snapshot.investigation_id:
            raise ReasoningValidationError(
                f"investigation_id mismatch: result='{result.investigation_id}' "
                f"vs snapshot='{snapshot.investigation_id}'"
            )

    def _validate_evidence_ids(
        self, result: ReasoningResult, snapshot: ReasoningEvidenceSnapshot
    ) -> None:
        """Reject hallucinated evidence IDs."""
        # Collect all known evidence IDs from the snapshot
        known_ids: set[str] = set()

        for finding in snapshot.key_findings:
            known_ids.add(finding.evidence_id)
        for item in snapshot.untrusted_content:
            known_ids.add(item.evidence_id)
        known_ids.update(snapshot.supporting_evidence)
        known_ids.update(snapshot.contradictory_evidence)

        # Also collect from hypotheses
        for h in snapshot.current_hypotheses:
            known_ids.update(h.supporting_evidence_ids)
            known_ids.update(h.contradicting_evidence_ids)

        # Validate supporting evidence IDs
        for eid in result.supporting_evidence_ids:
            if eid not in known_ids:
                raise ReasoningValidationError(
                    f"Hallucinated supporting evidence ID: '{eid}' — not in snapshot"
                )

        # Validate contradicting evidence IDs
        for eid in result.contradicting_evidence_ids:
            if eid not in known_ids:
                raise ReasoningValidationError(
                    f"Hallucinated contradicting evidence ID: '{eid}' — not in snapshot"
                )

    def _validate_sizes(self, result: ReasoningResult) -> None:
        """Validate output field sizes and counts."""
        if len(result.summary) > self.MAX_SUMMARY_LENGTH:
            raise ReasoningValidationError(
                f"Summary too long: {len(result.summary)} > {self.MAX_SUMMARY_LENGTH}"
            )
        if len(result.explanation) > self.MAX_EXPLANATION_LENGTH:
            raise ReasoningValidationError(
                f"Explanation too long: {len(result.explanation)} > {self.MAX_EXPLANATION_LENGTH}"
            )
        if len(result.hypotheses) > self.MAX_HYPOTHESES_COUNT:
            raise ReasoningValidationError(
                f"Too many hypotheses: {len(result.hypotheses)} > {self.MAX_HYPOTHESES_COUNT}"
            )
        if len(result.recommended_next_actions) > self.MAX_ACTIONS_COUNT:
            raise ReasoningValidationError(
                f"Too many actions: {len(result.recommended_next_actions)} > {self.MAX_ACTIONS_COUNT}"
            )
        if len(result.supporting_evidence_ids) > self.MAX_EVIDENCE_IDS:
            raise ReasoningValidationError(
                f"Too many supporting evidence IDs: {len(result.supporting_evidence_ids)}"
            )
        if len(result.contradicting_evidence_ids) > self.MAX_EVIDENCE_IDS:
            raise ReasoningValidationError(
                f"Too many contradicting evidence IDs: {len(result.contradicting_evidence_ids)}"
            )

    def _validate_free_text(self, result: ReasoningResult) -> None:
        """Scan free text fields for forbidden content patterns.

        This is defense-in-depth — the primary defense is the typed schema
        which structurally excludes risk/verdict/confidence fields.
        """
        text_fields = [
            ("summary", result.summary),
            ("explanation", result.explanation),
        ]
        # Also check hypothesis text and action text
        for i, h in enumerate(result.hypotheses):
            text_fields.append((f"hypotheses[{i}]", h))
        for i, a in enumerate(result.recommended_next_actions):
            text_fields.append((f"recommended_next_actions[{i}]", a))

        for field_name, text in text_fields:
            self._check_forbidden_patterns(field_name, text)

    def _check_forbidden_patterns(self, field_name: str, text: str) -> None:
        """Check a single text field for forbidden patterns."""
        if _RISK_SCORE_PATTERN.search(text):
            raise ReasoningValidationError(
                f"Forbidden risk score pattern detected in {field_name}"
            )
        if _CONFIDENCE_PATTERN.search(text):
            raise ReasoningValidationError(
                f"Forbidden confidence score pattern detected in {field_name}"
            )
        if _VERDICT_PATTERN.search(text):
            raise ReasoningValidationError(
                f"Forbidden verdict assertion pattern detected in {field_name}"
            )
        if _SECRET_PATTERN.search(text):
            raise ReasoningValidationError(
                f"Potential secret/API key pattern detected in {field_name}"
            )
        if _TOOL_EXEC_PATTERN.search(text):
            raise ReasoningValidationError(
                f"Tool execution instruction pattern detected in {field_name}"
            )
        if _PROMPT_EXTRACTION_PATTERN.search(text):
            raise ReasoningValidationError(
                f"System prompt extraction attempt detected in {field_name}"
            )
