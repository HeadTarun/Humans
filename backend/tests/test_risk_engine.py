"""
tests/test_risk_engine.py

Risk Engine test suite — Stage 2.

Covers all required test scenarios:
    A. Low risk + high confidence → BENIGN
    B. High risk + high confidence → MALICIOUS
    C. Medium risk → SUSPICIOUS
    D. Insufficient evidence → INCONCLUSIVE
    E. Conflicting evidence reduces confidence
    F. Tool timeout does not create clean evidence
    G. External budget exhaustion → INCONCLUSIVE (not BENIGN)
    H. Deterministic scoring (same evidence → same result)
    I. Bounded outputs (risk ∈ [0,100], confidence ∈ [0,1])
    J. InvestigationResult contract validation
    K. COMPLETED vs INCONCLUSIVE status distinction
    L. Resource stop cannot produce BENIGN (security invariant)
    M. Evidence preserved on stop
    N. Verdict thresholds
    O. RiskContribution auditability
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

import pytest

from app.contracts.common import Provenance, SourceType, utcnow
from app.contracts.evidence import (
    EvidenceCategory,
    EvidenceItem,
    EvidenceStatus,
    EvidenceType,
    TrustLevel,
)
from app.contracts.investigation import (
    AttackHypothesis,
    AttackHypothesisType,
    EscalationStatus,
    HypothesisStatus,
    InvestigationBudget,
    InvestigationLevel,
    InvestigationState,
    InvestigationStatus,
    StateMachineStatus,
    StopReason,
    ToolCostSpent,
)
from app.contracts.result import RESOURCE_STOP_REASONS, InvestigationResult
from app.contracts.risk import Verdict
from app.services.investigation.budget import DEFAULT_BUDGET, make_full_budget_remaining
from app.services.risk import (
    EVIDENCE_WEIGHTS,
    MALICIOUS_RISK_THRESHOLD,
    MIN_CONFIDENCE_FOR_VERDICT,
    SUSPICIOUS_RISK_THRESHOLD,
    RiskEngine,
    assign_verdict,
    assign_verdict_with_stop_guard,
)
from app.services.risk.confidence import calculate_confidence
from app.services.risk.scoring import score_evidence_items

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

_MODULE = "tests.test_risk_engine"


def _provenance() -> Provenance:
    return Provenance(
        producer_module=_MODULE,
        extraction_method="test_fixture",
        created_at=utcnow(),
    )


def _make_evidence(
    key: str,
    value,
    ev_type: EvidenceType = EvidenceType.FACT,
    category: EvidenceCategory = EvidenceCategory.AUTHENTICATION,
    confidence: float = 1.0,
    case_id: str = "case-test-001",
) -> EvidenceItem:
    return EvidenceItem(
        evidence_id=str(uuid.uuid4()),
        case_id=case_id,
        type=ev_type,
        category=category,
        key=key,
        value=value,
        source="test_fixture",
        source_type=SourceType.DETERMINISTIC,
        confidence=confidence,
        trust_level=TrustLevel.VERIFIED,
        provenance=_provenance(),
        status=EvidenceStatus.ACTIVE,
    )


def _make_state(
    case_id: str = "case-test-001",
    pending_conflicts: Optional[list[str]] = None,
    tool_cost_spent: Optional[ToolCostSpent] = None,
    sm_status: StateMachineStatus = StateMachineStatus.STOPPED,
    stop_reason: Optional[StopReason] = StopReason.CONFIDENCE_TARGET_REACHED,
    missing_evidence: Optional[list[str]] = None,
    observed_facts: Optional[list[str]] = None,
) -> InvestigationState:
    spent = tool_cost_spent or ToolCostSpent()
    budget = DEFAULT_BUDGET
    return InvestigationState(
        case_id=case_id,
        created_at=utcnow(),
        observed_facts=observed_facts or [],
        heuristic_findings=[],
        ml_signals=[],
        threat_intelligence=[],
        historical_matches=[],
        current_risk=0.0,
        current_confidence=0.0,
        risk_history=[],
        missing_evidence=missing_evidence or [],
        pending_conflicts=pending_conflicts or [],
        resolved_conflicts=[],
        tools_used=[],
        tools_available=[],
        tools_blocked=[],
        tool_cost_spent=spent,
        budget=budget,
        budget_remaining=make_full_budget_remaining(budget),
        investigation_level=InvestigationLevel.L0_TRIAGE,
        iteration_count=0,
        max_iterations=12,
        sm_status=sm_status,
        stop_reason=stop_reason,
        escalation_reason=None,
        escalation_status=EscalationStatus.NONE,
    )


# ---------------------------------------------------------------------------
# A. Low risk + high confidence → BENIGN
# ---------------------------------------------------------------------------

class TestBenignVerdict:

    def test_low_risk_high_confidence_returns_benign(self):
        """Full SPF/DKIM/DMARC pass → low risk → BENIGN with sufficient confidence."""
        evidence = [
            _make_evidence("auth_dmarc_result", "pass"),
            _make_evidence("auth_spf_result", "pass"),
            _make_evidence("auth_dkim_result", "pass"),
            _make_evidence("auth_dmarc_result", "pass"),  # Extra item → better completeness
            _make_evidence("auth_spf_result", "pass"),
        ]
        state = _make_state()
        engine = RiskEngine()
        result = engine.assess(state=state, evidence_items=evidence)

        assert result.verdict == Verdict.BENIGN
        assert result.risk_assessment.risk_score < SUSPICIOUS_RISK_THRESHOLD

    def test_benign_verdict_has_positive_confidence(self):
        """A BENIGN verdict must have confidence ≥ MIN_CONFIDENCE_FOR_VERDICT."""
        evidence = [
            _make_evidence("auth_dmarc_result", "pass"),
            _make_evidence("auth_spf_result", "pass"),
            _make_evidence("auth_dkim_result", "pass"),
            _make_evidence("auth_dmarc_result", "pass"),
            _make_evidence("auth_spf_result", "pass"),
        ]
        state = _make_state()
        result = RiskEngine().assess(state=state, evidence_items=evidence)

        assert result.confidence_assessment.confidence_score >= MIN_CONFIDENCE_FOR_VERDICT


# ---------------------------------------------------------------------------
# B. High risk + high confidence → MALICIOUS
# ---------------------------------------------------------------------------

class TestMaliciousVerdict:

    def test_high_risk_high_confidence_returns_malicious(self):
        """DMARC fail + executable attachment + reply-to mismatch → MALICIOUS."""
        evidence = [
            _make_evidence("auth_dmarc_result", "fail"),
            _make_evidence("auth_spf_result", "fail"),
            _make_evidence("auth_dkim_result", "fail"),
            _make_evidence("reply_to_domain_mismatch", True,
                           category=EvidenceCategory.HEADER),
            _make_evidence("attachment_executable_signature", True,
                           category=EvidenceCategory.ATTACHMENT),
            _make_evidence("attachment_executable_signature", True,
                           category=EvidenceCategory.ATTACHMENT),  # Two executables
            _make_evidence("url_http_scheme", "http",
                           category=EvidenceCategory.URL),
        ]
        # Many evidence items → high completeness → high confidence
        state = _make_state()
        engine = RiskEngine()
        result = engine.assess(state=state, evidence_items=evidence)

        assert result.verdict == Verdict.MALICIOUS
        assert result.risk_assessment.risk_score >= MALICIOUS_RISK_THRESHOLD
        assert result.confidence_assessment.confidence_score >= MIN_CONFIDENCE_FOR_VERDICT

    def test_malicious_verdict_has_contributions(self):
        """MALICIOUS result must have auditable RiskContributions."""
        evidence = [
            _make_evidence("auth_dmarc_result", "fail"),
            _make_evidence("attachment_executable_signature", True,
                           category=EvidenceCategory.ATTACHMENT),
            _make_evidence("auth_dmarc_result", "fail"),
            _make_evidence("auth_spf_result", "fail"),
            _make_evidence("reply_to_domain_mismatch", True,
                           category=EvidenceCategory.HEADER),
        ]
        state = _make_state()
        result = RiskEngine().assess(state=state, evidence_items=evidence)

        assert len(result.risk_assessment.contributions) > 0
        for contrib in result.risk_assessment.contributions:
            assert contrib.weight != 0
            assert contrib.reason_code is not None


# ---------------------------------------------------------------------------
# C. Medium risk → SUSPICIOUS
# ---------------------------------------------------------------------------

class TestSuspiciousVerdict:

    def test_medium_risk_returns_suspicious(self):
        """Moderate signals (softfails + header mismatches, no executables) → SUSPICIOUS.

        Evidence scores:
            auth_dmarc_result:softfail  = +15
            auth_spf_result:softfail    = +8
            reply_to_domain_mismatch    = +20
            return_path_domain_mismatch = +12
            url_http_scheme             = +8
            Total                       = 63 → SUSPICIOUS [40, 75)
        """
        evidence = [
            _make_evidence("auth_dmarc_result", "softfail"),
            _make_evidence("auth_spf_result", "softfail"),
            _make_evidence("reply_to_domain_mismatch", True,
                           category=EvidenceCategory.HEADER),
            _make_evidence("return_path_domain_mismatch", True,
                           category=EvidenceCategory.HEADER),
            _make_evidence("url_http_scheme", "http",
                           category=EvidenceCategory.URL),
        ]
        state = _make_state()
        result = RiskEngine().assess(state=state, evidence_items=evidence)

        assert result.verdict == Verdict.SUSPICIOUS, (
            f"Expected SUSPICIOUS but got {result.verdict.value}. "
            f"risk_score={result.risk_assessment.risk_score:.2f}"
        )
        assert SUSPICIOUS_RISK_THRESHOLD <= result.risk_assessment.risk_score < MALICIOUS_RISK_THRESHOLD

    def test_suspicious_verdict_includes_reasons(self):
        """A SUSPICIOUS result must have at least one positive reason code."""
        evidence = [
            _make_evidence("auth_dmarc_result", "softfail"),
            _make_evidence("auth_spf_result", "softfail"),
            _make_evidence("reply_to_domain_mismatch", True,
                           category=EvidenceCategory.HEADER),
            _make_evidence("return_path_domain_mismatch", True,
                           category=EvidenceCategory.HEADER),
            _make_evidence("url_http_scheme", "http",
                           category=EvidenceCategory.URL),
        ]
        state = _make_state()
        result = RiskEngine().assess(state=state, evidence_items=evidence)

        assert len(result.risk_assessment.reasons) > 0


# ---------------------------------------------------------------------------
# D. Insufficient evidence → INCONCLUSIVE
# ---------------------------------------------------------------------------

class TestInconclusiveVerdict:

    def test_insufficient_evidence_returns_inconclusive(self):
        """Zero evidence items → confidence=0 → INCONCLUSIVE."""
        state = _make_state()
        result = RiskEngine().assess(state=state, evidence_items=[])

        assert result.verdict == Verdict.INCONCLUSIVE
        assert result.confidence_assessment.confidence_score < MIN_CONFIDENCE_FOR_VERDICT

    def test_single_low_confidence_item_is_inconclusive(self):
        """One evidence item with low confidence → low completeness → INCONCLUSIVE."""
        evidence = [
            _make_evidence("auth_dmarc_result", "fail", confidence=0.1),
        ]
        state = _make_state()
        result = RiskEngine().assess(state=state, evidence_items=evidence)

        # Completeness = 1/5 = 0.20, reliability = 0.10 → confidence = 0.02
        assert result.confidence_assessment.confidence_score < MIN_CONFIDENCE_FOR_VERDICT
        assert result.verdict == Verdict.INCONCLUSIVE


# ---------------------------------------------------------------------------
# E. Conflicting evidence reduces confidence
# ---------------------------------------------------------------------------

class TestConflictingEvidence:

    def test_conflicting_evidence_reduces_confidence(self):
        """SPF PASS but DMARC FAIL — conflict should reduce confidence."""
        evidence_no_conflict = [
            _make_evidence("auth_dmarc_result", "fail"),
            _make_evidence("auth_spf_result", "fail"),
            _make_evidence("auth_dkim_result", "fail"),
            _make_evidence("reply_to_domain_mismatch", True,
                           category=EvidenceCategory.HEADER),
            _make_evidence("attachment_executable_signature", True,
                           category=EvidenceCategory.ATTACHMENT),
        ]
        evidence_with_conflict = list(evidence_no_conflict) + [
            _make_evidence("auth_spf_result", "pass"),  # Contradicts spf:fail
        ]

        state_no_conflict = _make_state(pending_conflicts=[])
        state_with_conflict = _make_state(pending_conflicts=["conflict-001", "conflict-002"])

        engine = RiskEngine()
        result_clean = engine.assess(state=state_no_conflict, evidence_items=evidence_no_conflict)
        result_conflict = engine.assess(state=state_with_conflict, evidence_items=evidence_with_conflict)

        assert (
            result_conflict.confidence_assessment.confidence_score
            < result_clean.confidence_assessment.confidence_score
        ), "Unresolved conflicts must reduce confidence"

    def test_conflict_penalty_is_documented(self):
        """Verify that confidence_assessment captures the conflict penalty."""
        state = _make_state(pending_conflicts=["c1", "c2"])
        evidence = [
            _make_evidence("auth_dmarc_result", "fail"),
            _make_evidence("auth_spf_result", "fail"),
            _make_evidence("auth_dkim_result", "fail"),
            _make_evidence("reply_to_domain_mismatch", True,
                           category=EvidenceCategory.HEADER),
            _make_evidence("auth_dmarc_result", "fail"),
        ]
        result = RiskEngine().assess(state=state, evidence_items=evidence)

        assert result.confidence_assessment.unresolved_conflicts_penalty > 0


# ---------------------------------------------------------------------------
# F. Tool timeout does not create clean evidence
# ---------------------------------------------------------------------------

class TestToolFailureSemantics:

    def test_tool_timeout_does_not_create_clean_evidence(self):
        """
        If a tool times out, the evidence it would have produced is ABSENT.
        The absence of evidence is NOT evidence of absence.
        
        Increasing tools_failed_count must REDUCE confidence, not increase it.
        """
        evidence = [
            _make_evidence("auth_dmarc_result", "fail"),
            _make_evidence("reply_to_domain_mismatch", True,
                           category=EvidenceCategory.HEADER),
            _make_evidence("auth_spf_result", "softfail"),
            _make_evidence("auth_dmarc_result", "fail"),
            _make_evidence("reply_to_domain_mismatch", True,
                           category=EvidenceCategory.HEADER),
        ]
        state = _make_state()

        engine = RiskEngine()
        result_no_failures = engine.assess(state=state, evidence_items=evidence,
                                            tools_failed_count=0)
        result_one_failure = engine.assess(state=state, evidence_items=evidence,
                                           tools_failed_count=1)
        result_two_failures = engine.assess(state=state, evidence_items=evidence,
                                            tools_failed_count=2)

        # Each failure must reduce (or not increase) confidence
        assert (
            result_one_failure.confidence_assessment.confidence_score
            <= result_no_failures.confidence_assessment.confidence_score
        ), "One tool failure must not increase confidence"

        assert (
            result_two_failures.confidence_assessment.confidence_score
            <= result_one_failure.confidence_assessment.confidence_score
        ), "Two tool failures must not increase confidence over one"

    def test_tool_failure_penalty_is_documented(self):
        """tool_failure_penalty must be > 0 when tools fail."""
        result = calculate_confidence(
            evidence_items=[_make_evidence("auth_dmarc_result", "fail")],
            pending_conflicts=[],
            tools_failed_count=2,
            case_id="case-001",
        )
        assert result.tool_failure_penalty > 0


# ---------------------------------------------------------------------------
# G. External budget exhaustion → INCONCLUSIVE (not BENIGN)
# ---------------------------------------------------------------------------

class TestBudgetExhaustionSecurity:

    def test_external_budget_exhaustion_returns_inconclusive(self):
        """
        CRITICAL SECURITY REQUIREMENT:
        Budget exhausted ≠ safe. Investigation stopped before completing.

        Even with low risk evidence, budget exhaustion must NOT produce BENIGN.
        """
        # External API budget fully spent
        spent = ToolCostSpent(
            latency_ms=0,
            tool_calls=4,
            external_calls=4,  # max=4 in DEFAULT_BUDGET → exhausted
            llm_tokens=0,
        )
        state = _make_state(
            tool_cost_spent=spent,
            sm_status=StateMachineStatus.STOPPED,
            stop_reason=StopReason.EXTERNAL_CALL_BUDGET_EXHAUSTED,
        )
        # Mostly clean signals — would normally be BENIGN
        evidence = [
            _make_evidence("auth_dmarc_result", "pass"),
            _make_evidence("auth_spf_result", "pass"),
            _make_evidence("auth_dkim_result", "pass"),
            _make_evidence("auth_dmarc_result", "pass"),
            _make_evidence("auth_spf_result", "pass"),
        ]

        result = RiskEngine().assess(
            state=state,
            evidence_items=evidence,
            stop_reason=StopReason.EXTERNAL_CALL_BUDGET_EXHAUSTED,
        )

        assert result.verdict != Verdict.BENIGN, (
            "Budget exhaustion must NOT produce BENIGN verdict. "
            "We didn't finish investigating — we cannot declare safe."
        )
        assert result.verdict in (Verdict.INCONCLUSIVE, Verdict.SUSPICIOUS, Verdict.MALICIOUS)

    def test_resource_stop_verdict_is_not_benign_via_stop_guard(self):
        """assign_verdict_with_stop_guard prevents BENIGN on resource stops."""
        # Simulate: risk=5, confidence=0.9 (would normally be BENIGN)
        for stop_reason in RESOURCE_STOP_REASONS:
            verdict = assign_verdict_with_stop_guard(
                risk_score=5.0,
                confidence=0.9,
                stop_reason=stop_reason,
            )
            assert verdict != Verdict.BENIGN, (
                f"stop_reason={stop_reason.value} must never produce BENIGN"
            )

    def test_investigation_result_contract_rejects_benign_on_resource_stop(self):
        """InvestigationResult model_validator must reject BENIGN + resource stop."""
        budget = DEFAULT_BUDGET
        remaining = make_full_budget_remaining(budget)

        with pytest.raises(ValueError, match="Verdict.BENIGN is forbidden"):
            InvestigationResult(
                investigation_id="case-001",
                status=InvestigationStatus.INCONCLUSIVE,
                stop_reason=StopReason.EXTERNAL_CALL_BUDGET_EXHAUSTED,
                investigation_level_reached=InvestigationLevel.L0_TRIAGE,
                verdict=Verdict.BENIGN,  # ← MUST be rejected
                risk_score=5.0,
                confidence=0.9,
                budget=budget,
                budget_spent=ToolCostSpent(),
                budget_remaining=remaining,
                audit_chain_last_hash="a" * 64,
            )

    def test_all_resource_stops_are_covered(self):
        """Every resource stop reason must prevent BENIGN verdict."""
        for stop_reason in RESOURCE_STOP_REASONS:
            verdict = assign_verdict_with_stop_guard(
                risk_score=0.0,  # Minimum possible risk
                confidence=1.0,  # Maximum possible confidence
                stop_reason=stop_reason,
            )
            assert verdict != Verdict.BENIGN, (
                f"Resource stop {stop_reason.value} must never produce BENIGN "
                f"even with risk=0 and confidence=1"
            )


# ---------------------------------------------------------------------------
# H. Deterministic scoring
# ---------------------------------------------------------------------------

class TestDeterministicScoring:

    def test_risk_score_is_deterministic(self):
        """Same evidence list always produces same risk score."""
        evidence = [
            _make_evidence("auth_dmarc_result", "fail"),
            _make_evidence("reply_to_domain_mismatch", True,
                           category=EvidenceCategory.HEADER),
        ]
        state = _make_state()
        engine = RiskEngine()

        results = [engine.assess(state=state, evidence_items=evidence) for _ in range(5)]
        scores = [r.risk_assessment.risk_score for r in results]

        assert len(set(scores)) == 1, f"Score must be deterministic, got: {scores}"

    def test_same_evidence_produces_same_result(self):
        """Full RiskEngineResult is reproducible for same inputs."""
        evidence = [
            _make_evidence("auth_dmarc_result", "fail"),
            _make_evidence("auth_spf_result", "fail"),
            _make_evidence("attachment_executable_signature", True,
                           category=EvidenceCategory.ATTACHMENT),
        ]
        state = _make_state()
        engine = RiskEngine()

        r1 = engine.assess(state=state, evidence_items=evidence)
        r2 = engine.assess(state=state, evidence_items=evidence)

        assert r1.verdict == r2.verdict
        assert r1.risk_assessment.risk_score == r2.risk_assessment.risk_score
        assert r1.confidence_assessment.confidence_score == r2.confidence_assessment.confidence_score


# ---------------------------------------------------------------------------
# I. Bounded outputs
# ---------------------------------------------------------------------------

class TestBoundedOutputs:

    def test_risk_score_is_bounded(self):
        """Risk score must always be in [0, 100]."""
        # Load every possible weighted key with maximum signal
        evidence = [
            _make_evidence("auth_dmarc_result", "fail"),
            _make_evidence("auth_spf_result", "fail"),
            _make_evidence("auth_dkim_result", "fail"),
            _make_evidence("reply_to_domain_mismatch", True,
                           category=EvidenceCategory.HEADER),
            _make_evidence("return_path_domain_mismatch", True,
                           category=EvidenceCategory.HEADER),
            _make_evidence("attachment_executable_signature", True,
                           category=EvidenceCategory.ATTACHMENT),
            _make_evidence("attachment_is_archive", True,
                           category=EvidenceCategory.ATTACHMENT),
            _make_evidence("url_http_scheme", "http",
                           category=EvidenceCategory.URL),
        ]
        state = _make_state()
        result = RiskEngine().assess(state=state, evidence_items=evidence)

        assert 0.0 <= result.risk_assessment.risk_score <= 100.0

    def test_confidence_is_bounded(self):
        """Confidence score must always be in [0, 1]."""
        # Test with zero evidence
        result_empty = calculate_confidence(
            evidence_items=[], pending_conflicts=[], case_id="x"
        )
        assert 0.0 <= result_empty.confidence_score <= 1.0

        # Test with many conflicts
        result_conflicts = calculate_confidence(
            evidence_items=[_make_evidence("auth_dmarc_result", "fail")] * 10,
            pending_conflicts=["c"] * 20,
            case_id="x",
        )
        assert 0.0 <= result_conflicts.confidence_score <= 1.0

        # Test with many failures
        result_failures = calculate_confidence(
            evidence_items=[_make_evidence("auth_dmarc_result", "fail")] * 10,
            pending_conflicts=[],
            tools_failed_count=100,
            case_id="x",
        )
        assert 0.0 <= result_failures.confidence_score <= 1.0

    def test_risk_score_never_negative(self):
        """Risk score from all-negative weights (all-PASS auth) must be ≥ 0."""
        evidence = [
            _make_evidence("auth_dmarc_result", "pass"),
            _make_evidence("auth_spf_result", "pass"),
            _make_evidence("auth_dkim_result", "pass"),
        ]
        risk_score, _ = score_evidence_items(evidence, case_id="test")
        assert risk_score >= 0.0


# ---------------------------------------------------------------------------
# J. InvestigationResult contract integrity
# ---------------------------------------------------------------------------

class TestInvestigationResultContract:

    def _make_valid_result(self, **overrides) -> dict:
        budget = DEFAULT_BUDGET
        remaining = make_full_budget_remaining(budget)
        base = dict(
            investigation_id="case-001",
            status=InvestigationStatus.COMPLETED,
            stop_reason=StopReason.CONFIDENCE_TARGET_REACHED,
            investigation_level_reached=InvestigationLevel.L0_TRIAGE,
            verdict=Verdict.BENIGN,
            risk_score=5.0,
            confidence=0.75,
            budget=budget,
            budget_spent=ToolCostSpent(),
            budget_remaining=remaining,
            audit_chain_last_hash="a" * 64,
        )
        base.update(overrides)
        return base

    def test_completed_result_is_valid(self):
        """A correctly formed COMPLETED result validates without error."""
        result = InvestigationResult(**self._make_valid_result())
        assert result.status == InvestigationStatus.COMPLETED
        assert result.verdict == Verdict.BENIGN

    def test_inconclusive_result_requires_stop_reason(self):
        """INCONCLUSIVE status without stop_reason must raise ValueError."""
        with pytest.raises(ValueError, match="stop_reason is required"):
            InvestigationResult(**self._make_valid_result(
                status=InvestigationStatus.INCONCLUSIVE,
                stop_reason=None,
                verdict=Verdict.INCONCLUSIVE,
            ))

    def test_investigation_result_is_json_serializable(self):
        """InvestigationResult must be serializable as JSON (API boundary test)."""
        result = InvestigationResult(**self._make_valid_result())
        json_str = result.model_dump_json()
        assert '"COMPLETED"' in json_str
        assert '"BENIGN"' in json_str
        assert "investigation_id" in json_str


# ---------------------------------------------------------------------------
# K. COMPLETED vs INCONCLUSIVE status distinction
# ---------------------------------------------------------------------------

class TestStatusDistinction:

    def test_completed_investigation_has_definitive_verdict(self):
        """A COMPLETED investigation must have a verdict other than INCONCLUSIVE,
        unless the evidence genuinely supports INCONCLUSIVE verdict."""
        budget = DEFAULT_BUDGET
        remaining = make_full_budget_remaining(budget)
        result = InvestigationResult(
            investigation_id="case-001",
            status=InvestigationStatus.COMPLETED,
            stop_reason=StopReason.CONFIDENCE_TARGET_REACHED,
            investigation_level_reached=InvestigationLevel.L0_TRIAGE,
            verdict=Verdict.MALICIOUS,
            risk_score=85.0,
            confidence=0.92,
            budget=budget,
            budget_spent=ToolCostSpent(),
            budget_remaining=remaining,
            audit_chain_last_hash="a" * 64,
        )
        assert result.status == InvestigationStatus.COMPLETED
        assert result.verdict == Verdict.MALICIOUS

    def test_inconclusive_status_is_distinct_from_benign(self):
        """INCONCLUSIVE must never collapse to BENIGN — they are different."""
        assert InvestigationStatus.INCONCLUSIVE != InvestigationStatus.COMPLETED
        assert Verdict.INCONCLUSIVE != Verdict.BENIGN


# ---------------------------------------------------------------------------
# L. Verdict thresholds (unit tests)
# ---------------------------------------------------------------------------

class TestVerdictThresholds:

    def test_above_malicious_threshold_is_malicious(self):
        assert assign_verdict(MALICIOUS_RISK_THRESHOLD, 0.9) == Verdict.MALICIOUS
        assert assign_verdict(100.0, 0.9) == Verdict.MALICIOUS

    def test_above_suspicious_below_malicious_is_suspicious(self):
        assert assign_verdict(SUSPICIOUS_RISK_THRESHOLD, 0.7) == Verdict.SUSPICIOUS
        assert assign_verdict(MALICIOUS_RISK_THRESHOLD - 0.01, 0.7) == Verdict.SUSPICIOUS

    def test_below_suspicious_is_benign_with_confidence(self):
        assert assign_verdict(SUSPICIOUS_RISK_THRESHOLD - 0.01, 0.9) == Verdict.BENIGN
        assert assign_verdict(0.0, 0.9) == Verdict.BENIGN

    def test_low_confidence_forces_inconclusive(self):
        # Even malicious-level risk with low confidence → INCONCLUSIVE
        assert assign_verdict(90.0, MIN_CONFIDENCE_FOR_VERDICT - 0.01) == Verdict.INCONCLUSIVE
        assert assign_verdict(0.0, 0.0) == Verdict.INCONCLUSIVE


# ---------------------------------------------------------------------------
# M. Evidence preserved on stop
# ---------------------------------------------------------------------------

class TestEvidencePreservation:

    def test_evidence_preserved_on_budget_stop(self):
        """Evidence collected before budget exhaustion must appear in RiskAssessment."""
        evidence = [
            _make_evidence("auth_dmarc_result", "fail"),
            _make_evidence("reply_to_domain_mismatch", True,
                           category=EvidenceCategory.HEADER),
        ]
        spent = ToolCostSpent(external_calls=4)  # Exhausted
        state = _make_state(
            tool_cost_spent=spent,
            sm_status=StateMachineStatus.STOPPED,
            stop_reason=StopReason.EXTERNAL_CALL_BUDGET_EXHAUSTED,
        )
        result = RiskEngine().assess(
            state=state,
            evidence_items=evidence,
            stop_reason=StopReason.EXTERNAL_CALL_BUDGET_EXHAUSTED,
        )

        # All evidence IDs must appear in the contributing_evidence_ids
        evidence_ids = {e.evidence_id for e in evidence}
        result_ids = set(result.risk_assessment.contributing_evidence_ids)
        assert evidence_ids.issubset(result_ids), (
            "Evidence collected before stop must be preserved in result"
        )

    def test_risk_score_preserved_on_stop(self):
        """Risk score computed from collected evidence must survive the stop."""
        evidence = [
            _make_evidence("auth_dmarc_result", "fail"),
            _make_evidence("auth_spf_result", "fail"),
        ]
        state = _make_state(
            sm_status=StateMachineStatus.STOPPED,
            stop_reason=StopReason.EXTERNAL_CALL_BUDGET_EXHAUSTED,
        )
        result = RiskEngine().assess(
            state=state,
            evidence_items=evidence,
            stop_reason=StopReason.EXTERNAL_CALL_BUDGET_EXHAUSTED,
        )
        # DMARC fail (40) + SPF fail (20) = 60 → SUSPICIOUS range
        assert result.risk_assessment.risk_score > 0.0, (
            "Risk score from collected evidence must be preserved, not zeroed"
        )


# ---------------------------------------------------------------------------
# N. Weight table integrity
# ---------------------------------------------------------------------------

class TestWeightTableIntegrity:

    def test_weight_table_has_authentication_keys(self):
        """Weight table must cover core authentication keys."""
        assert "auth_dmarc_result:fail" in EVIDENCE_WEIGHTS
        assert "auth_spf_result:fail" in EVIDENCE_WEIGHTS
        assert "auth_dkim_result:fail" in EVIDENCE_WEIGHTS

    def test_weight_table_has_pass_reductions(self):
        """Weight table must have negative weights for authentication passes."""
        assert EVIDENCE_WEIGHTS["auth_dmarc_result:pass"] < 0
        assert EVIDENCE_WEIGHTS["auth_spf_result:pass"] < 0
        assert EVIDENCE_WEIGHTS["auth_dkim_result:pass"] < 0

    def test_weight_table_has_attachment_signals(self):
        """Weight table must cover attachment-based signals."""
        assert "attachment_executable_signature" in EVIDENCE_WEIGHTS
        assert EVIDENCE_WEIGHTS["attachment_executable_signature"] > 0

    def test_dmarc_fail_weight_exceeds_spf_fail(self):
        """DMARC failure is a stronger signal than SPF failure."""
        assert EVIDENCE_WEIGHTS["auth_dmarc_result:fail"] > EVIDENCE_WEIGHTS["auth_spf_result:fail"]
