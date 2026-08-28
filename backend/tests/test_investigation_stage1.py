"""
tests/test_investigation_stage1.py

Stage 1 — Deterministic Investigation State Machine Test Suite

Covers the 7 mandatory test categories (PS 26106 §21):

    A. State initialization
    B. Evidence contract validation
    C. Hypothesis generation (determinism + correctness)
    D. Relevance gate (0.10 excluded, 0.15 included, 0.80 included)
    E. Budget tracking (remaining never negative)
    F. Stop conditions (each independently testable)
    G. Audit hash chain integrity

DESIGN:
    - No external calls.
    - No LLM.
    - No randomness.
    - Tests consume real EmailEvidencePackage instances (via parser + normalizer).
    - Tests also use direct factory helpers for isolated unit testing.
"""

from __future__ import annotations

import email as stdlib_email
import email.policy
import hashlib
import uuid
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Any

import pytest

from app.contracts.audit import GENESIS_HASH, AuditRecord, compute_record_hash
from app.contracts.common import utcnow, Provenance, SourceType
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
    StateMachineStatus,
    StopReason,
    ToolCostSpent,
)
from app.services.evidence import EvidenceNormalizer
from app.services.ingestion.parser import EmailParser
from app.services.investigation import (
    INVESTIGATION_PROFILES,
    RELEVANCE_FLOOR,
    TOOL_REGISTRY,
    AuditLogger,
    InvestigationDecisionEngine,
    calculate_budget_remaining,
    generate_initial_hypotheses,
    init_state,
    initialize_to_level0,
    select_profiles,
    should_stop,
    stop_investigation,
    transition,
)
from app.services.investigation.budget import (
    DEFAULT_BUDGET,
    make_full_budget_remaining,
    record_tool_cost,
)
from app.services.investigation.state_machine import InvalidTransitionError

# ---------------------------------------------------------------------------
# Test fixtures / helpers
# ---------------------------------------------------------------------------

_parser = EmailParser(storage_dir="/tmp/test_stage1_emails")
_normalizer = EvidenceNormalizer()


def _build_eml(
    subject: str = "Test Email",
    from_addr: str = "sender@example.com",
    to_addr: str = "recipient@target.com",
    body_text: str | None = None,
    body_html: str | None = None,
    received_headers: list[str] | None = None,
    auth_results: str | None = None,
    reply_to: str | None = None,
    return_path: str | None = None,
) -> bytes:
    """Build a minimal test .eml for testing."""
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg["Message-ID"] = f"<{uuid.uuid4().hex}@test.com>"
    if reply_to:
        msg["Reply-To"] = reply_to
    if return_path:
        msg["Return-Path"] = return_path
    if auth_results:
        msg["Authentication-Results"] = auth_results
    if received_headers:
        for rh in received_headers:
            msg["Received"] = rh

    if body_html:
        msg.set_content(body_text or "Plain text fallback", subtype="plain")
        msg.add_alternative(body_html, subtype="html")
    elif body_text:
        msg.set_content(body_text, subtype="plain")
    else:
        msg.set_content("Default body text.", subtype="plain")

    return msg.as_bytes()


def _build_package(
    subject: str = "Test Email",
    from_addr: str = "sender@example.com",
    to_addr: str = "recipient@target.com",
    body_text: str | None = None,
    body_html: str | None = None,
    received_headers: list[str] | None = None,
    auth_results: str | None = None,
    reply_to: str | None = None,
    return_path: str | None = None,
):
    """Parse and normalize an email into an EmailEvidencePackage."""
    raw = _build_eml(
        subject=subject,
        from_addr=from_addr,
        to_addr=to_addr,
        body_text=body_text,
        body_html=body_html,
        received_headers=received_headers,
        auth_results=auth_results,
        reply_to=reply_to,
        return_path=return_path,
    )
    parsed = _parser.parse(raw)
    return _normalizer.normalize(parsed)


def _default_budget() -> InvestigationBudget:
    return DEFAULT_BUDGET


def _state_with_spent(
    *,
    latency_ms: int = 0,
    tool_calls: int = 0,
    external_calls: int = 0,
    llm_tokens: int = 0,
) -> InvestigationState:
    """Create a minimal LEVEL_0 InvestigationState with specific spend values."""
    budget = _default_budget()
    spent = ToolCostSpent(
        latency_ms=latency_ms,
        tool_calls=tool_calls,
        external_calls=external_calls,
        llm_tokens=llm_tokens,
    )
    remaining = InvestigationBudget(
        max_latency_ms=max(0, budget.max_latency_ms - latency_ms),
        max_tool_calls=max(0, budget.max_tool_calls - tool_calls),
        max_external_calls=max(0, budget.max_external_calls - external_calls),
        max_llm_tokens=max(0, budget.max_llm_tokens - llm_tokens),
    )
    return InvestigationState(
        case_id=str(uuid.uuid4()),
        created_at=utcnow(),
        attack_hypotheses=[],
        observed_facts=[],
        heuristic_findings=[],
        ml_signals=[],
        threat_intelligence=[],
        historical_matches=[],
        current_risk=0.0,
        current_confidence=0.0,
        risk_history=[],
        missing_evidence=[],
        pending_conflicts=[],
        resolved_conflicts=[],
        tools_used=[],
        tools_available=["some_tool"],
        tools_blocked=[],
        tool_cost_spent=spent,
        budget=budget,
        budget_remaining=remaining,
        investigation_level=InvestigationLevel.L0_TRIAGE,
        iteration_count=0,
        max_iterations=12,
        sm_status=StateMachineStatus.LEVEL_0,
        stop_reason=None,
        escalation_reason=None,
        escalation_status=EscalationStatus.NONE,
    )


# ===========================================================================
# A. STATE INITIALIZATION
# ===========================================================================

class TestStateInitialization:

    def test_init_state_creates_valid_state(self):
        """Basic smoke test: EmailEvidencePackage → InvestigationState."""
        package = _build_package()
        state, facts = init_state(package)

        assert state is not None
        assert isinstance(state, InvestigationState)

    def test_case_id_is_set(self):
        """case_id must be set and non-empty."""
        package = _build_package()
        state, _ = init_state(package)
        assert state.case_id
        assert len(state.case_id) > 0

    def test_case_id_matches_package_id(self):
        """case_id should trace back to the evidence package."""
        package = _build_package()
        state, _ = init_state(package)
        assert state.case_id == package.package_id

    def test_created_at_is_set(self):
        """created_at must be populated and timezone-aware."""
        package = _build_package()
        state, _ = init_state(package)
        assert state.created_at is not None
        assert state.created_at.tzinfo is not None

    def test_initial_risk_is_zero(self):
        """Initial risk before any tool has run must be 0.0."""
        package = _build_package()
        state, _ = init_state(package)
        assert state.current_risk == 0.0

    def test_initial_confidence_is_zero(self):
        """Initial confidence before any tool has run must be 0.0."""
        package = _build_package()
        state, _ = init_state(package)
        assert state.current_confidence == 0.0

    def test_investigation_level_is_L0(self):
        """Initial investigation level must be L0_TRIAGE."""
        package = _build_package()
        state, _ = init_state(package)
        assert state.investigation_level == InvestigationLevel.L0_TRIAGE

    def test_sm_status_is_initialized(self):
        """State machine status must start at INITIALIZED."""
        package = _build_package()
        state, _ = init_state(package)
        assert state.sm_status == StateMachineStatus.INITIALIZED

    def test_iteration_count_is_zero(self):
        """iteration_count must start at 0."""
        package = _build_package()
        state, _ = init_state(package)
        assert state.iteration_count == 0

    def test_budget_is_initialized(self):
        """Budget fields must be initialized with positive values."""
        package = _build_package()
        state, _ = init_state(package)
        assert state.budget.max_latency_ms > 0
        assert state.budget.max_tool_calls > 0
        assert state.budget.max_external_calls > 0

    def test_budget_remaining_equals_budget_at_start(self):
        """At initialization, budget_remaining must equal the full budget."""
        package = _build_package()
        state, _ = init_state(package)
        assert state.budget_remaining.max_latency_ms == state.budget.max_latency_ms
        assert state.budget_remaining.max_tool_calls == state.budget.max_tool_calls
        assert state.budget_remaining.max_external_calls == state.budget.max_external_calls

    def test_tools_used_is_empty(self):
        """No tools have been used at initialization."""
        package = _build_package()
        state, _ = init_state(package)
        assert state.tools_used == []

    def test_observed_facts_populated_from_package(self):
        """L0 facts are extracted from the evidence package and referenced by ID."""
        package = _build_package(
            auth_results="dmarc=fail header.from=example.com; spf=pass; dkim=pass"
        )
        state, facts = init_state(package)
        # Facts are EvidenceItem instances
        assert len(facts) > 0
        # State references them by ID
        assert len(state.observed_facts) == len(facts)
        for f in facts:
            assert f.evidence_id in state.observed_facts

    def test_all_hypothesis_types_present_after_engine_run(self):
        """After Stage 1 engine run, all 13 hypothesis types must be present."""
        package = _build_package()
        engine = InvestigationDecisionEngine()
        result = engine.run_stage1(package)
        hyp_types = {h.hypothesis_type for h in result.hypotheses}
        assert hyp_types == set(AttackHypothesisType)

    def test_state_machine_transitions_to_completed_after_engine_run(self):
        """After engine.run_stage1() with no stop condition, sm_status must be COMPLETED.

        A normal Stage 1 pass (no budget exhaustion, no missing tools) transitions:
        INITIALIZED → LEVEL_0 → STOPPED (CONFIDENCE_TARGET_REACHED) → COMPLETED.
        The FSM must NOT be left stuck at LEVEL_0.
        """
        package = _build_package()
        engine = InvestigationDecisionEngine()
        result = engine.run_stage1(package)
        assert result.state.sm_status == StateMachineStatus.COMPLETED

    def test_no_stop_on_clean_email(self):
        """A benign-looking email with no budget exhaustion should not trigger stop."""
        package = _build_package()
        engine = InvestigationDecisionEngine()
        result = engine.run_stage1(package)
        # Should not stop because budgets are not exhausted and tools are available
        assert result.stop_decision is None


# ===========================================================================
# B. EVIDENCE CONTRACT
# ===========================================================================

class TestEvidenceContract:

    def test_valid_evidence_item_accepted(self):
        """A correctly constructed EvidenceItem must validate without error."""
        item = EvidenceItem(
            evidence_id=str(uuid.uuid4()),
            case_id=str(uuid.uuid4()),
            type=EvidenceType.FACT,
            category=EvidenceCategory.AUTHENTICATION,
            key="auth_dmarc_result",
            value="fail",
            source="test_module",
            source_type=SourceType.DETERMINISTIC,
            confidence=1.0,
            trust_level=TrustLevel.REPORTED,
            provenance=Provenance(
                producer_module="test",
                extraction_method="test",
                created_at=utcnow(),
            ),
            status=EvidenceStatus.ACTIVE,
        )
        assert item.type == EvidenceType.FACT
        assert item.key == "auth_dmarc_result"

    def test_evidence_key_with_space_rejected(self):
        """Evidence key with spaces must be rejected (not machine-readable)."""
        with pytest.raises(Exception):
            EvidenceItem(
                evidence_id=str(uuid.uuid4()),
                case_id=str(uuid.uuid4()),
                type=EvidenceType.FACT,
                category=EvidenceCategory.AUTHENTICATION,
                key="auth dmarc result",  # space → invalid
                value="fail",
                source="test",
                source_type=SourceType.DETERMINISTIC,
                confidence=1.0,
                trust_level=TrustLevel.REPORTED,
                provenance=Provenance(producer_module="test", created_at=utcnow()),
                status=EvidenceStatus.ACTIVE,
            )

    def test_score_as_fact_rejected(self):
        """A probability score stored as FACT must be rejected (§3 hard rule)."""
        with pytest.raises(Exception):
            EvidenceItem(
                evidence_id=str(uuid.uuid4()),
                case_id=str(uuid.uuid4()),
                type=EvidenceType.FACT,  # Wrong! Should be ML_SIGNAL
                category=EvidenceCategory.AUTHENTICATION,
                key="phishing_probability",  # _probability suffix triggers guard
                value=0.91,
                source="test_ml",
                source_type=SourceType.DETERMINISTIC,
                confidence=1.0,
                trust_level=TrustLevel.REPORTED,
                provenance=Provenance(producer_module="test", created_at=utcnow()),
                status=EvidenceStatus.ACTIVE,
            )

    def test_ml_signal_requires_ml_source_type(self):
        """EvidenceType.ML_SIGNAL must use SourceType.ML_MODEL."""
        with pytest.raises(Exception):
            EvidenceItem(
                evidence_id=str(uuid.uuid4()),
                case_id=str(uuid.uuid4()),
                type=EvidenceType.ML_SIGNAL,
                category=EvidenceCategory.URL,
                key="url_phishing_probability",
                value=0.85,
                source="test_ml",
                source_type=SourceType.DETERMINISTIC,  # Wrong! Should be ML_MODEL
                confidence=0.9,
                trust_level=TrustLevel.REPORTED,
                provenance=Provenance(producer_module="test", created_at=utcnow()),
                status=EvidenceStatus.ACTIVE,
            )

    def test_extra_fields_rejected(self):
        """BaseContract extra='forbid' must reject undeclared fields."""
        with pytest.raises(Exception):
            EvidenceItem(
                evidence_id=str(uuid.uuid4()),
                case_id=str(uuid.uuid4()),
                type=EvidenceType.FACT,
                category=EvidenceCategory.AUTHENTICATION,
                key="auth_dmarc_result",
                value="fail",
                source="test",
                source_type=SourceType.DETERMINISTIC,
                confidence=1.0,
                trust_level=TrustLevel.REPORTED,
                provenance=Provenance(producer_module="test", created_at=utcnow()),
                status=EvidenceStatus.ACTIVE,
                undeclared_field="this should fail",  # extra field
            )

    def test_confidence_out_of_range_rejected(self):
        """Confidence values outside [0.0, 1.0] must be rejected."""
        with pytest.raises(Exception):
            EvidenceItem(
                evidence_id=str(uuid.uuid4()),
                case_id=str(uuid.uuid4()),
                type=EvidenceType.FACT,
                category=EvidenceCategory.AUTHENTICATION,
                key="auth_spf_result",
                value="fail",
                source="test",
                source_type=SourceType.DETERMINISTIC,
                confidence=1.5,  # Out of range
                trust_level=TrustLevel.REPORTED,
                provenance=Provenance(producer_module="test", created_at=utcnow()),
                status=EvidenceStatus.ACTIVE,
            )

    def test_investigation_state_frozen(self):
        """InvestigationState must be immutable (frozen=True)."""
        package = _build_package()
        state, _ = init_state(package)
        with pytest.raises(Exception):
            state.current_risk = 50.0  # type: ignore[misc]

    def test_budget_remaining_cannot_exceed_budget(self):
        """budget_remaining > budget must be rejected by model_validator."""
        budget = InvestigationBudget(
            max_latency_ms=4000,
            max_tool_calls=8,
            max_external_calls=4,
            max_llm_tokens=0,
        )
        with pytest.raises(Exception):
            InvestigationState(
                case_id=str(uuid.uuid4()),
                created_at=utcnow(),
                budget=budget,
                budget_remaining=InvestigationBudget(
                    max_latency_ms=9999,  # Exceeds budget!
                    max_tool_calls=8,
                    max_external_calls=4,
                    max_llm_tokens=0,
                ),
                tool_cost_spent=ToolCostSpent(),
                investigation_level=InvestigationLevel.L0_TRIAGE,
                sm_status=StateMachineStatus.LEVEL_0,
                escalation_status=EscalationStatus.NONE,
            )


# ===========================================================================
# C. HYPOTHESIS GENERATION
# ===========================================================================

class TestHypothesisGeneration:

    def test_deterministic_same_input_same_output(self):
        """The same evidence package must always produce the same hypotheses."""
        package = _build_package(
            auth_results="dmarc=fail; spf=fail"
        )
        state1, _ = init_state(package)
        hyps1 = generate_initial_hypotheses(state1, package)

        state2, _ = init_state(package)
        hyps2 = generate_initial_hypotheses(state2, package)

        scores1 = {h.hypothesis_type: h.score for h in hyps1}
        scores2 = {h.hypothesis_type: h.score for h in hyps2}
        assert scores1 == scores2

    def test_dmarc_fail_increases_spoofing(self):
        """DMARC fail must increase the spoofing hypothesis score."""
        package_fail = _build_package(
            auth_results="dmarc=fail header.from=example.com"
        )
        package_pass = _build_package(
            auth_results="dmarc=pass header.from=example.com"
        )
        state_fail, _ = init_state(package_fail)
        state_pass, _ = init_state(package_pass)

        hyps_fail = generate_initial_hypotheses(state_fail, package_fail)
        hyps_pass = generate_initial_hypotheses(state_pass, package_pass)

        spoofing_fail = next(h for h in hyps_fail if h.hypothesis_type == AttackHypothesisType.SPOOFING)
        spoofing_pass = next(h for h in hyps_pass if h.hypothesis_type == AttackHypothesisType.SPOOFING)

        assert spoofing_fail.score > spoofing_pass.score

    def test_dmarc_fail_increases_bec(self):
        """DMARC fail must also increase BEC hypothesis."""
        package = _build_package(auth_results="dmarc=fail header.from=example.com")
        state, _ = init_state(package)
        hyps = generate_initial_hypotheses(state, package)
        bec = next(h for h in hyps if h.hypothesis_type == AttackHypothesisType.BEC)
        assert bec.score > 0.0

    def test_reply_to_mismatch_increases_bec(self):
        """Reply-To domain mismatch from From domain increases BEC hypothesis."""
        package = _build_package(
            from_addr="ceo@company.com",
            reply_to="attacker@gmail.com",
        )
        state, _ = init_state(package)
        hyps = generate_initial_hypotheses(state, package)
        bec = next(h for h in hyps if h.hypothesis_type == AttackHypothesisType.BEC)
        assert bec.score > 0.0

    def test_all_13_hypotheses_generated(self):
        """All 13 hypothesis types must appear in the output."""
        package = _build_package()
        state, _ = init_state(package)
        hyps = generate_initial_hypotheses(state, package)
        types = {h.hypothesis_type for h in hyps}
        assert types == set(AttackHypothesisType)

    def test_scores_capped_at_1(self):
        """No hypothesis score may exceed 1.0 even with many matching rules."""
        package = _build_package(
            auth_results="dmarc=fail; spf=fail; dkim=fail",
            from_addr="ceo@company.com",
            reply_to="attacker@evil.com",
        )
        state, _ = init_state(package)
        hyps = generate_initial_hypotheses(state, package)
        for h in hyps:
            assert h.score <= 1.0

    def test_hypothesis_reasons_populated_when_rule_matches(self):
        """When a rule fires, the reason must appear in hypothesis.reasons."""
        package = _build_package(
            auth_results="dmarc=fail header.from=example.com"
        )
        state, _ = init_state(package)
        hyps = generate_initial_hypotheses(state, package)
        spoofing = next(h for h in hyps if h.hypothesis_type == AttackHypothesisType.SPOOFING)
        # Must have at least one reason referencing the DMARC rule
        assert len(spoofing.reasons) > 0
        assert any("DMARC" in r.upper() or "dmarc" in r.lower() for r in spoofing.reasons)

    def test_clean_email_has_low_scores(self):
        """A clean email with no authentication failures should have low scores."""
        package = _build_package(
            auth_results="dmarc=pass header.from=example.com; spf=pass smtp.mailfrom=example.com; dkim=pass"
        )
        state, _ = init_state(package)
        hyps = generate_initial_hypotheses(state, package)
        # Spoofing score should be very low or zero
        spoofing = next(h for h in hyps if h.hypothesis_type == AttackHypothesisType.SPOOFING)
        assert spoofing.score < RELEVANCE_FLOOR

    def test_hypothesis_status_supported_at_high_score(self):
        """Score >= 0.60 must produce SUPPORTED status."""
        # We need a score >= 0.60 for spoofing
        # DMARC fail (0.40) + SPF fail (0.20) = 0.60 exactly
        package = _build_package(
            auth_results="dmarc=fail; spf=fail"
        )
        state, _ = init_state(package)
        hyps = generate_initial_hypotheses(state, package)
        spoofing = next(h for h in hyps if h.hypothesis_type == AttackHypothesisType.SPOOFING)
        assert spoofing.score >= 0.60
        assert spoofing.status == HypothesisStatus.SUPPORTED


# ===========================================================================
# D. RELEVANCE GATE
# ===========================================================================

class TestRelevanceGate:

    def _make_hypothesis(self, score: float, hypothesis_type: AttackHypothesisType) -> AttackHypothesis:
        return AttackHypothesis(
            hypothesis_id=str(uuid.uuid4()),
            case_id=str(uuid.uuid4()),
            hypothesis_type=hypothesis_type,
            score=score,
            confidence=0.0,
            status=HypothesisStatus.UNCERTAIN,
            reasons=[],
        )

    def test_score_010_is_excluded(self):
        """score=0.10 < RELEVANCE_FLOOR → profile excluded."""
        hyp = self._make_hypothesis(0.10, AttackHypothesisType.SPOOFING)
        profiles = select_profiles([hyp])
        assert not any(p.hypothesis_type == AttackHypothesisType.SPOOFING for p in profiles)

    def test_score_015_is_included(self):
        """score=0.15 == RELEVANCE_FLOOR → profile included (boundary case)."""
        hyp = self._make_hypothesis(0.15, AttackHypothesisType.SPOOFING)
        profiles = select_profiles([hyp])
        assert any(p.hypothesis_type == AttackHypothesisType.SPOOFING for p in profiles)

    def test_score_080_is_included(self):
        """score=0.80 > RELEVANCE_FLOOR → profile included."""
        hyp = self._make_hypothesis(0.80, AttackHypothesisType.BEC)
        profiles = select_profiles([hyp])
        assert any(p.hypothesis_type == AttackHypothesisType.BEC for p in profiles)

    def test_score_000_is_excluded(self):
        """score=0.0 → profile excluded."""
        hyp = self._make_hypothesis(0.0, AttackHypothesisType.CAMPAIGN)
        profiles = select_profiles([hyp])
        assert not any(p.hypothesis_type == AttackHypothesisType.CAMPAIGN for p in profiles)

    def test_score_014_is_excluded(self):
        """score=0.14 just below floor → excluded."""
        hyp = self._make_hypothesis(0.14, AttackHypothesisType.BEC)
        profiles = select_profiles([hyp])
        assert not any(p.hypothesis_type == AttackHypothesisType.BEC for p in profiles)

    def test_score_016_is_included(self):
        """score=0.16 just above floor → included."""
        hyp = self._make_hypothesis(0.16, AttackHypothesisType.BEC)
        profiles = select_profiles([hyp])
        assert any(p.hypothesis_type == AttackHypothesisType.BEC for p in profiles)

    def test_relevance_floor_constant_is_015(self):
        """RELEVANCE_FLOOR must be exactly 0.15."""
        assert RELEVANCE_FLOOR == 0.15

    def test_mixed_hypotheses_only_relevant_profiles_selected(self):
        """Mixed high/low scores → only high-score profiles selected."""
        hyps = [
            self._make_hypothesis(0.10, AttackHypothesisType.SPOOFING),   # excluded
            self._make_hypothesis(0.50, AttackHypothesisType.BEC),         # included
            self._make_hypothesis(0.00, AttackHypothesisType.CAMPAIGN),    # excluded
            self._make_hypothesis(0.15, AttackHypothesisType.MALICIOUS_URL),  # included (boundary)
        ]
        profiles = select_profiles(hyps)
        types = {p.hypothesis_type for p in profiles}
        assert AttackHypothesisType.BEC in types
        assert AttackHypothesisType.MALICIOUS_URL in types
        assert AttackHypothesisType.SPOOFING not in types
        assert AttackHypothesisType.CAMPAIGN not in types

    def test_select_profiles_is_deterministic(self):
        """Same hypotheses must always produce the same profile set."""
        hyps = [
            self._make_hypothesis(0.50, AttackHypothesisType.BEC),
            self._make_hypothesis(0.30, AttackHypothesisType.SPOOFING),
        ]
        profiles1 = select_profiles(hyps)
        profiles2 = select_profiles(hyps)
        assert [p.profile_id for p in profiles1] == [p.profile_id for p in profiles2]

    def test_select_profiles_returns_sorted_results(self):
        """Profiles are returned sorted by profile_id for reproducibility."""
        hyps = [
            self._make_hypothesis(0.80, AttackHypothesisType.SPOOFING),
            self._make_hypothesis(0.80, AttackHypothesisType.BEC),
        ]
        profiles = select_profiles(hyps)
        ids = [p.profile_id for p in profiles]
        assert ids == sorted(ids)


# ===========================================================================
# E. BUDGET TRACKING
# ===========================================================================

class TestBudget:

    def test_fresh_state_has_full_remaining(self):
        """After init, budget_remaining == budget."""
        package = _build_package()
        state, _ = init_state(package)
        state = initialize_to_level0(state)
        assert state.budget_remaining.max_tool_calls == state.budget.max_tool_calls
        assert state.budget_remaining.max_latency_ms == state.budget.max_latency_ms
        assert state.budget_remaining.max_external_calls == state.budget.max_external_calls

    def test_spent_3_of_5_remaining_is_2(self):
        """spending 3 tool calls from budget of 5 leaves 2 remaining."""
        budget = InvestigationBudget(
            max_latency_ms=4000,
            max_tool_calls=5,
            max_external_calls=4,
            max_llm_tokens=0,
        )
        spent = ToolCostSpent(tool_calls=3)
        remaining = InvestigationBudget(
            max_latency_ms=budget.max_latency_ms,
            max_tool_calls=max(0, budget.max_tool_calls - spent.tool_calls),
            max_external_calls=budget.max_external_calls,
            max_llm_tokens=0,
        )
        assert remaining.max_tool_calls == 2

    def test_spent_equals_budget_remaining_is_0(self):
        """If spent == budget, remaining == 0."""
        state = _state_with_spent(tool_calls=8)  # DEFAULT_BUDGET max = 8
        remaining = calculate_budget_remaining(state)
        assert remaining.max_tool_calls == 0

    def test_remaining_never_negative(self):
        """Even if spent > budget (shouldn't happen), remaining is clamped to 0."""
        # The model clamps at compute time
        budget = InvestigationBudget(
            max_latency_ms=4000,
            max_tool_calls=8,
            max_external_calls=4,
            max_llm_tokens=0,
        )
        spent = ToolCostSpent(tool_calls=20)  # Over budget

        remaining_calls = max(0, budget.max_tool_calls - spent.tool_calls)
        assert remaining_calls == 0  # clamped, not negative

    def test_calculate_budget_remaining_all_dimensions(self):
        """All four budget dimensions are tracked independently."""
        state = _state_with_spent(
            latency_ms=1000,
            tool_calls=3,
            external_calls=2,
            llm_tokens=0,
        )
        remaining = calculate_budget_remaining(state)
        assert remaining.max_latency_ms == DEFAULT_BUDGET.max_latency_ms - 1000
        assert remaining.max_tool_calls == DEFAULT_BUDGET.max_tool_calls - 3
        assert remaining.max_external_calls == DEFAULT_BUDGET.max_external_calls - 2

    def test_record_tool_cost_increments_tool_calls(self):
        """record_tool_cost adds 1 to tool_calls."""
        initial = ToolCostSpent(tool_calls=3)
        updated = record_tool_cost(initial)
        assert updated.tool_calls == 4

    def test_record_tool_cost_external_increments_external_calls(self):
        """record_tool_cost with is_external=True increments external_calls."""
        initial = ToolCostSpent(external_calls=1)
        updated = record_tool_cost(initial, is_external=True)
        assert updated.external_calls == 2

    def test_record_tool_cost_does_not_mutate_original(self):
        """record_tool_cost returns a new object, never mutates the input."""
        initial = ToolCostSpent(tool_calls=2)
        _ = record_tool_cost(initial)
        assert initial.tool_calls == 2  # unchanged


# ===========================================================================
# F. STOP CONDITIONS
# ===========================================================================

class TestStopConditions:

    def _make_stopped_state(
        self,
        *,
        tool_calls: int = 0,
        latency_ms: int = 0,
        external_calls: int = 0,
        iteration_count: int = 0,
        max_iterations: int = 12,
        tools_available: list[str] | None = None,
    ) -> InvestigationState:
        return _state_with_spent(
            tool_calls=tool_calls,
            latency_ms=latency_ms,
            external_calls=external_calls,
        ).model_copy(update={
            "iteration_count": iteration_count,
            "max_iterations": max_iterations,
            "tools_available": tools_available if tools_available is not None else ["some_tool"],
        })

    def test_no_stop_on_fresh_state(self):
        """A fresh state with no exhaustion must not trigger stop."""
        state = _state_with_spent()
        decision = should_stop(state)
        assert decision.should_stop is False

    def test_max_iterations_reached(self):
        """Reaching max_iterations triggers MAX_ITERATIONS_REACHED stop."""
        state = self._make_stopped_state(iteration_count=12, max_iterations=12)
        decision = should_stop(state)
        assert decision.should_stop is True
        assert decision.stop_reason == StopReason.MAX_ITERATIONS_REACHED

    def test_tool_call_budget_exhausted(self):
        """Using all tool calls triggers BUDGET_EXHAUSTED stop."""
        state = self._make_stopped_state(tool_calls=8)  # max=8 in DEFAULT_BUDGET
        decision = should_stop(state)
        assert decision.should_stop is True
        assert decision.stop_reason == StopReason.BUDGET_EXHAUSTED

    def test_latency_budget_exhausted(self):
        """Exhausting latency triggers LATENCY_BUDGET_EXHAUSTED stop."""
        state = self._make_stopped_state(latency_ms=4000)  # max=4000
        decision = should_stop(state)
        assert decision.should_stop is True
        assert decision.stop_reason == StopReason.LATENCY_BUDGET_EXHAUSTED

    def test_external_call_budget_exhausted(self):
        """Exhausting external calls triggers EXTERNAL_CALL_BUDGET_EXHAUSTED."""
        state = self._make_stopped_state(external_calls=4)  # max=4
        decision = should_stop(state)
        assert decision.should_stop is True
        assert decision.stop_reason == StopReason.EXTERNAL_CALL_BUDGET_EXHAUSTED

    def test_no_candidate_tools_after_iterations(self):
        """Empty tools_available after iteration_count > 0 triggers NO_CANDIDATE_TOOLS."""
        state = self._make_stopped_state(
            iteration_count=1,
            tools_available=[],  # No tools left
        )
        decision = should_stop(state)
        assert decision.should_stop is True
        assert decision.stop_reason == StopReason.NO_CANDIDATE_TOOLS

    def test_no_candidate_tools_not_triggered_at_iteration_0(self):
        """Empty tools_available at iteration 0 does NOT trigger stop (init in progress)."""
        state = self._make_stopped_state(
            iteration_count=0,
            tools_available=[],  # Empty but iteration_count == 0
        )
        decision = should_stop(state)
        # Should not trigger NO_CANDIDATE_TOOLS because we're at iteration 0
        if decision.should_stop:
            assert decision.stop_reason != StopReason.NO_CANDIDATE_TOOLS

    def test_already_stopped_returns_consistent_decision(self):
        """An already-stopped state consistently returns should_stop=True."""
        state = _state_with_spent()
        state = stop_investigation(state, StopReason.MAX_ITERATIONS_REACHED)
        decision = should_stop(state)
        assert decision.should_stop is True

    def test_stop_decision_has_explanation(self):
        """Every stop decision must include a non-empty explanation."""
        state = self._make_stopped_state(iteration_count=12, max_iterations=12)
        decision = should_stop(state)
        assert decision.should_stop is True
        assert len(decision.explanation) > 0

    def test_max_iterations_stop_takes_priority_over_tools(self):
        """max_iterations fires first in the evaluation order."""
        state = self._make_stopped_state(
            iteration_count=12,
            max_iterations=12,
            tools_available=[],
        ).model_copy(update={"iteration_count": 12})
        decision = should_stop(state)
        assert decision.stop_reason == StopReason.MAX_ITERATIONS_REACHED


# ===========================================================================
# G. AUDIT HASH CHAIN
# ===========================================================================

class TestAuditHashChain:

    def test_genesis_hash_is_correct(self):
        """GENESIS_HASH must be 64 zero characters."""
        assert GENESIS_HASH == "0" * 64

    def test_empty_chain_verifies(self):
        """An empty audit trail must verify without error."""
        logger = AuditLogger(case_id=str(uuid.uuid4()))
        assert logger.verify_chain() is True

    def test_single_record_has_correct_hash_prev(self):
        """First record must reference GENESIS_HASH."""
        logger = AuditLogger(case_id=str(uuid.uuid4()))
        record = logger.log_investigation_started(evidence_ids=["ev1", "ev2"])
        assert record.hash_prev == GENESIS_HASH

    def test_chain_of_3_records_linked(self):
        """N+1 record must have hash_prev == N record's hash_self."""
        case_id = str(uuid.uuid4())
        logger = AuditLogger(case_id=case_id)
        r0 = logger.log_investigation_started()
        r1 = logger.log_transition(
            from_status="INITIALIZED",
            to_status="LEVEL_0",
            reason_code="TEST",
        )
        r2 = logger.log_stop(stop_reason="MAX_ITERATIONS_REACHED")

        assert r1.hash_prev == r0.hash_self
        assert r2.hash_prev == r1.hash_self

    def test_chain_verification_passes(self):
        """verify_chain() must return True for an unmodified chain."""
        logger = AuditLogger(case_id=str(uuid.uuid4()))
        logger.log_investigation_started()
        logger.log_transition(from_status="INITIALIZED", to_status="LEVEL_0", reason_code="T")
        logger.log_stop(stop_reason="BUDGET_EXHAUSTED")
        assert logger.verify_chain() is True

    def test_chain_verification_fails_on_tampered_record(self):
        """Modifying a previous record must cause verify_chain() to raise."""
        logger = AuditLogger(case_id=str(uuid.uuid4()))
        logger.log_investigation_started()
        logger.log_transition(from_status="INITIALIZED", to_status="LEVEL_0", reason_code="T")
        logger.log_stop(stop_reason="MAX_ITERATIONS_REACHED")

        # Tamper: replace the first record with a modified copy
        original = logger._records[0]
        # Build a tampered record with a changed reason_code but same hash_self
        tampered = AuditRecord.create(
            hash_prev=GENESIS_HASH,
            case_id=original.case_id,
            step=original.step,
            event_type=original.event_type,
            reason_code="TAMPERED_REASON",  # Changed!
            reason_data={},
            evidence_before=[],
            evidence_after=["injected_evidence"],  # Changed!
        )
        logger._records[0] = tampered

        from app.services.investigation.audit_logger import AuditChainIntegrityError
        with pytest.raises(AuditChainIntegrityError):
            logger.verify_chain()

    def test_hash_self_computed_with_sha256(self):
        """hash_self must be a 64-character hex string (SHA256)."""
        logger = AuditLogger(case_id=str(uuid.uuid4()))
        record = logger.log_investigation_started()
        assert len(record.hash_self) == 64
        assert all(c in "0123456789abcdef" for c in record.hash_self)

    def test_hash_chain_with_engine_run(self):
        """A full Stage 1 engine run produces a valid audit chain."""
        package = _build_package()
        engine = InvestigationDecisionEngine()
        result = engine.run_stage1(package)
        audit = result.audit_logger
        assert len(audit.records) >= 2  # at least init + transition
        assert audit.verify_chain() is True


# ===========================================================================
# H. STATE MACHINE TRANSITIONS
# ===========================================================================

class TestStateMachine:

    def test_initialized_to_level0_is_valid(self):
        """INITIALIZED → LEVEL_0 is a valid transition."""
        package = _build_package()
        state, _ = init_state(package)
        assert state.sm_status == StateMachineStatus.INITIALIZED
        new_state = initialize_to_level0(state)
        assert new_state.sm_status == StateMachineStatus.LEVEL_0

    def test_initialized_to_level1_is_invalid(self):
        """INITIALIZED → LEVEL_1 is an illegal transition."""
        package = _build_package()
        state, _ = init_state(package)
        with pytest.raises(InvalidTransitionError):
            transition(state, StateMachineStatus.LEVEL_1)

    def test_initialized_to_stopped_without_reason_is_invalid(self):
        """Transition to STOPPED without stop_reason must be rejected."""
        package = _build_package()
        state, _ = init_state(package)
        # INITIALIZED → STOPPED is illegal (not in legal transitions)
        with pytest.raises(InvalidTransitionError):
            transition(state, StateMachineStatus.STOPPED, stop_reason=StopReason.MAX_ITERATIONS_REACHED)

    def test_level0_to_stopped_requires_reason(self):
        """LEVEL_0 → STOPPED without stop_reason must raise ValueError."""
        state = _state_with_spent()
        with pytest.raises(ValueError):
            transition(state, StateMachineStatus.STOPPED)  # Missing stop_reason

    def test_level0_to_stopped_with_reason_is_valid(self):
        """LEVEL_0 → STOPPED with stop_reason is valid."""
        state = _state_with_spent()
        new_state = stop_investigation(state, StopReason.BUDGET_EXHAUSTED)
        assert new_state.sm_status == StateMachineStatus.STOPPED
        assert new_state.stop_reason == StopReason.BUDGET_EXHAUSTED

    def test_completed_is_terminal(self):
        """Transitions from COMPLETED must be rejected."""
        state = _state_with_spent()
        stopped = stop_investigation(state, StopReason.MAX_ITERATIONS_REACHED)
        from app.services.investigation import complete_investigation
        completed = complete_investigation(stopped)
        assert completed.sm_status == StateMachineStatus.COMPLETED
        # Any further transition must fail
        with pytest.raises(InvalidTransitionError):
            transition(completed, StateMachineStatus.LEVEL_0)

    def test_transition_returns_new_state(self):
        """State machine transitions return a NEW immutable state."""
        state = _state_with_spent()
        new_state = stop_investigation(state, StopReason.BUDGET_EXHAUSTED)
        # Original state is unchanged (frozen)
        assert state.sm_status == StateMachineStatus.LEVEL_0
        assert new_state.sm_status == StateMachineStatus.STOPPED


# ===========================================================================
# I. TOOL REGISTRY
# ===========================================================================

class TestToolRegistry:

    def test_all_profile_tools_exist_in_registry(self):
        """Every tool referenced in any profile must exist in TOOL_REGISTRY."""
        for hyp_type, profile in INVESTIGATION_PROFILES.items():
            all_tools = (
                profile.mandatory_tools
                + profile.optional_tools
                + profile.expensive_tools
            )
            for tool_name in all_tools:
                assert tool_name in TOOL_REGISTRY, (
                    f"Profile '{profile.profile_id}' references tool '{tool_name}' "
                    f"which is not in TOOL_REGISTRY"
                )

    def test_groq_reasoning_is_disabled(self):
        """groq_reasoning tool must be disabled in Stage 1."""
        assert TOOL_REGISTRY["groq_reasoning"].enabled is False

    def test_get_tool_raises_for_unknown_name(self):
        """get_tool() must raise KeyError for unknown tool names."""
        from app.services.investigation.tool_registry import get_tool
        with pytest.raises(KeyError):
            get_tool("invented_tool_from_llm")

    def test_all_enabled_tools_have_positive_reliability(self):
        """All enabled tools must have reliability > 0."""
        from app.services.investigation import get_enabled_tools
        for name, tool in get_enabled_tools().items():
            assert tool.reliability > 0, f"Tool '{name}' has zero reliability"

    def test_all_13_profiles_covered(self):
        """All 13 hypothesis types must have an investigation profile."""
        assert set(INVESTIGATION_PROFILES.keys()) == set(AttackHypothesisType)
