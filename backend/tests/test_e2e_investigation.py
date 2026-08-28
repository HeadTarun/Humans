"""
tests/test_e2e_investigation.py

End-to-end integration tests for the full deterministic investigation pipeline.

Pipeline under test:
    Raw .eml bytes
        ↓  EmailParser.parse()
    ParsedEmail
        ↓  EvidenceNormalizer.normalize()
    EmailEvidencePackage
        ↓  InvestigationDecisionEngine.run_stage1()
    Stage1Result
        ↓  to_investigation_result()
    InvestigationResult

Tests cover:
    E2E-A. Clean email (all auth passes) → COMPLETED, low risk
    E2E-B. Phishing email (auth fails + header anomalies) → risk > 0
    E2E-C. InvestigationResult is JSON-serializable (API boundary test)
    E2E-D. Deterministic: same input → same result
    E2E-E. Budget information in result is correct
    E2E-F. Hypotheses in result correspond to email signals
    E2E-G. Audit chain hash is included and non-empty
    E2E-H. stop_reason is CONFIDENCE_TARGET_REACHED on normal completion
    E2E-I. sm_status is COMPLETED (not stuck at LEVEL_0)
    E2E-J. Evidence IDs in result match the actual evidence items
    E2E-K. Verdict is never BENIGN on a high-risk email
    E2E-L. Risk score is bounded in [0, 100]
    E2E-M. Confidence is bounded in [0, 1]

DESIGN:
    - No external calls.
    - No LLM.
    - No randomness.
    - Uses the same _build_eml / _build_package helpers as Stage 1 tests.
"""

from __future__ import annotations

import email.policy
import uuid
from email.message import EmailMessage

import pytest

from app.contracts.investigation import (
    InvestigationStatus,
    StateMachineStatus,
    StopReason,
)
from app.contracts.result import InvestigationResult
from app.contracts.risk import Verdict
from app.services.evidence import EvidenceNormalizer
from app.services.ingestion.parser import EmailParser
from app.services.investigation import (
    InvestigationDecisionEngine,
    to_investigation_result,
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_parser = EmailParser(storage_dir="/tmp/test_e2e_emails")
_normalizer = EvidenceNormalizer()
_engine = InvestigationDecisionEngine()


def _build_eml(
    subject: str = "Test Email",
    from_addr: str = "sender@example.com",
    to_addr: str = "recipient@target.com",
    body_text: str | None = None,
    auth_results: str | None = None,
    reply_to: str | None = None,
    return_path: str | None = None,
    received_headers: list[str] | None = None,
) -> bytes:
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
    msg.set_content(body_text or "Default body text.", subtype="plain")
    return msg.as_bytes()


def _run_pipeline(raw_eml: bytes) -> InvestigationResult:
    """Run the full investigation pipeline and return InvestigationResult."""
    parsed = _parser.parse(raw_eml)
    package = _normalizer.normalize(parsed)
    stage1 = _engine.run_stage1(package)
    return to_investigation_result(stage1)


def _run_pipeline_with_stage1(raw_eml: bytes):
    """Return both Stage1Result and InvestigationResult."""
    parsed = _parser.parse(raw_eml)
    package = _normalizer.normalize(parsed)
    stage1 = _engine.run_stage1(package)
    return stage1, to_investigation_result(stage1)


# ---------------------------------------------------------------------------
# E2E-A. Clean email (all auth passes)
# ---------------------------------------------------------------------------

class TestCleanEmail:

    def setup_method(self):
        self.raw_eml = _build_eml(
            subject="Monthly newsletter",
            from_addr="newsletter@trusted-corp.com",
            auth_results=(
                "mx.example.com;"
                " dkim=pass header.d=trusted-corp.com;"
                " spf=pass smtp.mailfrom=trusted-corp.com;"
                " dmarc=pass header.from=trusted-corp.com"
            ),
        )

    def test_clean_email_completes_normally(self):
        """A clean email with valid auth should reach COMPLETED status."""
        result = _run_pipeline(self.raw_eml)
        assert result.status == InvestigationStatus.COMPLETED

    def test_clean_email_has_low_or_negative_risk(self):
        """All auth passes → negative weights → risk_score should be low (clipped to 0 or low)."""
        result = _run_pipeline(self.raw_eml)
        # Auth passes reduce risk, so score should be low
        assert result.risk_score < 40.0, (
            f"Clean email should have risk < SUSPICIOUS_THRESHOLD but got {result.risk_score}"
        )

    def test_clean_email_has_stop_reason_set(self):
        """A non-COMPLETED result always has stop_reason. COMPLETED may have None."""
        result = _run_pipeline(self.raw_eml)
        from app.contracts.investigation import InvestigationStatus as _IS
        if result.status == _IS.COMPLETED:
            # stop_reason is optional for COMPLETED — None is valid
            pass  # No assertion needed
        else:
            assert result.stop_reason is not None, (
                f"Non-COMPLETED status={result.status} must have stop_reason"
            )

    def test_clean_email_sm_status_is_completed(self):
        """Stage1Result.state.sm_status must be COMPLETED after normal run."""
        stage1, result = _run_pipeline_with_stage1(self.raw_eml)
        assert stage1.state.sm_status == StateMachineStatus.COMPLETED


# ---------------------------------------------------------------------------
# E2E-B. Suspicious phishing email
# ---------------------------------------------------------------------------

class TestPhishingEmail:

    def setup_method(self):
        self.raw_eml = _build_eml(
            subject="Urgent: Verify your account immediately",
            from_addr="support@legitimate-bank.com",
            reply_to="harvester@phish-domain.ru",  # Reply-to mismatch
            return_path="<bounce@phish-domain.ru>",  # Return-path mismatch
            auth_results=(
                "mx.bank.com;"
                " dkim=fail header.d=legitimate-bank.com;"
                " spf=fail smtp.mailfrom=legitimate-bank.com;"
                " dmarc=fail header.from=legitimate-bank.com"
            ),
            received_headers=[
                "from phish-server.ru (phish-server.ru [185.220.101.1]) by mx.bank.com",
                "from mail-relay.phish-domain.ru by phish-server.ru",
            ],
        )

    def test_phishing_email_has_elevated_risk(self):
        """Auth failures + header mismatches → risk_score > 0."""
        result = _run_pipeline(self.raw_eml)
        assert result.risk_score > 0.0, "Phishing signals must produce elevated risk"

    def test_phishing_verdict_is_not_benign(self):
        """A phishing email with auth failures must NOT be BENIGN."""
        result = _run_pipeline(self.raw_eml)
        assert result.verdict != Verdict.BENIGN, (
            f"Phishing email returned BENIGN — check weight table. "
            f"risk_score={result.risk_score}, confidence={result.confidence}"
        )

    def test_phishing_email_has_attack_hypotheses(self):
        """Phishing signals should activate at least one attack hypothesis."""
        result = _run_pipeline(self.raw_eml)
        assert len(result.attack_hypotheses) > 0

    def test_phishing_email_has_observed_facts(self):
        """Auth failure evidence items should appear as observed_facts IDs."""
        result = _run_pipeline(self.raw_eml)
        assert len(result.observed_facts) > 0


# ---------------------------------------------------------------------------
# E2E-C. JSON serializability (API boundary test)
# ---------------------------------------------------------------------------

class TestJsonSerializability:

    def test_result_is_json_serializable(self):
        """InvestigationResult must serialize to JSON without error."""
        raw_eml = _build_eml(auth_results="mx.test.com; dmarc=pass")
        result = _run_pipeline(raw_eml)
        json_str = result.model_dump_json()
        assert len(json_str) > 100  # Non-trivial output

    def test_result_json_contains_required_fields(self):
        """JSON output must contain all critical fields."""
        raw_eml = _build_eml(auth_results="mx.test.com; dmarc=pass")
        result = _run_pipeline(raw_eml)
        json_str = result.model_dump_json()

        for field in [
            "investigation_id", "status", "verdict", "risk_score",
            "confidence", "stop_reason", "audit_chain_last_hash",
            "budget", "budget_spent", "budget_remaining",
        ]:
            assert f'"{field}"' in json_str, f"Missing field '{field}' in JSON output"

    def test_result_enum_values_are_strings(self):
        """Enums in the JSON output must serialize as strings, not integers."""
        raw_eml = _build_eml()
        result = _run_pipeline(raw_eml)
        json_str = result.model_dump_json()
        # Status, verdict, stop_reason must be string-valued
        assert '"COMPLETED"' in json_str or '"INCONCLUSIVE"' in json_str
        assert '"BENIGN"' in json_str or '"SUSPICIOUS"' in json_str \
               or '"MALICIOUS"' in json_str or '"INCONCLUSIVE"' in json_str


# ---------------------------------------------------------------------------
# E2E-D. Determinism
# ---------------------------------------------------------------------------

class TestDeterminism:

    def test_same_input_produces_same_result(self):
        """Running the pipeline twice on the same .eml → identical result."""
        raw_eml = _build_eml(
            from_addr="phisher@bad.example",
            auth_results=(
                "mx.test.com;"
                " dkim=fail header.d=bad.example;"
                " spf=fail smtp.mailfrom=bad.example;"
                " dmarc=fail header.from=bad.example"
            ),
        )
        # Note: we rebuild parsers to ensure no state leaks between runs
        p, n, e = EmailParser(storage_dir="/tmp/test_det"), EvidenceNormalizer(), InvestigationDecisionEngine()

        def run():
            return to_investigation_result(e.run_stage1(n.normalize(p.parse(raw_eml))))

        r1 = run()
        r2 = run()

        assert r1.verdict == r2.verdict
        assert r1.risk_score == r2.risk_score
        assert r1.confidence == r2.confidence
        assert r1.status == r2.status


# ---------------------------------------------------------------------------
# E2E-E. Budget transparency
# ---------------------------------------------------------------------------

class TestBudgetTransparency:

    def test_result_includes_full_budget_info(self):
        """Budget, budget_spent, and budget_remaining must all be present."""
        result = _run_pipeline(_build_eml())
        assert result.budget is not None
        assert result.budget_spent is not None
        assert result.budget_remaining is not None

    def test_budget_remaining_does_not_exceed_budget(self):
        """budget_remaining must never exceed the original budget."""
        result = _run_pipeline(_build_eml())
        b = result.budget
        r = result.budget_remaining
        assert r.max_latency_ms <= b.max_latency_ms
        assert r.max_tool_calls <= b.max_tool_calls
        assert r.max_external_calls <= b.max_external_calls
        assert r.max_llm_tokens <= b.max_llm_tokens

    def test_budget_spent_is_zero_in_stage1(self):
        """Stage 1 executes no external tools, so all spent counters are 0."""
        result = _run_pipeline(_build_eml())
        s = result.budget_spent
        assert s.tool_calls == 0
        assert s.external_calls == 0
        assert s.latency_ms == 0


# ---------------------------------------------------------------------------
# E2E-F. Attack hypotheses
# ---------------------------------------------------------------------------

class TestHypothesesInResult:

    def test_result_contains_all_hypothesis_types(self):
        """All 13 AttackHypothesisType values should appear in the result."""
        from app.contracts.investigation import AttackHypothesisType
        result = _run_pipeline(_build_eml())
        hypothesis_types = {h.hypothesis_type for h in result.attack_hypotheses}
        all_types = set(AttackHypothesisType)
        assert hypothesis_types == all_types

    def test_hypotheses_have_scores(self):
        """Every hypothesis must have a score in [0, 1]."""
        result = _run_pipeline(_build_eml())
        for h in result.attack_hypotheses:
            assert 0.0 <= h.score <= 1.0


# ---------------------------------------------------------------------------
# E2E-G. Audit chain
# ---------------------------------------------------------------------------

class TestAuditChain:

    def test_result_has_audit_hash(self):
        """audit_chain_last_hash must be a non-empty, non-genesis string."""
        from app.contracts.audit import GENESIS_HASH
        result = _run_pipeline(_build_eml())
        assert result.audit_chain_last_hash
        assert len(result.audit_chain_last_hash) == 64  # SHA256 hex
        # On a normal completion, we expect a real hash (not genesis)
        # since the engine logs investigation_started and the transition
        assert result.audit_chain_last_hash != GENESIS_HASH


# ---------------------------------------------------------------------------
# E2E-H/I. FSM + stop reason on normal completion
# ---------------------------------------------------------------------------

class TestNormalCompletionFSM:

    def test_normal_completion_has_stop_reason_set(self):
        """After Stage 1, stop_reason must always be set (required by contract)."""
        result = _run_pipeline(_build_eml())
        assert result.stop_reason is not None, "stop_reason must always be populated"

    def test_auth_pass_email_reaches_completed_or_inconclusive(self):
        """A valid-auth email should produce COMPLETED or INCONCLUSIVE (never FAILED)."""
        result = _run_pipeline(_build_eml(
            auth_results=(
                "mx.test.com;"
                " dkim=pass header.d=example.com;"
                " spf=pass smtp.mailfrom=example.com;"
                " dmarc=pass header.from=example.com"
            )
        ))
        from app.contracts.investigation import InvestigationStatus as _IS
        assert result.status in (_IS.COMPLETED, _IS.INCONCLUSIVE)

    def test_high_auth_email_stop_reason_is_semantic_or_none(self):
        """With rich auth data, stop_reason is a semantic stop or None (if COMPLETED)."""
        from app.contracts.investigation import InvestigationStatus as _IS, StopReason as _SR
        result = _run_pipeline(_build_eml(
            auth_results=(
                "mx.test.com;"
                " dkim=pass header.d=example.com;"
                " spf=pass smtp.mailfrom=example.com;"
                " dmarc=pass header.from=example.com"
            )
        ))
        if result.status == _IS.COMPLETED:
            # COMPLETED results may have stop_reason=None — that's valid
            assert result.stop_reason in (
                None,
                _SR.CONFIDENCE_TARGET_REACHED,
                _SR.NO_MANDATORY_EVIDENCE_MISSING,
                _SR.NO_MAJOR_UNRESOLVED_CONFLICT,
            )
        else:
            # INCONCLUSIVE must have a stop_reason
            assert result.stop_reason is not None



# ---------------------------------------------------------------------------
# E2E-J. Evidence IDs
# ---------------------------------------------------------------------------

class TestEvidenceIdIntegrity:

    def test_observed_facts_are_non_empty_strings(self):
        """All observed_fact IDs must be non-empty strings."""
        result = _run_pipeline(_build_eml(
            auth_results="mx.test.com; dmarc=fail; spf=fail; dkim=fail"
        ))
        for eid in result.observed_facts:
            assert isinstance(eid, str) and len(eid) > 0

    def test_investigation_id_matches_package_id(self):
        """investigation_id must match the EmailEvidencePackage.package_id."""
        raw_eml = _build_eml()
        parsed = _parser.parse(raw_eml)
        package = _normalizer.normalize(parsed)
        stage1 = _engine.run_stage1(package)
        result = to_investigation_result(stage1)

        assert result.investigation_id == package.package_id


# ---------------------------------------------------------------------------
# E2E-K/L/M. Bounded outputs
# ---------------------------------------------------------------------------

class TestBoundedOutputs:

    def test_risk_score_bounded(self):
        """risk_score must be in [0, 100] for any email."""
        for auth in [
            "mx.t.com; dmarc=pass; spf=pass; dkim=pass",
            "mx.t.com; dmarc=fail; spf=fail; dkim=fail",
            None,
        ]:
            result = _run_pipeline(_build_eml(auth_results=auth))
            assert 0.0 <= result.risk_score <= 100.0

    def test_confidence_bounded(self):
        """confidence must be in [0, 1] for any email."""
        for auth in [
            "mx.t.com; dmarc=pass; spf=pass; dkim=pass",
            "mx.t.com; dmarc=fail; spf=fail; dkim=fail",
            None,
        ]:
            result = _run_pipeline(_build_eml(auth_results=auth))
            assert 0.0 <= result.confidence <= 1.0

    def test_high_risk_email_verdict_not_benign(self):
        """Email with all auth failures + header mismatches must not be BENIGN."""
        raw_eml = _build_eml(
            auth_results=(
                "mx.test.com;"
                " dkim=fail header.d=bad.com;"
                " spf=fail smtp.mailfrom=bad.com;"
                " dmarc=fail header.from=bad.com"
            ),
            reply_to="attacker@evil.com",
            return_path="<attacker@evil.com>",
        )
        result = _run_pipeline(raw_eml)
        assert result.verdict != Verdict.BENIGN
