"""
services/investigation/case_manager.py

Initializes InvestigationState from an EmailEvidencePackage and generates
the first set of deterministic hypotheses (Level 0 scoring).

HARD RULES:
    - Do NOT parse raw email content here.
    - Do NOT call the email parser.
    - Consume EmailEvidencePackage as-is (it is already validated).
    - Every EvidenceItem created here gets a proper Provenance.
    - Invalid evidence raises ValidationError — never silently coerces.
    - No LLM. No external calls. No random numbers.
    - hypothesis_rules.py is the single source of truth for scoring rules.

HYPOTHESIS SCORING:
    Scores are additive and capped at 1.0.
    Status is derived from score thresholds:
        >= 0.60 → SUPPORTED
        >= 0.30 → UNCERTAIN
        >= 0.15 → WEAK
        <  0.15 → REJECTED  (though these won't be selected by profiles)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from app.contracts.common import CaseId, EvidenceId, Provenance, SourceType, utcnow
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
    InvestigationLevel,
    InvestigationState,
    StateMachineStatus,
    ToolCostSpent,
)
from app.services.evidence import EmailEvidencePackage
from app.services.investigation.budget import (
    DEFAULT_BUDGET,
    make_full_budget_remaining,
)
from app.services.investigation.hypothesis_rules import HYPOTHESIS_RULES, HypothesisRule

_MODULE = "services.investigation.case_manager"

# ---------------------------------------------------------------------------
# Hypothesis status thresholds (engineering-set; single source of truth)
# ---------------------------------------------------------------------------

_THRESHOLD_SUPPORTED = 0.60
_THRESHOLD_UNCERTAIN = 0.30
_THRESHOLD_WEAK = 0.15  # == RELEVANCE_FLOOR


def _score_to_status(score: float) -> HypothesisStatus:
    if score >= _THRESHOLD_SUPPORTED:
        return HypothesisStatus.SUPPORTED
    if score >= _THRESHOLD_UNCERTAIN:
        return HypothesisStatus.UNCERTAIN
    if score >= _THRESHOLD_WEAK:
        return HypothesisStatus.WEAK
    return HypothesisStatus.REJECTED


# ---------------------------------------------------------------------------
# Evidence attribute resolver
# ---------------------------------------------------------------------------

def _resolve_evidence_path(package: EmailEvidencePackage, path: str) -> list[Any]:
    """
    Resolve a dot-separated attribute path on EmailEvidencePackage.

    Returns a list of values (to handle list-typed attributes uniformly).

    Examples:
        "authentication.dmarc"            → [AuthResultValue("fail")]
        "headers.has_reply_to_mismatch"   → [True]
        "attachments"                     → [<AttachmentEvidence>, ...]
        "attachments.is_executable_signature" → [True, False, ...]  (per element)
        "urls.scheme"                     → ["https", "http", ...]
        "urls"                            → [<URLIndicator>, ...]
    """
    parts = path.split(".")
    current: Any = package

    for i, part in enumerate(parts):
        if current is None:
            return []

        if isinstance(current, list):
            # Already in list context: collect attribute from each element
            results = []
            for item in current:
                val = getattr(item, part, None)
                if val is not None:
                    results.append(val)
            current = results
        else:
            current = getattr(current, part, None)

    if current is None:
        return []
    if isinstance(current, list):
        return current
    return [current]


def _rule_matches(package: EmailEvidencePackage, rule: HypothesisRule) -> bool:
    """
    Evaluate whether a hypothesis rule fires against the evidence package.

    Rule match semantics:
        match_value=None  → rule fires if the path resolves to any truthy value
        match_value=<v>   → rule fires if any resolved value equals <v>
    """
    values = _resolve_evidence_path(package, rule.evidence_path)

    if not values:
        return False

    if rule.match_value is None:
        # Truthy check: list of items (non-empty), or a True bool
        return bool(values)

    # Exact-match: check string representations for enum compatibility
    for val in values:
        # Handle both enum values (which have .value) and plain strings/bools
        val_str = val.value if hasattr(val, "value") else val
        match_str = rule.match_value.value if hasattr(rule.match_value, "value") else rule.match_value
        if val_str == match_str or val == rule.match_value:
            return True

    return False


# ---------------------------------------------------------------------------
# EvidenceItem factory for L0 observed facts
# ---------------------------------------------------------------------------

def _make_fact_evidence(
    case_id: CaseId,
    key: str,
    value: Any,
    category: EvidenceCategory,
    source_field: str,
    related_entity: Optional[str] = None,
) -> EvidenceItem:
    """Create a typed FACT EvidenceItem from an L0 deterministic observation."""
    return EvidenceItem(
        evidence_id=str(uuid.uuid4()),
        case_id=case_id,
        type=EvidenceType.FACT,
        category=category,
        key=key,
        value=value,
        source="services.investigation.case_manager",
        source_type=SourceType.DETERMINISTIC,
        confidence=1.0,
        trust_level=TrustLevel.REPORTED,  # reported by mail server, not independently verified
        provenance=Provenance(
            producer_module=_MODULE,
            source_artifact=None,
            extraction_method="evidence_package_consumption",
            created_at=utcnow(),
        ),
        related_entity=related_entity,
        status=EvidenceStatus.ACTIVE,
    )


# ---------------------------------------------------------------------------
# L0 fact extraction from EmailEvidencePackage
# ---------------------------------------------------------------------------

def _extract_l0_facts(
    case_id: CaseId,
    package: EmailEvidencePackage,
) -> list[EvidenceItem]:
    """
    Convert key deterministic fields of EmailEvidencePackage into typed
    EvidenceItems. Only creates facts that are directly observable from
    the evidence package without ML or external lookup.

    Returns a list of EvidenceItem instances (not yet stored; IDs only
    will be stored in InvestigationState.observed_facts).
    """
    facts: list[EvidenceItem] = []


    # Authentication results — iterate over the results list (SingleAuthResult objects)
    for auth_result in package.authentication.results:
        protocol_name = auth_result.protocol.value if hasattr(auth_result.protocol, "value") else str(auth_result.protocol)
        result_val = auth_result.result.value if hasattr(auth_result.result, "value") else str(auth_result.result)
        facts.append(_make_fact_evidence(
            case_id=case_id,
            key=f"auth_{protocol_name}_result",
            value=result_val,
            category=EvidenceCategory.AUTHENTICATION,
            source_field=f"Authentication-Results:{protocol_name}",
        ))

    # Header structural observations
    headers = package.headers
    if headers.has_reply_to_mismatch:
        facts.append(_make_fact_evidence(
            case_id=case_id,
            key="reply_to_domain_mismatch",
            value=True,
            category=EvidenceCategory.HEADER,
            source_field="From + Reply-To headers",
        ))
    if headers.has_return_path_mismatch:
        facts.append(_make_fact_evidence(
            case_id=case_id,
            key="return_path_domain_mismatch",
            value=True,
            category=EvidenceCategory.HEADER,
            source_field="From + Return-Path headers",
        ))
    if headers.received_hop_count > 0:
        facts.append(_make_fact_evidence(
            case_id=case_id,
            key="received_hop_count",
            value=headers.received_hop_count,
            category=EvidenceCategory.RELAY,
            source_field="Received headers",
        ))

    # Attachment indicators
    for att in package.attachments:
        if att.is_executable_signature:
            facts.append(_make_fact_evidence(
                case_id=case_id,
                key="attachment_executable_signature",
                value=True,
                category=EvidenceCategory.ATTACHMENT,
                source_field="MIME attachment",
                related_entity=att.sha256_hash,
            ))
        if att.is_archive:
            facts.append(_make_fact_evidence(
                case_id=case_id,
                key="attachment_is_archive",
                value=True,
                category=EvidenceCategory.ATTACHMENT,
                source_field="MIME attachment",
                related_entity=att.sha256_hash,
            ))

    # URL indicators (presence only; scheme check for http)
    for url_ind in package.urls:
        scheme = url_ind.scheme
        if scheme == "http":
            facts.append(_make_fact_evidence(
                case_id=case_id,
                key="url_http_scheme",
                value="http",
                category=EvidenceCategory.URL,
                source_field="URL extracted from body/html",
                related_entity=url_ind.raw_url,
            ))

    return facts


# ---------------------------------------------------------------------------
# Hypothesis generation
# ---------------------------------------------------------------------------
def generate_initial_hypotheses(
    state: InvestigationState,
    package: EmailEvidencePackage,
    accumulated_evidence: list[EvidenceItem] = None,
) -> list[AttackHypothesis]:
    if accumulated_evidence is None:
        accumulated_evidence = []
        
    scores: dict[AttackHypothesisType, float] = {h: 0.0 for h in AttackHypothesisType}
    reasons: dict[AttackHypothesisType, list[str]] = {h: [] for h in AttackHypothesisType}
    triggered: dict[AttackHypothesisType, bool] = {h: False for h in AttackHypothesisType}

    for rule in HYPOTHESIS_RULES:
        if not _rule_matches(package, rule):
            continue
        try:
            h_type = AttackHypothesisType(rule.target_hypothesis)
        except ValueError:
            continue
        scores[h_type] = min(1.0, scores[h_type] + rule.score_delta)
        reasons[h_type].append(f"[{rule.rule_id}] {rule.reason}")
        if getattr(rule, "triggers_investigation", False):
            triggered[h_type] = True

    # Dynamic Profile Expansion logic (Stage 7)
    for ev in accumulated_evidence:
        # Example: URL ML suspicious -> Boost Credential Phishing & Malware Delivery
        if ev.key in ["url_ml_suspicious", "url_ml_phishing"] and float(ev.value) > 0.5:
            scores[AttackHypothesisType.CREDENTIAL_PHISHING] = min(1.0, scores[AttackHypothesisType.CREDENTIAL_PHISHING] + 0.3)
            reasons[AttackHypothesisType.CREDENTIAL_PHISHING].append("[dyn_url_ml] Suspicious URL found")
        # Example: Historical exact match -> Boost Campaign
        if ev.key == "historical_exact_match":
            scores[AttackHypothesisType.CAMPAIGN] = min(1.0, scores[AttackHypothesisType.CAMPAIGN] + 0.45)
            reasons[AttackHypothesisType.CAMPAIGN].append("[dyn_historical] Historical IOC correlation found")

    hypotheses: list[AttackHypothesis] = []
    for h_type, score in scores.items():
        hypotheses.append(
            AttackHypothesis(
                hypothesis_id=str(uuid.uuid4()),
                case_id=state.case_id,
                hypothesis_type=h_type,
                score=score,
                confidence=0.0,
                status=_score_to_status(score),
                reasons=reasons[h_type],
                investigation_triggered=triggered[h_type],
            )
        )

    return hypotheses


# ---------------------------------------------------------------------------
# State initialization
# ---------------------------------------------------------------------------

def init_state(package: EmailEvidencePackage, original_case_id: Optional[str] = None) -> tuple[InvestigationState, list[EvidenceItem]]:
    """
    Create the initial InvestigationState from a validated EmailEvidencePackage.

    This is the ONLY entry point for creating a new InvestigationState.
    It must never be called more than once per case (idempotency enforcement
    is the responsibility of the caller / case manager API layer).

    Flow:
        1. Generate case_id (reuse package.package_id for traceability).
        2. Extract L0 observed facts from the evidence package.
        3. Initialize budgets.
        4. Build the base INITIALIZED state.
        5. Return state (caller will transition to LEVEL_0 via state_machine).
    """
    # Use the package's own ID as the case_id for perfect traceability
    case_id: CaseId = package.package_id

    # Extract L0 facts from the evidence package
    l0_facts = _extract_l0_facts(case_id, package)
    fact_ids: list[EvidenceId] = [f.evidence_id for f in l0_facts]

    # Determine available tools from the tool registry (enabled tools only)
    from app.services.investigation.tool_registry import get_enabled_tools
    available_tools = list(get_enabled_tools().keys())

    budget = DEFAULT_BUDGET

    state = InvestigationState(
        case_id=case_id,
        original_case_id=original_case_id,
        created_at=utcnow(),
        attack_hypotheses=[],  # Populated after init via generate_initial_hypotheses
        observed_facts=fact_ids,
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
        tools_available=available_tools,
        tools_blocked=[],
        tool_cost_spent=ToolCostSpent(),
        budget=budget,
        budget_remaining=make_full_budget_remaining(budget),
        investigation_level=InvestigationLevel.L0_TRIAGE,
        iteration_count=0,
        max_iterations=12,
        sm_status=StateMachineStatus.INITIALIZED,
        stop_reason=None,
        escalation_reason=None,
        escalation_status=EscalationStatus.NONE,
    )

    return state, l0_facts
