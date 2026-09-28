"""
services/reasoning/snapshot_builder.py

Pure, deterministic, local snapshot builder.

Converts InvestigationState + evidence store into a
ReasoningEvidenceSnapshot using an ALLOWLIST pattern.

SECURITY PRINCIPLE:
    Build "only explicitly permitted typed fields"
    NOT  "all investigation data except dangerous fields"

This function:
    - is deterministic
    - is local (no network calls)
    - does NOT call Groq or any external provider
    - does NOT mutate InvestigationState
    - does NOT persist anything
    - can NEVER accidentally include raw .eml bytes
"""

from __future__ import annotations

import logging
from typing import Optional

from app.contracts.evidence import EvidenceItem, EvidenceType
from app.contracts.investigation import InvestigationState

from app.contracts.reasoning import (
    BudgetStatus,
    ReasoningEvidenceSnapshot,
    ReasoningFinding,
    ReasoningHypothesis,
    UntrustedContentItem,
)

logger = logging.getLogger(__name__)

# Categories whose value field may contain email-derived free text
# These are isolated into the untrusted_content list instead of key_findings
_UNTRUSTED_CATEGORIES = {"CONTENT"}

# Keys that are safe to include as findings even from CONTENT category
_SAFE_CONTENT_KEYS = frozenset({
    "language",
    "language_confidence",
    "word_count",
    "has_html",
    "link_count",
    "attachment_count",
})


def _evidence_to_finding(item: EvidenceItem) -> Optional[ReasoningFinding]:
    """Convert an EvidenceItem to a typed ReasoningFinding.

    Returns None if the item should be excluded from findings
    (e.g. content-category items with free-text values).
    """
    # Skip content-category items unless they have safe machine-readable keys
    if item.category.value in _UNTRUSTED_CATEGORIES:
        if item.key not in _SAFE_CONTENT_KEYS:
            return None

    return ReasoningFinding(
        evidence_id=item.evidence_id,
        type=item.type.value,
        category=item.category.value,
        key=item.key,
        value=item.value,
        source=item.source,
        confidence=item.confidence,
    )


def _evidence_to_untrusted(item: EvidenceItem) -> Optional[UntrustedContentItem]:
    """Extract untrusted content items from content-category evidence.

    Only creates untrusted items for evidence that contains email-derived
    free-form text (subject lines, body snippets, display names).
    """
    if item.category.value not in _UNTRUSTED_CATEGORIES:
        return None
    if item.key in _SAFE_CONTENT_KEYS:
        return None

    text_value = str(item.value) if item.value is not None else ""
    if not text_value.strip():
        return None

    # Bound the text to prevent oversized snapshots
    bounded_text = text_value[:2000]

    return UntrustedContentItem(
        evidence_id=item.evidence_id,
        content_type=item.key,
        text=bounded_text,
    )


def _compute_budget_status(state: InvestigationState) -> BudgetStatus:
    """Compute coarse budget status — never expose exact remaining counts."""
    remaining = state.budget_remaining
    budget = state.budget

    if budget.max_tool_calls == 0:
        return BudgetStatus.EXHAUSTED

    tool_ratio = remaining.max_tool_calls / max(budget.max_tool_calls, 1)
    ext_ratio = remaining.max_external_calls / max(budget.max_external_calls, 1)

    if tool_ratio <= 0 or ext_ratio <= 0:
        return BudgetStatus.EXHAUSTED
    if tool_ratio < 0.25 or ext_ratio < 0.25:
        return BudgetStatus.LOW
    return BudgetStatus.AVAILABLE


def build_reasoning_snapshot(
    state: InvestigationState,
    evidence_store: dict[str, EvidenceItem],
) -> ReasoningEvidenceSnapshot:
    """Build a sanitized, allowlist-based snapshot for the reasoning model.

    Args:
        state: The current InvestigationState (read-only).
        evidence_store: Map of evidence_id → EvidenceItem.

    Returns:
        ReasoningEvidenceSnapshot with only approved, typed fields.
    """
    # Collect all evidence IDs from state
    all_evidence_ids = (
        state.observed_facts
        + state.heuristic_findings
        + state.ml_signals
        + state.threat_intelligence
        + state.historical_matches
    )

    # Build typed findings (allowlist)
    key_findings: list[ReasoningFinding] = []
    untrusted_items: list[UntrustedContentItem] = []
    supporting_ids: list[str] = []
    contradicting_ids: list[str] = []

    for eid in all_evidence_ids:
        item = evidence_store.get(eid)
        if item is None:
            continue

        # Try as a typed finding
        finding = _evidence_to_finding(item)
        if finding is not None:
            key_findings.append(finding)
        else:
            # Check if it should be an untrusted content item
            untrusted = _evidence_to_untrusted(item)
            if untrusted is not None:
                untrusted_items.append(untrusted)

    # Build hypotheses
    hypotheses: list[ReasoningHypothesis] = []
    for h in state.attack_hypotheses:
        hypotheses.append(
            ReasoningHypothesis(
                hypothesis_type=h.hypothesis_type.value,
                score=h.score,
                status=h.status.value,
                reasons=h.reasons[:10],
                supporting_evidence_ids=h.supporting_evidence_ids[:50],
                contradicting_evidence_ids=h.contradicting_evidence_ids[:50],
            )
        )
        supporting_ids.extend(h.supporting_evidence_ids)
        contradicting_ids.extend(h.contradicting_evidence_ids)

    # Build bounded historical context
    historical_context: str | None = None
    if state.historical_matches:
        count = len(state.historical_matches)
        historical_context = (
            f"{count} historical case match(es) found. "
            f"Evidence IDs: {', '.join(state.historical_matches[:5])}"
        )
        if len(historical_context) > 500:
            historical_context = historical_context[:497] + "..."

    # Deduplicate support/contradict lists
    supporting_ids = list(dict.fromkeys(supporting_ids))[:50]
    contradicting_ids = list(dict.fromkeys(contradicting_ids))[:50]

    return ReasoningEvidenceSnapshot(
        case_id=state.case_id,
        investigation_id=state.case_id,
        investigation_level=state.investigation_level.value,
        current_risk=state.current_risk,
        current_confidence=state.current_confidence,
        key_findings=key_findings[:100],
        current_hypotheses=hypotheses[:15],
        missing_evidence=state.missing_evidence[:30],
        completed_tools=state.tools_used[:30],
        failed_tools=state.tools_failed[:30],
        budget_status=_compute_budget_status(state),
        supporting_evidence=supporting_ids,
        contradictory_evidence=contradicting_ids,
        historical_context=historical_context,
        untrusted_content=untrusted_items[:10],
    )
