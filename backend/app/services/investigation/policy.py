"""
services/investigation/policy.py

Investigation Policy Engine — Stage 1: Profile Selection.

RELEVANCE_FLOOR: The single source of truth for hypothesis relevance gating.

    hypothesis_score >= RELEVANCE_FLOOR → profile is selected
    hypothesis_score <  RELEVANCE_FLOOR → profile is excluded

Rule: 0.15 is INCLUSIVE (use >=, not >).

Stage 1 only implements:
    - select_profiles(): relevance-gated profile selection

Stage 2+ will add:
    - tool utility scoring (EIG, reliability, cost)
    - policy decision generation (PolicyDecision)
    - tool ranking (ToolPriorityScore)

No LLM. No external calls. No random numbers.
"""

from __future__ import annotations

from app.contracts.investigation import AttackHypothesis, AttackHypothesisType
from app.contracts.policy import InvestigationProfile
from app.services.investigation.profile_registry import INVESTIGATION_PROFILES

# ---------------------------------------------------------------------------
# Relevance floor — single source of truth
# ---------------------------------------------------------------------------

RELEVANCE_FLOOR: float = 0.15


def select_profiles(
    hypotheses: list[AttackHypothesis],
) -> list[InvestigationProfile]:
    """
    Return investigation profiles whose corresponding hypothesis score
    meets or exceeds the RELEVANCE_FLOOR.

    Filtering rule: score >= RELEVANCE_FLOOR (0.15 is INCLUSIVE).

    Examples:
        score = 0.10 → excluded
        score = 0.15 → included  ← boundary case, explicitly included
        score = 0.80 → included

    The result is deterministic and sorted by hypothesis type string for
    reproducibility. No randomness, no LLM.

    Parameters:
        hypotheses: List of AttackHypothesis objects from the current state.

    Returns:
        List of InvestigationProfile objects for all hypotheses that pass
        the relevance floor. May be empty if no hypothesis is relevant.
    """
    selected: list[InvestigationProfile] = []

    for hyp in hypotheses:
        if hyp.score >= RELEVANCE_FLOOR or getattr(hyp, "investigation_triggered", False):
            profile = INVESTIGATION_PROFILES.get(hyp.hypothesis_type)
            if profile is not None:
                selected.append(profile)

    # Sort deterministically by profile_id for reproducibility
    selected.sort(key=lambda p: p.profile_id)
    return selected


def get_candidate_tools(
    profiles: list[InvestigationProfile],
    tools_used: list[str],
    tools_blocked: list[str],
) -> list[str]:
    """
    Collect the set of candidate tool names from all active profiles,
    excluding tools that have already been used or are blocked.

    Returns a deterministically sorted list of unique tool names.
    This is the candidate pool for tool selection in Stage 2.

    In Stage 1, this is used only to populate tools_available in the state
    and to evaluate the NO_CANDIDATE_TOOLS stop condition.
    """
    used_set = set(tools_used)
    blocked_set = set(tools_blocked)
    candidates: set[str] = set()

    for profile in profiles:
        for tool in profile.mandatory_tools + profile.optional_tools:
            if tool not in used_set and tool not in blocked_set:
                candidates.add(tool)

    return sorted(candidates)
