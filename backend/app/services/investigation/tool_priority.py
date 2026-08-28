"""
services/investigation/tool_priority.py

Deterministic tool ranking and selection for the adaptive loop.
"""

from __future__ import annotations

from typing import Iterable, Optional
from app.contracts.investigation import InvestigationState, AttackHypothesis
from app.contracts.policy import InvestigationProfile, ToolEligibility
from app.contracts.tool import ToolDefinition, ToolPriorityScore
from app.services.investigation.tool_registry import get_tool

def calculate_priority(
    tool_def: ToolDefinition,
    hypotheses: list[AttackHypothesis],
    profiles: list[InvestigationProfile]
) -> ToolPriorityScore:
    """
    Calculate priority score for a single tool based on current hypotheses.
    
    ToolPriority = EIG * Reliability * Availability / Cost
    """
    relevance = 0.0
    
    # Find max relevance from profiles that include this tool
    for profile in profiles:
        if tool_def.name in profile.mandatory_tools or tool_def.name in profile.optional_tools or tool_def.name in profile.expensive_tools:
            # Find matching hypothesis
            for hyp in hypotheses:
                if hyp.hypothesis_type == profile.hypothesis_type:
                    relevance = max(relevance, hyp.score)
                    
    eig = relevance
    
    w_latency = 0.4
    w_api = 0.4
    w_resource = 0.2
    
    normalized_latency = min(tool_def.estimated_latency_ms / 2000.0, 1.0)
    normalized_api = min(tool_def.estimated_api_cost / 0.05, 1.0) if tool_def.external_api else 0.0
    normalized_resource = tool_def.cost / 1.0
    
    calculated_cost = (w_latency * normalized_latency) + (w_api * normalized_api) + (w_resource * normalized_resource)
    calculated_cost = max(calculated_cost, 0.01)
    
    priority = (eig * tool_def.reliability * tool_def.availability_score) / calculated_cost
    if relevance < 0.15:
        priority = 0.0
    
    return ToolPriorityScore(
        tool_name=tool_def.name,
        relevance=relevance,
        eligibility=tool_def.tier,
        eig=eig,
        reliability=tool_def.reliability,
        cost=calculated_cost,
        cost_breakdown={
            "latency": normalized_latency,
            "api": normalized_api,
            "resource": normalized_resource
        },
        priority=priority,
        reason=f"Calculated priority {priority:.2f} based on relevance {relevance:.2f}"
    )

def rank_tools(
    candidate_tools: Iterable[str],
    state: InvestigationState,
    active_profiles: list[InvestigationProfile]
) -> list[ToolPriorityScore]:
    scored = []
    for t_name in candidate_tools:
        try:
            tool_def = get_tool(t_name)
        except KeyError:
            continue
            
        if not tool_def.enabled:
            continue
            
        score = calculate_priority(tool_def, state.attack_hypotheses, active_profiles)
        if score.priority > 0.0:
            scored.append(score)
            
    scored.sort(key=lambda s: s.priority, reverse=True)
    return scored
