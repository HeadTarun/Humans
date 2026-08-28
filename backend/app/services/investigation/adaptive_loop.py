"""
services/investigation/adaptive_loop.py

Adaptive Investigation Loop (Stage 4).
"""

from __future__ import annotations

import logging
import asyncio
from typing import Any, Optional

from app.contracts.investigation import InvestigationState, StopReason
from app.contracts.policy import InvestigationProfile
from app.contracts.tool import ToolExecutionRequest, ToolExecutionStatus
from app.services.evidence.models import EmailEvidencePackage
from app.services.investigation.budget import calculate_budget_remaining, record_tool_cost
from app.services.investigation.case_manager import generate_initial_hypotheses
from app.services.investigation.policy import select_profiles, get_candidate_tools
from app.services.investigation.tool_priority import rank_tools
from app.services.tools.executor import ToolExecutor
from app.services.tools.normaliser import EvidenceToolNormaliser
from app.services.investigation.tool_registry import get_tool
from app.services.risk.engine import RiskEngine

logger = logging.getLogger(__name__)

async def _map_inputs_for_tool(tool_name: str, state: InvestigationState, package: EmailEvidencePackage) -> list[dict[str, Any]]:
    """
    Very simplified IOC mapping for the MVP.
    Returns a list of inputs. For each input, we execute the tool.
    """
    inputs = []
    
    if tool_name == "url_canonicalizer" or tool_name == "attachment_hasher":
        # Uses the package directly
        return [{}]
        
    if tool_name in ["virustotal_lookup", "urlhaus_feed_lookup"]:
        # Find URLs
        for url_item in package.urls:
            inputs.append({"indicator": url_item.raw_url, "url": url_item.raw_url, "canonical_url": url_item.raw_url, "indicator_type": "URL"})
            
    if tool_name == "url_ml":
        # Only unique canonical URLs
        unique_urls = set()
        from app.services.tools.handlers.url_canonicalizer import _canonicalize_url
        for url_item in package.urls:
            c_url = _canonicalize_url(url_item.raw_url)
            if c_url not in unique_urls:
                unique_urls.add(c_url)
                inputs.append({"canonical_url": c_url})

    if tool_name == "nlp_intent_ml":
        # Provide text for the adapter. We pull it from the artifact reference if needed, 
        # but the adapter doesn't need to re-parse. We can pass the raw_artifact_reference
        # so the handler can read the text, OR just pass a flag and the handler reads it.
        # Actually, let's just pass empty dict and the handler will use the package.
        inputs.append({"artifact_reference": package.raw_artifact_reference})
            
    if tool_name in ["ip_classifier", "abuseipdb_lookup", "geoip_lookup"]:
        # Find IPs (from headers for now)
        for hop in package.headers.received_hops:
            if hop.sender_ip:
                inputs.append({"ip_address": hop.sender_ip})
                
    if tool_name in ["dns_resolver", "rdap_domain_lookup"]:
        for url_item in package.urls:
            import tldextract
            ext = tldextract.extract(url_item.raw_url)
            domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
            if domain:
                inputs.append({"domain": domain})
                
    if tool_name == "sender_history":
        inputs.append({"email_address": package.headers.sender})
        
    if tool_name == "historical_correlation":
        inputs.append({})
        
    # Deduplicate inputs for safety
    unique_inputs = []
    seen = set()
    for inp in inputs:
        # Convert dict to frozen tuple for hashing
        key = frozenset(inp.items())
        if key not in seen:
            seen.add(key)
            unique_inputs.append(inp)
            
    return unique_inputs

async def run_adaptive_loop(
    state: InvestigationState, 
    package: EmailEvidencePackage,
    audit: Any
) -> InvestigationState:
    """
    The True Adaptive Loop:
    1. Hypotheses/Profiles -> 2. Rank -> 3. Select 1 Tool -> 4. Execute -> 5. Risk -> 6. Repeat
    """
    executor = ToolExecutor()
    normaliser = EvidenceToolNormaliser()
    risk_engine = RiskEngine()
    
    MAX_ITERATIONS = 15
    iteration = 0
    
    # 1. Pre-process (canonicalize URLs and hashes if they exist)
    # This avoids doing it repeatedly in the loop.
    for pre_tool in ["url_canonicalizer", "attachment_hasher"]:
        req = ToolExecutionRequest(
            case_id=state.case_id,
            tool_name=pre_tool,
            input={},
            reason="Pre-processing",
            policy_version="1.0"
        )
        res = await executor.execute(req, state, package=package)
        state.tools_used.append(pre_tool)
    
    while iteration < MAX_ITERATIONS:
        iteration += 1
        
        # --- 1. Re-evaluate Hypotheses & Policy ---
        hypotheses = generate_initial_hypotheses(state, package)
        state = state.model_copy(update={"attack_hypotheses": hypotheses})
        
        active_profiles = select_profiles(hypotheses)
        candidate_tools = get_candidate_tools(active_profiles, state.tools_used, state.tools_blocked)
        
        # --- 2. Rank Eligible Tools ---
        ranked_tools = rank_tools(candidate_tools, state, active_profiles)
        
        if not ranked_tools:
            logger.info("No worthwhile tools remaining.")
            break
            
        # --- 3. Select Top Tool ---
        top_tool_score = ranked_tools[0]
        tool_def = get_tool(top_tool_score.tool_name)
        
        # --- 4. Budget Check ---
        remaining = calculate_budget_remaining(state.budget)
        if tool_def.cost > remaining.max_tool_calls: # Simplify budget check for MVP
            logger.info(f"Budget exhausted for {tool_def.name}.")
            # Mark as blocked so we don't keep trying it
            state.tools_blocked.append(tool_def.name)
            continue
            
        # --- 5. Generate Inputs ---
        inputs = await _map_inputs_for_tool(tool_def.name, state, package)
        if not inputs:
            logger.info(f"No valid inputs found for {tool_def.name}, skipping.")
            state.tools_blocked.append(tool_def.name)
            continue
            
        # --- 6. Execute (Controlled Parallel for multiple inputs of the same tool) ---
        tasks = []
        for inp in inputs:
            req = ToolExecutionRequest(
                case_id=state.case_id,
                tool_name=tool_def.name,
                input=inp,
                reason=top_tool_score.reason,
                policy_version="1.0"
            )
            tasks.append(executor.execute(req, state, package=package))
            
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # --- 7. Normalize & Update State ---
        state.tools_used.append(tool_def.name)
        # Deduct cost once per execution batch for simplicity
        is_ext = getattr(tool_def, "external_api", False)
        state = state.model_copy(update={
            "tool_cost_spent": record_tool_cost(state.tool_cost_spent, latency_ms=tool_def.estimated_latency_ms, is_external=is_ext)
        })
        
        new_evidence = []
        for res in results:
            if isinstance(res, ToolExecutionResult) and res.status == ToolExecutionStatus.SUCCESS and res.output:
                try:
                    if isinstance(res.output, list):
                        from app.contracts.evidence import EvidenceItem
                        for item in res.output:
                            if isinstance(item, dict):
                                new_evidence.append(EvidenceItem(**item))
                            elif isinstance(item, EvidenceItem):
                                new_evidence.append(item)
                    else:
                        from app.contracts.provider_result import ProviderResult
                        pr = ProviderResult(**res.output)
                        items = normaliser.from_provider_result(
                            case_id=state.case_id,
                            result=pr,
                            module_path=tool_def.handler_ref
                        )
                        new_evidence.extend(items)
                except Exception as e:
                    logger.error(f"Normalization failed for {tool_def.name}: {e}")
                    
        # Add evidence to state (if we had a real store, we'd use it. For now, we simulate).
        # We need a way to pass this to the Risk Engine. Since Stage 1 stores L0 facts externally,
        # we can attach them to state or return them.
        if not hasattr(state, "accumulated_evidence"):
            state.accumulated_evidence = []
        state.accumulated_evidence.extend(new_evidence)
        
        # --- 8. Re-evaluate Risk ---
        # Evaluate risk based on ALL evidence so far
        risk_result = risk_engine.assess(state, state.accumulated_evidence)
        state = state.model_copy(update={
            "current_risk": risk_result.risk_assessment.risk_score,
            "current_confidence": risk_result.confidence_assessment.confidence_score
        })
        
        # --- 9. Check Stop Conditions ---
        from app.services.investigation.stop_conditions import should_stop
        stop_decision = should_stop(state)
        if stop_decision.should_stop:
            logger.info(f"Stopping investigation: {stop_decision.stop_reason}")
            break
            
    return state
