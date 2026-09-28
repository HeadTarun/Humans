"""
services/investigation/adaptive_loop.py

Single authoritative adaptive tool-execution loop for Stage 1.

The loop is the ONLY place where tools are actually executed during a
Stage 1 investigation. It is deterministic, budget-bounded and fully
audited:

    - Profile selection re-evaluated every iteration (relevance floor).
    - Candidate tools gated by level (min_level <= current level) and by
      the enabled flag in the Tool Registry.
    - Level advancement: when no candidates remain at the current level
      but enabled profile tools exist at a higher level, the FSM advances
      one level at a time (LEVEL_0 -> LEVEL_1 -> LEVEL_2 -> LEVEL_3).
    - Per-input slicing against the external-call budget.
    - Raw-output caching for external_api tools only (cache_ttl_seconds).
    - tools_used  = executions that produced at least one usable EvidenceItem.
    - tools_failed = executions that produced no usable evidence (never
      treated as silent success; surfaced in the audit trail and fed to the
      Risk Engine as a confidence penalty).
    - Stop conditions evaluated every iteration via stop_conditions.should_stop().

No LLM. No randomness. No `except Exception: pass`. All costs are recorded
through budget.record_tool_cost().
"""

from __future__ import annotations

import asyncio
from email.utils import parseaddr
import hashlib
import logging
import time
from typing import Any, Optional

from app.contracts.evidence import EvidenceItem, EvidenceType
from app.contracts.investigation import (
    InvestigationLevel,
    InvestigationState,
    StateMachineStatus,
    StopReason,
)
from app.contracts.policy import InvestigationProfile
from app.contracts.provider_result import ProviderResult
from app.contracts.tool import (
    ToolDefinition,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolExecutionStatus,
)
from app.services.ingestion.parser import classify_ip
from app.services.evidence import EmailEvidencePackage
from app.services.investigation.audit_logger import AuditLogger
from app.services.investigation.budget import calculate_budget_remaining, record_tool_cost
from app.services.investigation.case_manager import generate_initial_hypotheses
from app.services.investigation.policy import get_candidate_tools, select_profiles
from app.services.investigation.state_machine import InvalidTransitionError, transition
from app.services.investigation.stop_conditions import StopDecision, should_stop
from app.services.investigation.tool_priority import rank_tools
from app.services.investigation.tool_registry import get_tool
from app.services.risk.conflict_engine import ConflictEngine
from app.services.risk.engine import RiskEngine
from app.services.tools.executor import ToolExecutor
from app.services.tools.normaliser import EvidenceToolNormaliser

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Level ordering — explicit rank so enum string values never decide ordering
# ---------------------------------------------------------------------------

_LEVEL_RANK: dict[InvestigationLevel, int] = {
    InvestigationLevel.L0_TRIAGE: 0,
    InvestigationLevel.L1_TARGETED: 1,
    InvestigationLevel.L2_DEEP: 2,
    InvestigationLevel.L3_GROQ: 3,
}

_STATUS_FOR_LEVEL: dict[InvestigationLevel, StateMachineStatus] = {
    InvestigationLevel.L1_TARGETED: StateMachineStatus.LEVEL_1,
    InvestigationLevel.L2_DEEP: StateMachineStatus.LEVEL_2,
    InvestigationLevel.L3_GROQ: StateMachineStatus.LEVEL_3,
}

# ---------------------------------------------------------------------------
# Input mapping — deterministic, package-derived (NEVER from email text)
# ---------------------------------------------------------------------------


def _canonicalise_url(raw_url: str) -> str:
    """Canonicalise a URL to its deduplicated form (deterministic)."""
    try:
        from app.services.tools.handlers.url_canonicalizer import _canonicalize_url
        return _canonicalize_url(raw_url)
    except Exception as e:  # noqa: BLE001 - URL normalisation must never crash the loop
        logger.warning("url canonicalisation failed for %r: %s", raw_url, e)
        return raw_url


def _extract_domain(raw_url: str) -> str:
    try:
        import tldextract
        ext = tldextract.extract(raw_url)
        return f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    except Exception:  # noqa: BLE001
        return ""


def _extract_email_domain(address: str | None) -> str:
    """Return a normalized sender domain without treating local parts as IOCs."""
    _, parsed = parseaddr(address or "")
    if "@" not in parsed:
        return ""
    return parsed.rsplit("@", 1)[1].strip().lower().rstrip(".")


def _map_inputs_for_tool(
    tool_name: str,
    package: EmailEvidencePackage,
    accumulated_evidence: list[EvidenceItem],
) -> list[dict[str, Any]]:
    """Build deterministic tool inputs from the evidence package."""
    inputs: list[dict[str, Any]] = []

    if tool_name in ("url_ml",):
        seen: set[str] = set()
        for url_item in package.urls:
            canonical = _canonicalise_url(url_item.raw_url)
            if canonical not in seen:
                seen.add(canonical)
                inputs.append({"canonical_url": canonical})

    if tool_name in ("urlhaus_feed_lookup", "virustotal_lookup", "url_reputation"):
        seen = set()
        for url_item in package.urls:
            raw = url_item.raw_url
            canonical = _canonicalise_url(raw)
            if canonical not in seen:
                seen.add(canonical)
                inputs.append({
                    "indicator": raw,
                    "url": raw,
                    "canonical_url": canonical,
                    "indicator_type": "URL",
                })

    if tool_name in ("dns_resolver", "rdap_domain_lookup", "domain_intelligence"):
        seen = set()
        sender_domain = _extract_email_domain(
            getattr(package.sender, "email_address", None) if package.sender else None
        )
        if sender_domain:
            seen.add(sender_domain)
            inputs.append({"domain": sender_domain})
        for url_item in package.urls:
            domain = _extract_domain(url_item.raw_url)
            if domain and domain not in seen:
                seen.add(domain)
                inputs.append({"domain": domain})
        if not seen:
            for ev in accumulated_evidence:
                if ev.type == EvidenceType.URL and ev.related_entity:
                    domain = _extract_domain(ev.related_entity)
                    if domain and domain not in seen:
                        seen.add(domain)
                        inputs.append({"domain": domain})

    if tool_name in ("abuseipdb_lookup", "ip_intelligence", "ip_reputation", "geoip_lookup", "ip_geolocation"):
        seen = set()
        for hop in package.received_hops:
            ip = getattr(hop, "sending_ip", None) or getattr(hop, "sender_ip", None)
            # Only ever hand a public/routable claimed IP to an external
            # provider. Internal delivery-queue/relay addresses aren't real
            # geographic egress points and would waste external-call
            # budget on noise or leak internal addressing to a third party.
            if ip and ip not in seen and classify_ip(ip) == "public":
                seen.add(ip)
                inputs.append({"ip_address": ip})

    if tool_name in ("spf_dkim_dmarc", "header_parse", "relay_reconstruction", "deterministic_heuristics"):
        inputs.append({})

    if tool_name == "sender_history":
        if package.sender and getattr(package.sender, "email_address", None):
            inputs.append({"email_address": package.sender.email_address})

    if tool_name == "nlp_intent_ml":
        if package.raw_artifact_reference and package.body and (package.body.visible_text_length or package.body.plain_text_length or package.body.html_length):
            inputs.append({"artifact_reference": package.raw_artifact_reference})

    # Deterministic dedup: identical frozenset-of-items inputs collapse
    unique: list[dict[str, Any]] = []
    seen_keys: set[Any] = set()
    for inp in inputs:
        key = frozenset(inp.items())
        if key not in seen_keys:
            seen_keys.add(key)
            unique.append(inp)
    return unique


def _required_package_tools(
    package: EmailEvidencePackage,
    level: InvestigationLevel,
    attempted: set[str],
) -> list[str]:
    """Add policy-mandated analysis independent of a threat-profile score."""
    required: list[str] = []
    has_visible_body = bool(
        package.body and (package.body.visible_text_length or package.body.plain_text_length or package.body.html_length)
    )
    if level >= InvestigationLevel.L1_TARGETED and has_visible_body and "nlp_intent_ml" not in attempted:
        required.append("nlp_intent_ml")
    if level >= InvestigationLevel.L2_DEEP and package.received_hops and "ip_geolocation" not in attempted:
        required.append("ip_geolocation")
    return required


# ---------------------------------------------------------------------------
# Execution-result disambiguation
# ---------------------------------------------------------------------------


def _normalise_execution_result(
    res: Any,
    case_id: str,
    tool_def: ToolDefinition,
    normaliser: EvidenceToolNormaliser,
) -> tuple[list[EvidenceItem], Optional[str]]:
    """
    Convert one ToolExecutionResult into evidence items.

    Returns (evidence_items, error). A non-None error means the execution
    produced no usable evidence and must be counted as a tool failure.
    No silent evidence loss: unexpected output shapes surface as errors.
    """
    if isinstance(res, BaseException):
        return [], f"execution raised: {res}"

    if not isinstance(res, ToolExecutionResult):
        return [], f"unexpected result object: {type(res).__name__}"

    if res.status != ToolExecutionStatus.SUCCESS:
        return [], f"status={res.status.value} error={res.error}"

    if res.output is None:
        return [], "tool returned no output"

    # Handler convention: dict {"status": "failed", "error": ...} = failure
    if isinstance(res.output, dict):
        if res.output.get("status") == "failed" or (set(res.output.keys()) == {"error"}):
            return [], str(res.output.get("error") or "handler-reported failure")
        if not res.output:
            return [], "tool returned empty dictionary"

    items: list[EvidenceItem] = []
    try:
        if isinstance(res.output, list):
            for item in res.output:
                if isinstance(item, EvidenceItem):
                    items.append(item)
                elif isinstance(item, dict):
                    items.append(EvidenceItem(**item))
                else:
                    return [], f"unknown list element type: {type(item).__name__}"
        elif isinstance(res.output, dict):
            pr = ProviderResult(**res.output)
            items.extend(
                normaliser.from_provider_result(
                    case_id=case_id,
                    result=pr,
                    module_path=tool_def.handler_ref,
                )
            )
    except Exception as e:  # noqa: BLE001 - surfaced, never silent
        logger.warning("Failed to normalise output from %s: %s", tool_def.name, e)
        return [], f"normalisation failed: {e}"

    if not items:
        return [], "normalisation produced zero evidence items"
    return items, None


# ---------------------------------------------------------------------------
# The loop
# ---------------------------------------------------------------------------


async def run_adaptive_loop(
    initial_state: InvestigationState,
    package: EmailEvidencePackage,
    initial_evidence: list[EvidenceItem],
    audit: AuditLogger,
) -> tuple[InvestigationState, list[EvidenceItem], Optional[StopDecision]]:
    """
    Run the adaptive tool-execution loop until a stop condition fires or
    no candidate tools remain.

    Returns (final_state, all_evidence_items, stop_decision_if_fired).
    stop_decision is None when the loop simply ran out of candidates and no
    stop condition fired inside the loop (the caller then evaluates stop
    conditions once more on the final state).
    """
    executor = ToolExecutor()
    normaliser = EvidenceToolNormaliser()
    risk_engine = RiskEngine()
    conflict_engine = ConflictEngine()

    state = initial_state
    all_evidence: list[EvidenceItem] = list(initial_evidence)
    loop_started = time.perf_counter()

    while state.iteration_count < state.max_iterations:
        # 1. Re-evaluate hypotheses, profiles and candidates (level-gated)
        hypotheses = generate_initial_hypotheses(state, package, all_evidence)
        active_profiles = select_profiles(hypotheses)
        attempted = set(state.tools_used) | set(state.tools_failed) | set(state.tools_blocked)
        candidates = get_candidate_tools(
            profiles=active_profiles,
            tools_used=list(state.tools_used) + list(state.tools_failed),
            tools_blocked=state.tools_blocked,
            current_level=state.investigation_level,
        )
        candidates = sorted(set(candidates) | set(_required_package_tools(package, state.investigation_level, attempted)))
        state = state.model_copy(update={
            "attack_hypotheses": hypotheses,
            "tools_available": candidates,
        })

        # 2. Rank eligible tools
        ranked = rank_tools(candidates, state, active_profiles)

        # 3. Level advancement: nothing eligible at this level, but enabled
        #    profile tools still exist higher up -> advance one level.
        if not ranked:
            all_level_candidates = get_candidate_tools(
                profiles=active_profiles,
                tools_used=list(state.tools_used) + list(state.tools_failed),
                tools_blocked=state.tools_blocked,
                current_level=InvestigationLevel.L3_GROQ,
            )
            all_level_candidates = sorted(set(all_level_candidates) | set(
                _required_package_tools(package, InvestigationLevel.L3_GROQ, attempted)
            ))
            if all_level_candidates and _LEVEL_RANK[state.investigation_level] < 3:
                new_level = InvestigationLevel(
                    list(_LEVEL_RANK)[_LEVEL_RANK[state.investigation_level] + 1]
                )
                target_status = _STATUS_FOR_LEVEL[new_level]
                old_status = state.sm_status.value
                try:
                    state = transition(state, target_status)
                except InvalidTransitionError:
                    logger.error(
                        "Illegal level advance %s -> %s; aborting loop", old_status, target_status.value
                    )
                    break
                audit.log_transition(
                    from_status=old_status,
                    to_status=target_status.value,
                    reason_code="STAGE4_LEVEL_ADVANCE",
                    evidence_ids=[ev.evidence_id for ev in all_evidence],
                    risk_before=state.current_risk,
                    risk_after=state.current_risk,
                    confidence_before=state.current_confidence,
                    confidence_after=state.current_confidence,
                )
                continue
            # No candidates at any level: nothing more to execute.
            state = state.model_copy(update={"tools_available": []})
            break

        # 4. Begin an iteration
        iteration = state.iteration_count + 1
        state = state.model_copy(update={"iteration_count": iteration})

        top_score = ranked[0]
        tool_def = get_tool(top_score.tool_name)

        # 5. Budget gates (before executing anything)
        remaining = calculate_budget_remaining(state)
        if remaining.max_latency_ms <= 0:
            break
        if remaining.max_tool_calls <= 0:
            break
        if tool_def.external_api and remaining.max_external_calls <= 0:
            state = state.model_copy(update={"tools_blocked": list(state.tools_blocked) + [tool_def.name]})
            continue

        # 6. Build inputs (deterministic, package-derived)
        inputs = _map_inputs_for_tool(tool_def.name, package, all_evidence)
        if not inputs:
            state = state.model_copy(update={"tools_blocked": list(state.tools_blocked) + [tool_def.name]})
            continue

        # 7. Slice inputs against the external-call budget (defer the rest)
        deferred: list[dict[str, Any]] = []
        if tool_def.external_api:
            input_capacity = remaining.max_external_calls
            # A geo lookup can use primary plus fallback. Reserve both before
            # launching parallel work so concurrent providers cannot overspend.
            if tool_def.name in ("geoip_lookup", "ip_geolocation"):
                per_lookup = 3
                input_capacity = max(1, remaining.max_external_calls // per_lookup)
                for inp in inputs:
                    inp["max_external_calls"] = min(per_lookup, remaining.max_external_calls)
            if len(inputs) > input_capacity:
                deferred = inputs[input_capacity:]
                inputs = inputs[:input_capacity]
            if deferred:
                missing = list(state.missing_evidence)
                for d in deferred:
                    missing.append(f"Deferred {tool_def.name} for {d}")
                state = state.model_copy(update={"missing_evidence": missing})

        # 8. Execute
        evidence_before_ids = [ev.evidence_id for ev in all_evidence]
        tasks = [
            executor.execute(
                ToolExecutionRequest(
                    case_id=state.case_id,
                    tool_name=tool_def.name,
                    input=inp,
                    reason=top_score.reason,
                    policy_version="1.0",
                ),
                state,
                package=package,
            )
            for inp in inputs
        ]
        exec_started = time.perf_counter()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        exec_elapsed_ms = int((time.perf_counter() - exec_started) * 1000)

        # 9. Normalise results, classify success vs failure, count external usage
        new_evidence: list[EvidenceItem] = []
        failed_reasons: list[str] = []
        external_used = 0
        for res in results:
            items, error = _normalise_execution_result(res, state.case_id, tool_def, normaliser)
            if error is not None:
                failed_reasons.append(error)
            else:
                new_evidence.extend(items)
            if isinstance(res, ToolExecutionResult):
                external_used += res.external_calls_made

        # Model absence is a first-class evidence gap, not a failed/clean ML
        # result. The fallback itself remains usable deterministic evidence.
        if tool_def.name == "nlp_intent_ml":
            model_errors = [
                str((item.metadata or {}).get("model_error"))
                for item in new_evidence
                if (item.metadata or {}).get("model_status") == "MODEL_UNAVAILABLE"
            ]
            if model_errors:
                gap = f"MODEL_UNAVAILABLE: {model_errors[0]}"
                if gap not in state.missing_evidence:
                    state = state.model_copy(update={"missing_evidence": [*state.missing_evidence, gap]})

        # 10. Account costs — once per tool invocation (+ actual external inputs)
        new_spent = record_tool_cost(state.tool_cost_spent, latency_ms=exec_elapsed_ms)
        if tool_def.external_api and external_used > 0:
            new_spent = new_spent.model_copy(
                update={"external_calls": new_spent.external_calls + external_used}
            )

        tool_succeeded = bool(new_evidence)
        # `budget_remaining` is part of the public result contract. Refresh
        # the snapshot after every invocation so it always agrees with the
        # authoritative accumulated cost (including failed provider calls).
        state = state.model_copy(update={"tool_cost_spent": new_spent})
        state = state.model_copy(update={
            "budget_remaining": calculate_budget_remaining(state),
        })
        if tool_succeeded:
            state = state.model_copy(update={
                "tools_used": list(state.tools_used) + [tool_def.name]
            })
        else:
            state = state.model_copy(update={
                "tools_failed": list(state.tools_failed) + [tool_def.name]
            })
            missing = list(state.missing_evidence)
            for reason in failed_reasons:
                missing.append(f"Tool {tool_def.name} failed: {reason}")
            state = state.model_copy(update={"missing_evidence": missing})
            audit.log_tool_failed(
                tool_name=tool_def.name,
                failure_reason="; ".join(failed_reasons) or "no usable evidence produced",
                evidence_ids=evidence_before_ids,
                risk_before=state.current_risk,
                confidence_before=state.current_confidence,
            )

        # 11. Accumulate evidence and update typed ID lists
        if new_evidence:
            known_ids = {item.evidence_id for item in all_evidence}
            new_evidence = [item for item in new_evidence if item.evidence_id not in known_ids]
            all_evidence.extend(new_evidence)
            obs = list(state.observed_facts)
            heu = list(state.heuristic_findings)
            mls = list(state.ml_signals)
            thi = list(state.threat_intelligence)
            his = list(state.historical_matches)
            for item in new_evidence:
                if item.type == EvidenceType.FACT:
                    if item.evidence_id not in obs:
                        obs.append(item.evidence_id)
                elif item.type == EvidenceType.HEURISTIC:
                    if item.evidence_id not in heu:
                        heu.append(item.evidence_id)
                elif item.type == EvidenceType.ML_SIGNAL:
                    if item.evidence_id not in mls:
                        mls.append(item.evidence_id)
                elif item.type == EvidenceType.THREAT_INTEL:
                    if item.evidence_id not in thi:
                        thi.append(item.evidence_id)
                elif item.type == EvidenceType.HISTORICAL:
                    if item.evidence_id not in his:
                        his.append(item.evidence_id)
            state = state.model_copy(update={
                "observed_facts": obs,
                "heuristic_findings": heu,
                "ml_signals": mls,
                "threat_intelligence": thi,
                "historical_matches": his,
            })

        # 12. Evidence distribution across state-driver lists
        state = state.model_copy(update={
            "all_evidence_items": list(all_evidence),
        })

        # 13. Conflict detection
        try:
            conflicts = conflict_engine.detect_conflicts(all_evidence)
            state = state.model_copy(update={"active_conflicts": [c.model_dump() for c in conflicts]})
        except Exception as e:  # noqa: BLE001
            logger.warning("Conflict detection failed for case %s: %s", state.case_id, e)

        # 14. Re-assess risk + confidence on the full evidence set
        risk_before = state.current_risk
        conf_before = state.current_confidence
        risk_result = risk_engine.assess(state, all_evidence)
        risk_after = risk_result.risk_assessment.risk_score
        conf_after = risk_result.confidence_assessment.confidence_score
        state = state.model_copy(update={
            "current_risk": risk_after,
            "current_confidence": conf_after,
        })

        # 15. Audit the execution (only when the tool actually ran)
        audit.log_tool_executed(
            tool_name=tool_def.name,
            evidence_before=evidence_before_ids,
            evidence_after=[ev.evidence_id for ev in all_evidence],
            risk_before=risk_before,
            risk_after=risk_after,
            confidence_before=conf_before,
            confidence_after=conf_after,
        )
        if new_evidence:
            audit.log_evidence_created(
                evidence_ids=[ev.evidence_id for ev in new_evidence],
                risk_before=risk_before,
                risk_after=risk_after,
                confidence_before=conf_before,
                confidence_after=conf_after,
            )

        # 16. Stop conditions
        stop_dec = should_stop(state)
        if stop_dec.should_stop:
            return state, all_evidence, stop_dec

    # Loop naturally exhausted (no candidates remaining on the last level)
    # or the iteration/iteration cap was not reached. The caller re-evaluates
    # stop conditions once on the final state.
    return state, all_evidence, None
