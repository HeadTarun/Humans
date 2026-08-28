import json
import logging
import os
import sys
from contextvars import ContextVar
from typing import Any


_request_id: ContextVar[str | None] = ContextVar("backend_request_id", default=None)


def configure_backend_logging() -> None:
    level_name = os.getenv("BACKEND_LOG_LEVEL", "INFO").strip().upper()
    level = getattr(logging, level_name, logging.INFO)
    root_logger = logging.getLogger()
    if not root_logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(message)s"))
        root_logger.addHandler(handler)
    root_logger.setLevel(level)
    logging.getLogger("backend").setLevel(level)
    logging.getLogger("orchestrator").setLevel(level)
    logging.getLogger("modules").setLevel(level)


def set_request_id(request_id: str):
    return _request_id.set(request_id)


def reset_request_id(token) -> None:
    _request_id.reset(token)


def get_request_id() -> str | None:
    return _request_id.get()


def diagnostic_logs_enabled() -> bool:
    return _truthy_env("BACKEND_DIAGNOSTIC_LOGS")


def full_input_logging_enabled() -> bool:
    return diagnostic_logs_enabled() and _truthy_env("BACKEND_LOG_FULL_INPUT")


def log_json(
    logger_name: str,
    level: int,
    event: str,
    diagnostic_only: bool = False,
    **fields: Any,
) -> None:
    if diagnostic_only and not diagnostic_logs_enabled():
        return

    payload: dict[str, Any] = {"event": event}
    request_id = get_request_id()
    if request_id:
        payload["request_id"] = request_id
    payload.update(fields)

    if _log_format() == "json":
        message = json.dumps(payload, default=str, separators=(",", ":"), sort_keys=True)
    else:
        message = _ascii_safe(_format_readable_log(payload))
    logging.getLogger(logger_name).log(level, message)


def _log_format() -> str:
    value = os.getenv("BACKEND_LOG_FORMAT", "simple").strip().lower()
    return "json" if value == "json" else "simple"


def _format_readable_log(payload: dict[str, Any]) -> str:
    event = str(payload.get("event", "log"))
    request_id = str(payload.get("request_id", "-"))
    prefix = f"[req {request_id[:8]}]"

    formatters = {
        "request_started": _format_request_started,
        "request_completed": _format_request_completed,
        "pipeline_started": _format_pipeline_started,
        "pipeline_completed": _format_pipeline_completed,
        "module_started": _format_module_started,
        "module_completed": _format_module_completed,
        "module_failed": _format_module_failed,
        "early_exit_used": _format_early_exit_used,
        "fallback_used": _format_fallback_used,
        "m2_model_prediction": _format_m2_model_prediction,
        "m2_model_latency": _format_m2_model_latency,
        "m2_deterministic_guard_override": _format_m2_guard_override,
        "m2_model_unavailable": _format_model_unavailable,
        "m4_url_normalized": _format_m4_url_normalized,
        "m4_url_risk_flags_detected": _format_m4_url_flags,
        "m4_redirect_lookup_started": _format_m4_redirect_started,
        "m4_redirect_lookup_completed": _format_m4_redirect_completed,
        "m4_redirect_lookup_cache_hit": _format_m4_redirect_cache_hit,
        "m4_redirect_lookup_skipped": _format_m4_lookup_skipped,
        "m4_redirect_lookup_failed": _format_m4_lookup_failed,
        "m4_rdap_bootstrap_loaded": _format_m4_rdap_bootstrap_loaded,
        "m4_rdap_lookup_started": _format_m4_rdap_started,
        "m4_rdap_lookup_completed": _format_m4_rdap_completed,
        "m4_rdap_lookup_cache_hit": _format_m4_rdap_cache_hit,
        "m4_rdap_lookup_skipped": _format_m4_lookup_skipped,
        "m4_rdap_lookup_failed": _format_m4_lookup_failed,
        "m4_lighturlnet_prediction": _format_m4_lighturlnet_prediction,
        "m4_lighturlnet_fallback_to_heuristics": _format_fallback_used,
        "m4_url_analysis_completed": _format_m4_url_completed,
        "m3_llm_plan": _format_m3_llm_plan,
        "m3_llm_attempt_started": _format_m3_attempt_started,
        "m3_llm_attempt_failed": _format_m3_attempt_failed,
        "m3_llm_attempt_empty": _format_m3_attempt_empty,
        "m3_llm_attempt_parsed": _format_m3_attempt_parsed,
        "m3_prediction_completed": _format_m3_prediction_completed,
    }
    formatter = formatters.get(event, _format_generic)
    return f"{prefix} {formatter(payload)}"


def _format_request_started(payload: dict[str, Any]) -> str:
    parts = [
        "REQUEST start",
        f"source={payload.get('source')}",
        f"input_len={payload.get('raw_input_length')}",
        f"ts={payload.get('timestamp')}",
    ]
    if "raw_input" in payload:
        parts.append(f'text="{_truncate(payload.get("raw_input"))}"')
    return " | ".join(parts)


def _format_request_completed(payload: dict[str, Any]) -> str:
    return (
        f"REQUEST done {payload.get('total_duration_ms')}ms | "
        f"status={payload.get('status')} module={payload.get('final_module')} "
        f"verdict={payload.get('final_verdict')} error={payload.get('error_code')}"
    )


def _format_pipeline_started(payload: dict[str, Any]) -> str:
    return f"PIPELINE start | stage={payload.get('stage')}"


def _format_pipeline_completed(payload: dict[str, Any]) -> str:
    return f"PIPELINE done {payload.get('total_duration_ms')}ms | verdict={payload.get('final_verdict')}"


def _format_module_started(payload: dict[str, Any]) -> str:
    return f"{payload.get('module')} start"


def _format_module_completed(payload: dict[str, Any]) -> str:
    module = str(payload.get("module", "?"))
    output = payload.get("output") if isinstance(payload.get("output"), dict) else {}
    base = f"{module} {payload.get('status')} {payload.get('duration_ms')}ms"
    if module == "M1":
        return (
            f"{base} | chars={output.get('char_count')} lang={output.get('language')} "
            f"source={output.get('source_type')} flags={_list_text(output.get('encoding_flags'))} "
            f'text="{_truncate(output.get("normalized_text"))}"'
        )
    if module == "M2":
        entities = output.get("entities") if isinstance(output.get("entities"), dict) else {}
        return (
            f"{base} | intent={output.get('intent_label')} conf={output.get('intent_confidence')} "
            f"urgency={output.get('urgency_score')} urls={len(entities.get('urls', []))} "
            f"social={_list_text(output.get('social_engineering_flags'))}"
        )
    if module == "M4":
        rows = output.get("url_risk_scores") if isinstance(output.get("url_risk_scores"), list) else []
        first = rows[0] if rows and isinstance(rows[0], dict) else {}
        suffix = (
            f" | aggregate={output.get('aggregate_url_risk')} urls={output.get('urls_analyzed')} "
            f"top_risk={first.get('risk_score')} age_days={first.get('domain_age_days')} "
            f"redirects={first.get('redirect_count')} flags={_list_text(first.get('risk_flags'))}"
        )
        if first.get("url"):
            suffix += f" url={first.get('url')}"
        return base + suffix
    if module == "M3":
        return (
            f"{base} | verdict={output.get('verdict')} conf={output.get('confidence')} "
            f"severity={output.get('severity')} action={output.get('recommended_action')}"
        )
    return f"{base} | error={payload.get('error_code')}"


def _format_module_failed(payload: dict[str, Any]) -> str:
    return (
        f"{payload.get('module')} FAILED {payload.get('duration_ms')}ms | "
        f"{payload.get('error_type')}: {_truncate(payload.get('error_message'))}"
    )


def _format_early_exit_used(payload: dict[str, Any]) -> str:
    return (
        f"EARLY EXIT at {payload.get('stage')} | confidence={payload.get('confidence')} "
        f"reason={_truncate(payload.get('reason'))}"
    )


def _format_fallback_used(payload: dict[str, Any]) -> str:
    fallback = payload.get("fallback") or payload.get("event")
    return (
        f"FALLBACK {fallback} | module={payload.get('module')} "
        f"location={payload.get('location')} reason={_truncate(payload.get('reason'))}"
    )


def _format_m2_model_prediction(payload: dict[str, Any]) -> str:
    return (
        f"M2 model | predicted={payload.get('predicted_label')} idx={payload.get('predicted_index')} "
        f"conf={payload.get('confidence')} gate={payload.get('confidence_gate')} "
        f"final={payload.get('final_label')}"
    )


def _format_m2_model_latency(payload: dict[str, Any]) -> str:
    return (
        f"M2 model latency {payload.get('duration_ms')}ms | "
        f"intent={payload.get('intent_label')} conf={payload.get('intent_confidence')}"
    )


def _format_m2_guard_override(payload: dict[str, Any]) -> str:
    return (
        f"M2 guard override | {payload.get('original_intent_label')}:{payload.get('original_intent_confidence')} "
        f"-> {payload.get('final_intent_label')}:{payload.get('final_intent_confidence')}"
    )


def _format_model_unavailable(payload: dict[str, Any]) -> str:
    return f"{payload.get('model')} unavailable | path={payload.get('model_path')}"


def _format_m4_url_normalized(payload: dict[str, Any]) -> str:
    return f"M4 URL normalize | {payload.get('raw_url')} -> {payload.get('normalized_url')}"


def _format_m4_url_flags(payload: dict[str, Any]) -> str:
    return (
        f"M4 URL flags | domain={payload.get('domain')} "
        f"flags={_list_text(payload.get('risk_flags'))}"
    )


def _format_m4_redirect_started(payload: dict[str, Any]) -> str:
    return (
        f"M4 redirect check start | url={payload.get('normalized_url')} "
        f"timeout={payload.get('timeout_seconds')}s max={payload.get('max_redirects')}"
    )


def _format_m4_redirect_completed(payload: dict[str, Any]) -> str:
    result = payload.get("result") if isinstance(payload.get("result"), dict) else {}
    return (
        f"M4 redirect check done {payload.get('duration_ms')}ms | "
        f"redirects={result.get('redirect_count')} final={result.get('final_destination')}"
    )


def _format_m4_redirect_cache_hit(payload: dict[str, Any]) -> str:
    result = payload.get("result") if isinstance(payload.get("result"), dict) else {}
    return (
        f"M4 redirect cache hit | url={payload.get('normalized_url')} "
        f"redirects={result.get('redirect_count')} final={result.get('final_destination')}"
    )


def _format_m4_lookup_skipped(payload: dict[str, Any]) -> str:
    target = payload.get("normalized_url") or payload.get("domain") or payload.get("rdap_url")
    return f"{payload.get('event')} | target={target} reason={payload.get('reason')}"


def _format_m4_lookup_failed(payload: dict[str, Any]) -> str:
    target = payload.get("normalized_url") or payload.get("domain") or payload.get("rdap_url")
    return (
        f"{payload.get('event')} | target={target} "
        f"{payload.get('error_type')}: {_truncate(payload.get('error_message'))}"
    )


def _format_m4_rdap_bootstrap_loaded(payload: dict[str, Any]) -> str:
    return f"M4 RDAP bootstrap loaded | services={payload.get('services_count')}"


def _format_m4_rdap_started(payload: dict[str, Any]) -> str:
    return f"M4 RDAP start | domain={payload.get('domain')} url={payload.get('rdap_url')}"


def _format_m4_rdap_completed(payload: dict[str, Any]) -> str:
    return (
        f"M4 RDAP done {payload.get('duration_ms')}ms | "
        f"domain={payload.get('domain')} age_days={payload.get('domain_age_days')}"
    )


def _format_m4_rdap_cache_hit(payload: dict[str, Any]) -> str:
    return f"M4 RDAP cache hit | domain={payload.get('domain')} age_days={payload.get('domain_age_days')}"


def _format_m4_lighturlnet_prediction(payload: dict[str, Any]) -> str:
    return (
        f"M4 LightURLNet {payload.get('duration_ms')}ms | "
        f"probability={payload.get('probability')} url={payload.get('normalized_url')}"
    )


def _format_m4_url_completed(payload: dict[str, Any]) -> str:
    return (
        f"M4 URL done {payload.get('duration_ms')}ms | risk={payload.get('final_risk_score')} "
        f"heuristic={payload.get('heuristic_risk_score')} ml={payload.get('lighturlnet_risk_score')} "
        f"age_days={payload.get('domain_age_days')} redirects={payload.get('redirect_count')} "
        f"flags={_list_text(payload.get('risk_flags'))} url={payload.get('normalized_url')}"
    )


def _format_m3_llm_plan(payload: dict[str, Any]) -> str:
    return f"M3 LLM plan | primary={payload.get('primary_model')} fallback={payload.get('fallback_model')}"


def _format_m3_attempt_started(payload: dict[str, Any]) -> str:
    return f"M3 LLM start | call={payload.get('call_name')} model={payload.get('model_name')}"


def _format_m3_attempt_failed(payload: dict[str, Any]) -> str:
    return (
        f"M3 LLM failed {payload.get('duration_ms')}ms | call={payload.get('call_name')} "
        f"model={payload.get('model_name')} {payload.get('error_type')}: {_truncate(payload.get('error_message'))}"
    )


def _format_m3_attempt_empty(payload: dict[str, Any]) -> str:
    return f"M3 LLM empty {payload.get('duration_ms')}ms | call={payload.get('call_name')} model={payload.get('model_name')}"


def _format_m3_attempt_parsed(payload: dict[str, Any]) -> str:
    return (
        f"M3 LLM parsed {payload.get('duration_ms')}ms | call={payload.get('call_name')} "
        f"schema={payload.get('schema_valid')} verdict={payload.get('parsed_verdict')} "
        f"conf={payload.get('parsed_confidence')} severity={payload.get('parsed_severity')} "
        f"action={payload.get('parsed_recommended_action')}"
    )


def _format_m3_prediction_completed(payload: dict[str, Any]) -> str:
    return (
        f"M3 prediction | verdict={payload.get('verdict')} conf={payload.get('confidence')} "
        f"category={payload.get('threat_category')} severity={payload.get('severity')} "
        f"action={payload.get('recommended_action')}"
    )


def _format_generic(payload: dict[str, Any]) -> str:
    event = str(payload.get("event", "log"))
    ignored = {"event", "request_id"}
    parts = [f"{key}={_compact_value(value)}" for key, value in payload.items() if key not in ignored]
    return f"{event} | " + " ".join(parts)


def _list_text(value: Any) -> str:
    if not value:
        return "none"
    if isinstance(value, list):
        return ",".join(str(item) for item in value) or "none"
    return str(value)


def _compact_value(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, default=str, separators=(",", ":"))
    return str(value)


def _truncate(value: Any, limit: int = 160) -> str:
    text = "" if value is None else str(value)
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _ascii_safe(value: str) -> str:
    return value.encode("ascii", errors="backslashreplace").decode("ascii")


def _truthy_env(name: str) -> bool:
    return os.getenv(name, "false").strip().lower() in {"1", "true", "yes", "on"}
