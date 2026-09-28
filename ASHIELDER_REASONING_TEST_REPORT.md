# ASHIELDER Reasoning Layer — Test Report

## Test Execution Summary

| Metric | Value |
|--------|-------|
| **Baseline Tests (before)** | 372 |
| **New Reasoning Tests** | 50 |
| **Total Tests (after)** | 422 |
| **Regressions** | 0 |
| **Framework** | pytest + pytest-asyncio |

> [!NOTE]
> 1 pre-existing collection error (`test_m2_legacy.py`) due to missing DistilBERT model
> weights is excluded — this is unrelated to the reasoning layer.

---

## New Test Files

### `test_reasoning_contracts.py` (9 tests)
| Test | Status |
|------|--------|
| `test_reasoning_finding_construction` | ✅ PASS |
| `test_reasoning_hypothesis_construction` | ✅ PASS |
| `test_untrusted_content_item_construction` | ✅ PASS |
| `test_budget_status_enum` | ✅ PASS |
| `test_reasoning_evidence_snapshot` | ✅ PASS |
| `test_reasoning_result` | ✅ PASS |
| `test_reasoning_unavailable` | ✅ PASS |
| `test_validated_reasoning_artifact` | ✅ PASS |
| `test_snapshot_builder` | ✅ PASS |

### `test_reasoning_validator.py` (16 tests)
| Test | Status |
|------|--------|
| `test_validator_valid_case` | ✅ PASS |
| `test_validator_hallucinated_supporting_evidence` | ✅ PASS |
| `test_validator_hallucinated_contradicting_evidence` | ✅ PASS |
| `test_validator_wrong_case_id` | ✅ PASS |
| `test_validator_wrong_investigation_id` | ✅ PASS |
| `test_validator_oversized_summary` | ✅ PASS |
| `test_validator_oversized_explanation` | ✅ PASS |
| `test_validator_too_many_hypotheses` | ✅ PASS |
| `test_validator_too_many_actions` | ✅ PASS |
| `test_validator_risk_score_pattern` | ✅ PASS |
| `test_validator_confidence_pattern` | ✅ PASS |
| `test_validator_verdict_pattern` | ✅ PASS |
| `test_validator_secret_pattern` | ✅ PASS |
| `test_validator_tool_execution_pattern` | ✅ PASS |
| `test_validator_system_prompt_extraction` | ✅ PASS |
| `test_validator_normal_cybersecurity_language_allowed` | ✅ PASS |
| `test_validator_benign_risk_discussion_allowed` | ✅ PASS |

### `test_reasoning_security.py` (5 tests)
| Test | Status |
|------|--------|
| `test_security_prompt_injection_does_not_affect_structure` | ✅ PASS |
| `test_security_fake_api_key_in_evidence_rejected_in_output` | ✅ PASS |
| `test_security_hallucinated_evidence_rejected` | ✅ PASS |
| `test_security_schema_rejects_authoritative_fields` | ✅ PASS |
| `test_security_snapshot_builder_never_emits_raw_bytes` | ✅ PASS |

### `test_reasoning_service.py` (12 tests)
| Test | Status |
|------|--------|
| `test_reasoning_enabled_false` | ✅ PASS |
| `test_missing_api_key` | ✅ PASS |
| `test_successful_reasoning` | ✅ PASS |
| `test_llm_timeout` | ✅ PASS |
| `test_llm_429_rate_limited` | ✅ PASS |
| `test_llm_503_unavailable` | ✅ PASS |
| `test_hallucinated_evidence_rejected` | ✅ PASS |
| `test_caching_avoids_duplicate_calls` | ✅ PASS |
| `test_no_tools_passed_to_chatgroq` | ✅ PASS |
| `test_malformed_output_returns_unavailable` | ✅ PASS |
| `test_error_classification` | ✅ PASS |

### `test_reasoning_api.py` (5 tests)
| Test | Status |
|------|--------|
| `test_request_reasoning_unauthenticated` | ✅ PASS |
| `test_request_reasoning_nonexistent_case` | ✅ PASS |
| `test_request_reasoning_disabled` | ✅ PASS |
| `test_request_reasoning_success` | ✅ PASS |
| `test_request_reasoning_provider_failure` | ✅ PASS |

### `test_reasoning_e2e.py` (3 tests)
| Test | Status |
|------|--------|
| `test_reasoning_e2e_pipeline` | ✅ PASS |
| `test_reasoning_validator_catches_hallucinations` | ✅ PASS |
| `test_reasoning_unavailable_fallback` | ✅ PASS |

---

## Coverage Areas

| Area | Test Count | Coverage |
|------|-----------|----------|
| Contract schema validation | 9 | Field types, frozen, extra=forbid, enums, hash, snapshot builder |
| Deterministic validator | 16 | Identity, evidence IDs, sizes, forbidden patterns, normal language |
| Security / injection | 5 | Prompt injection, API key leakage, hallucination, authority override |
| Service (LangChain + Groq) | 12 | Success, timeout, 429, 503, caching, no tools, no memory |
| API endpoint | 5 | Auth, RBAC, disabled, success, failure |
| End-to-end | 3 | Full pipeline, hallucination rejection, fallback |

---

## Regression Check

All 372 pre-existing tests continue to pass without modification.
The reasoning layer does NOT affect the deterministic investigation pipeline.
